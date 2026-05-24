"""Search a .logz file for a query string without full decompression."""

import struct
import sys
from datetime import datetime, timezone
import zstandard as zstd

import bloom

FOOTER_SIZE = 44        # chain_hash(32) + jt_offset(8) + num_chunks(4)
JUMP_ENTRY_SIZE = 1600  # offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + hash(32) + min_ts(8) + max_ts(8) + field_bloom(512)


def _date_to_ts(date_str, end_of_day=False):
    """Parse a date string like '2025-01-01' to unix epoch seconds, or None on error."""
    s = date_str.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if end_of_day and 'T' not in date_str and ' ' not in date_str:
            dt = dt.replace(hour=23, minute=59, second=59)
        return int(dt.timestamp())
    except (ValueError, OverflowError):
        return None


def run(args):
    """CLI entry point — delegates to _search with parsed argparse namespace.

    Args:
        args: argparse.Namespace with .file, .query, optional .from_date/.to_date,
              and optional .user/.ip/.action/.level field filters.
    """
    from_ts = _date_to_ts(args.from_date) if getattr(args, 'from_date', None) else None
    to_ts = _date_to_ts(args.to_date, end_of_day=True) if getattr(args, 'to_date', None) else None
    field_filters = []
    for attr in ('user', 'ip', 'action', 'level'):
        val = getattr(args, attr, None)
        if val:
            field_filters.append(val.encode('utf-8'))
    _search(args.file, args.query, from_ts=from_ts, to_ts=to_ts,
            field_filters=field_filters or None)


def _search(logz_path, query, from_ts=None, to_ts=None, field_filters=None):
    """Search a .logz file and print every line that contains the query string.

    Skips are applied in cheapest-first order:
      1. Time range (min_ts/max_ts in jump table)
      2. Field bloom (512-byte per-chunk filter for structured field values)
      3. Main bloom (1024-byte per-chunk full-text filter)

    Matching lines are printed to stdout. A summary line is printed to stderr.

    Args:
        logz_path:     Path to the .logz compressed file.
        query:         Search string (UTF-8). Matched as a literal byte sequence.
        from_ts:       Optional start of time window as unix epoch seconds (inclusive).
        to_ts:         Optional end of time window as unix epoch seconds (inclusive).
        field_filters: Optional list of byte strings (field values); a chunk is skipped
                       when its field bloom says ANY of these values is definitely absent.
                       Ignored when the field bloom is all zeros (non-JSON logs).
    """
    query_bytes = query.encode('utf-8')

    with open(logz_path, 'rb') as f:
        # Read header fields in order
        f.seek(4)
        version = struct.unpack('<H', f.read(2))[0]
        if version != 4:
            print(f"error: unsupported version {version} (expected 4)", file=sys.stderr)
            sys.exit(2)

        # Load the shared dictionary; without it zstd cannot decompress chunks
        f.seek(7)
        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        # Footer is always the last 44 bytes — seek there first to find the jump table
        f.seek(-FOOTER_SIZE, 2)
        f.read(32)  # skip chain_hash (not needed for search)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        # Read the full jump table into memory — it's small (1088 bytes per chunk)
        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            bf = f.read(bloom.BLOOM_BYTES)
            f.read(32)  # skip stored chunk_hash
            min_ts, max_ts = struct.unpack('<QQ', f.read(16))
            field_bloom = f.read(bloom.FIELD_BLOOM_BYTES)
            jump_table.append((offset, comp_size, orig_size, bf, min_ts, max_ts, field_bloom))

        matches = 0
        chunks_scanned = 0
        skipped_by_bloom = 0
        skipped_by_time = 0
        skipped_by_field = 0

        for offset, comp_size, orig_size, bf, min_ts, max_ts, field_bloom in jump_table:
            # Time-range skip: cheapest check, done first
            if from_ts is not None or to_ts is not None:
                has_ts = (min_ts != 0 or max_ts != 0)
                if has_ts:
                    if from_ts is not None and max_ts < from_ts:
                        skipped_by_time += 1
                        continue
                    if to_ts is not None and min_ts > to_ts:
                        skipped_by_time += 1
                        continue

            # Field bloom skip: only active when field_bloom is non-zero (JSON logs)
            # and at least one --user/--ip/--action/--level filter was given.
            # A chunk is skipped if ANY requested value is definitely absent.
            if field_filters and any(field_bloom):
                skip_by_field = False
                for fv in field_filters:
                    if not bloom.query_field_present(field_bloom, fv):
                        skip_by_field = True
                        break
                if skip_by_field:
                    skipped_by_field += 1
                    continue

            if bf is not None and not bloom.query_present(bf, query_bytes):
                # Main bloom guarantees no false negatives — safe to skip entirely
                skipped_by_bloom += 1
                continue
            chunks_scanned += 1
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)

            if query_bytes not in raw:
                # Bloom false positive — chunk passed the filter but query isn't here
                continue

            for line in raw.split(b'\n'):
                if line and query_bytes in line:
                    print(line.decode('utf-8', errors='replace'))
                    matches += 1

    print(
        f"Matches: {matches}  |  Chunks scanned: {chunks_scanned} / {num_chunks}"
        f"  |  Skipped by time: {skipped_by_time}"
        f"  |  Skipped by field: {skipped_by_field}"
        f"  |  Skipped by bloom: {skipped_by_bloom}",
        file=sys.stderr,
    )
