"""Export log records from a .logz file to CSV or JSONL format."""

import csv
import json
import struct
import sys
from datetime import datetime, timezone
import zstandard as zstd

import bloom
from compress import FOOTER_SIZE

_MAGIC       = b'LOGZ'
_VERSION     = 4
_FORMAT_JSON = 0  # matches compress.FORMAT_JSON

# JSON field-key groups used when extracting structured fields for export
_TS_KEYS    = ('timestamp', 'time', 'ts', '@timestamp')
_LEVEL_KEYS = ('level', 'severity')
_USER_KEYS  = ('user', 'user_id', 'username')
_IP_KEYS    = ('ip', 'ip_address')
_MSG_KEYS   = ('message', 'msg')

# Column order for both CSV header and JSONL keys — must not be reordered.
EXPORT_FIELDS = ('timestamp', 'level', 'user', 'ip', 'action', 'message', 'raw')


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


def _extract_fields(line_bytes):
    """Extract structured fields from a single JSON log line.

    Returns a 7-tuple (timestamp, level, user, ip, action, message, raw) where
    every element is a string.  If the line is not valid JSON, all structured
    fields are empty and only raw is populated.

    Args:
        line_bytes: One log line as bytes (trailing newline stripped or not).

    Returns:
        Tuple of seven strings aligned with EXPORT_FIELDS.
    """
    raw_str = line_bytes.decode('utf-8', errors='replace').rstrip('\r\n')
    try:
        obj = json.loads(raw_str)
    except (json.JSONDecodeError, ValueError):
        return '', '', '', '', '', '', raw_str

    def _first(keys):
        """Return str(value) of the first key found in obj, or empty string."""
        for k in keys:
            v = obj.get(k)
            if v is not None:
                return str(v)
        return ''

    return (
        _first(_TS_KEYS),
        _first(_LEVEL_KEYS),
        _first(_USER_KEYS),
        _first(_IP_KEYS),
        _first(('action',)),
        _first(_MSG_KEYS),
        raw_str,
    )


def run(args):
    """CLI entry point — delegates to _export with parsed argparse namespace.

    Args:
        args: argparse.Namespace with .input, optional .from_date/.to_date,
              and .format ('csv' or 'json').
    """
    from_ts = _date_to_ts(args.from_date) if getattr(args, 'from_date', None) else None
    to_ts   = _date_to_ts(args.to_date, end_of_day=True) if getattr(args, 'to_date', None) else None
    _export(args.input, from_ts=from_ts, to_ts=to_ts, output_fmt=args.format)


def _export(logz_path, from_ts=None, to_ts=None, output_fmt='csv'):
    """Export log records from a .logz file to stdout in CSV or JSONL format.

    Applies the same chunk-level time-range skip as search.py: chunks whose
    min_ts/max_ts window does not overlap [from_ts, to_ts] are skipped
    entirely.  All lines in qualifying chunks are exported without further
    per-line filtering.

    CSV output starts with a header row:
        timestamp,level,user,ip,action,message,raw

    JSONL output writes one JSON object per line with the same keys.

    For JSON-format logs each record has its structured fields extracted from
    the known field keys.  For syslog and plaintext logs only the raw column
    is populated; all other fields are empty strings.

    Output is written to stdout so callers can redirect to a file:
        shrinker export archive.logz --from 2025-01-01 > audit.csv

    A one-line progress summary is written to stderr.

    Args:
        logz_path:  Path to the input .logz file.
        from_ts:    Optional start of time window (unix epoch seconds, inclusive).
        to_ts:      Optional end of time window (unix epoch seconds, inclusive).
        output_fmt: 'csv' (default) or 'json' (JSONL).
    """
    # Initialise CSV writer before entering the file loop so the header is
    # written before any data rows even if there are no matching chunks.
    writer = None
    if output_fmt == 'csv':
        writer = csv.writer(sys.stdout, lineterminator='\n')
        writer.writerow(EXPORT_FIELDS)

    lines_exported  = 0
    chunks_processed = 0
    chunks_skipped   = 0

    with open(logz_path, 'rb') as f:
        magic = f.read(4)
        if magic != _MAGIC:
            print(f"error: not a .logz file (bad magic: {magic!r})", file=sys.stderr)
            sys.exit(1)

        version = struct.unpack('<H', f.read(2))[0]
        if version != _VERSION:
            print(f"error: unsupported version {version} (expected {_VERSION})",
                  file=sys.stderr)
            sys.exit(1)

        log_fmt  = struct.unpack('B', f.read(1))[0]
        is_json  = (log_fmt == _FORMAT_JSON)

        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data    = f.read(dict_len)
            zdict        = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        # Bootstrap from footer — identical pattern to search.py / decompress.py
        f.seek(-FOOTER_SIZE, 2)
        f.read(32)  # skip chain_hash (not needed for export)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            f.read(bloom.BLOOM_BYTES)        # main bloom   — not needed for export
            f.read(32)                       # chunk_hash   — not needed for export
            min_ts, max_ts = struct.unpack('<QQ', f.read(16))
            f.read(bloom.FIELD_BLOOM_BYTES)  # field bloom  — not needed for export
            jump_table.append((offset, comp_size, orig_size, min_ts, max_ts))

        for offset, comp_size, orig_size, min_ts, max_ts in jump_table:
            # Time-range skip: same logic as search.py
            if from_ts is not None or to_ts is not None:
                has_ts = (min_ts != 0 or max_ts != 0)
                if has_ts:
                    if from_ts is not None and max_ts < from_ts:
                        chunks_skipped += 1
                        continue
                    if to_ts is not None and min_ts > to_ts:
                        chunks_skipped += 1
                        continue

            chunks_processed += 1
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)

            for line in raw.split(b'\n'):
                if not line:
                    continue

                if is_json:
                    ts, level, user, ip, action, message, raw_str = _extract_fields(line)
                else:
                    raw_str = line.decode('utf-8', errors='replace').rstrip('\r\n')
                    ts = level = user = ip = action = message = ''

                if output_fmt == 'csv':
                    writer.writerow([ts, level, user, ip, action, message, raw_str])
                else:
                    print(json.dumps({
                        'timestamp': ts,
                        'level':     level,
                        'user':      user,
                        'ip':        ip,
                        'action':    action,
                        'message':   message,
                        'raw':       raw_str,
                    }))

                lines_exported += 1

    print(
        f"Exported: {lines_exported} lines"
        f"  |  Chunks: {chunks_processed} processed, {chunks_skipped} skipped",
        file=sys.stderr,
    )
