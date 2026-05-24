"""Compress log files into the .logz seekable compressed format."""

import hashlib
import json
import re
import struct
import sys
from datetime import datetime, timezone
import zstandard as zstd

import bloom

CHUNK_SIZE = 64 * 1024   # 64 KB — SIMD-aligned for the future C rewrite
DICT_SIZE = 112 * 1024   # zstd dictionary target size in bytes
TRAIN_LIMIT = 10 * 1024 * 1024  # cap dictionary training at 10 MB so startup stays fast

VERSION = 4  # v1 = no bloom/hash, v2 = bloom + SHA-256 hash chain, v3 = + timestamps, v4 = + field bloom
FOOTER_SIZE = 44        # chain_hash(32) + jt_offset(8) + num_chunks(4)
JUMP_ENTRY_SIZE = 1600  # offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + hash(32) + min_ts(8) + max_ts(8) + field_bloom(512)

FORMAT_JSON = 0
FORMAT_SYSLOG = 1
FORMAT_PLAINTEXT = 2
FORMAT_NAMES = {FORMAT_JSON: 'json', FORMAT_SYSLOG: 'syslog', FORMAT_PLAINTEXT: 'plaintext'}
FORMAT_BY_NAME = {'json': FORMAT_JSON, 'syslog': FORMAT_SYSLOG, 'plaintext': FORMAT_PLAINTEXT}

SYSLOG_RE = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s')

_SYSLOG_TS_RE = re.compile(rb'^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s')
_SYSLOG_MONTHS = {
    b'Jan': 1, b'Feb': 2, b'Mar': 3, b'Apr': 4, b'May': 5, b'Jun': 6,
    b'Jul': 7, b'Aug': 8, b'Sep': 9, b'Oct': 10, b'Nov': 11, b'Dec': 12,
}
_JSON_TS_KEYS = ('timestamp', 'time', 'ts', '@timestamp')

# JSON field keys whose values are indexed in the per-chunk field bloom filter.
# Only these fields are extracted; all other JSON content goes to the main bloom.
_FIELD_KEYS = ('user', 'user_id', 'username', 'ip', 'ip_address', 'action', 'level', 'severity')


def detect_format(path):
    """Detect whether a log file contains JSON, syslog, or plaintext lines.

    Reads up to the first five lines and applies a majority vote: if at least
    min(3, len(lines)) lines match a format, that format wins. Falls back to
    plaintext when nothing matches.

    Args:
        path: Path to the input log file.

    Returns:
        One of FORMAT_JSON, FORMAT_SYSLOG, or FORMAT_PLAINTEXT.
    """
    lines = []
    with open(path, 'rb') as f:
        for _ in range(5):
            line = f.readline()
            if not line:
                break
            lines.append(line.decode('utf-8', errors='replace').rstrip())
    if not lines:
        return FORMAT_PLAINTEXT
    # Majority threshold: require at least 3 matching lines, or all lines if fewer than 3
    threshold = max(1, min(3, len(lines)))
    if sum(1 for l in lines if _try_json(l)) >= threshold:
        return FORMAT_JSON
    if sum(1 for l in lines if SYSLOG_RE.match(l)) >= threshold:
        return FORMAT_SYSLOG
    return FORMAT_PLAINTEXT


def _try_json(line):
    """Return True if line is valid JSON, False otherwise.

    Args:
        line: A single log line as a string.

    Returns:
        bool
    """
    try:
        json.loads(line)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _parse_iso(s):
    """Parse an ISO 8601 string to unix epoch seconds, or return None."""
    s = s.strip()
    if s.endswith('Z'):
        s = s[:-1] + '+00:00'
    try:
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except (ValueError, OverflowError):
        return None


def _ts_from_json_line(line_bytes):
    """Return a unix timestamp from a JSON log line, or None if not found."""
    try:
        obj = json.loads(line_bytes.decode('utf-8', errors='replace'))
        for key in _JSON_TS_KEYS:
            val = obj.get(key)
            if val is None:
                continue
            if isinstance(val, (int, float)) and val > 0:
                return int(val)
            if isinstance(val, str):
                ts = _parse_iso(val)
                if ts is not None:
                    return ts
    except (json.JSONDecodeError, ValueError, AttributeError):
        pass
    return None


def _ts_from_syslog_line(line_bytes):
    """Return a unix timestamp from a syslog-format line, or None if not found."""
    m = _SYSLOG_TS_RE.match(line_bytes)
    if not m:
        return None
    mon = _SYSLOG_MONTHS.get(m.group(1))
    if not mon:
        return None
    day, hour, minute, sec = int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5))
    year = datetime.now(timezone.utc).year
    try:
        dt = datetime(year, mon, day, hour, minute, sec, tzinfo=timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


def _ts_for_line(line_bytes, fmt):
    """Dispatch timestamp extraction based on log format."""
    if fmt == FORMAT_JSON:
        return _ts_from_json_line(line_bytes)
    if fmt == FORMAT_SYSLOG:
        return _ts_from_syslog_line(line_bytes)
    # Plaintext: try JSON first, then syslog
    ts = _ts_from_json_line(line_bytes)
    return ts if ts is not None else _ts_from_syslog_line(line_bytes)


def _extract_timestamps(raw, fmt):
    """Return (min_ts, max_ts) as unix epoch seconds for a raw chunk.

    Scans forward for the first timestamp and backward for the last. Assumes
    logs are in chronological order, which is true for virtually all log files.
    Returns (0, 0) if no timestamps are found.
    """
    lines = raw.split(b'\n')
    min_ts = None
    max_ts = None
    for line in lines:
        if line:
            ts = _ts_for_line(line, fmt)
            if ts is not None:
                min_ts = ts
                break
    for line in reversed(lines):
        if line:
            ts = _ts_for_line(line, fmt)
            if ts is not None:
                max_ts = ts
                break
    if min_ts is None or max_ts is None:
        return 0, 0
    return min_ts, max_ts


def _extract_field_values(raw, fmt):
    """Return a list of UTF-8 byte strings for structured fields in a raw chunk.

    Only JSON-format logs are processed; syslog and plaintext produce an empty
    list, which causes the field bloom to be stored as all-zero bytes.  Callers
    in search.py treat an all-zero field bloom as "no field index available" and
    fall back to a full scan when field filters are requested.

    Args:
        raw: Raw (pre-compression) chunk bytes.
        fmt: One of FORMAT_JSON, FORMAT_SYSLOG, FORMAT_PLAINTEXT.

    Returns:
        List of byte strings (field values). May be empty.
    """
    if fmt != FORMAT_JSON:
        return []
    values = []
    for line in raw.split(b'\n'):
        if not line:
            continue
        try:
            obj = json.loads(line.decode('utf-8', errors='replace'))
            for key in _FIELD_KEYS:
                val = obj.get(key)
                if val is not None:
                    values.append(str(val).encode('utf-8'))
        except (json.JSONDecodeError, ValueError, AttributeError):
            continue
    return values


def _train_dict(path):
    """Train a zstd shared dictionary on the first TRAIN_LIMIT bytes of a file.

    A shared dictionary dramatically improves compression on small, similarly
    structured chunks (JSON log lines). Returns None if there are fewer than
    two samples — zstd requires at least two to train.

    Args:
        path: Path to the input log file used as training corpus.

    Returns:
        A zstd.ZstdCompressionDict, or None if training was skipped or failed.
    """
    samples = []
    total = 0
    with open(path, 'rb') as f:
        while total < TRAIN_LIMIT:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            samples.append(chunk)
            total += len(chunk)
    if len(samples) < 2:
        # zstd train_dictionary raises ZstdError with fewer than 2 samples
        return None
    try:
        return zstd.train_dictionary(DICT_SIZE, samples)
    except zstd.ZstdError:
        return None


def run(args):
    """CLI entry point — delegates to _compress with parsed argparse namespace.

    Args:
        args: argparse.Namespace with .input, .output, and optional .format.
    """
    _compress(args.input, args.output, getattr(args, 'format', None))


def _compress(input_path, output_path, fmt_name=None):
    """Compress a log file into .logz format with seekable chunks and bloom filters.

    Writes the .logz file in this order:
      1. Header (magic, version, format byte, dict length, dict bytes)
      2. Compressed 64 KB chunks back-to-back
      3. Jump table (one entry per chunk: offset + sizes + bloom filter)
      4. Footer (jump table offset + chunk count) — read first on open, like Parquet

    Args:
        input_path:  Path to the source log file.
        output_path: Destination path for the .logz output file.
        fmt_name:    Optional format override ('json', 'syslog', 'plaintext').
                     Auto-detected from file content when None.
    """
    fmt = FORMAT_BY_NAME[fmt_name] if fmt_name else detect_format(input_path)

    print("Training dictionary...", file=sys.stderr)
    zdict = _train_dict(input_path)
    dict_data = zdict.as_bytes() if zdict else b''

    if zdict:
        compressor = zstd.ZstdCompressor(dict_data=zdict, level=3)
    else:
        compressor = zstd.ZstdCompressor(level=3)

    input_size = 0
    jump_table = []  # (chunk_offset, comp_size, orig_size, bloom_bytes, chunk_hash, min_ts, max_ts, field_bf)
    prev_hash = None

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        # --- Header ---
        fout.write(b'LOGZ')
        fout.write(struct.pack('<H', VERSION))
        fout.write(struct.pack('B', fmt))
        fout.write(struct.pack('<I', len(dict_data)))
        fout.write(dict_data)

        # --- Chunks ---
        while True:
            raw = fin.read(CHUNK_SIZE)
            if not raw:
                break
            input_size += len(raw)
            bf = bloom.build(raw)

            # Hash chain over raw bytes — chunk N = SHA256(prev_hash || raw)
            h = hashlib.sha256()
            if prev_hash is not None:
                h.update(prev_hash)
            h.update(raw)
            chunk_hash = h.digest()
            prev_hash = chunk_hash

            min_ts, max_ts = _extract_timestamps(raw, fmt)
            field_bf = bloom.build_field(_extract_field_values(raw, fmt))
            chunk_offset = fout.tell()  # absolute byte offset stored in jump table
            comp = compressor.compress(raw)
            fout.write(comp)
            jump_table.append((chunk_offset, len(comp), len(raw), bf, chunk_hash, min_ts, max_ts, field_bf))

        # --- Jump table ---
        jump_table_offset = fout.tell()
        for offset, comp_size, orig_size, bf, chunk_hash, min_ts, max_ts, field_bf in jump_table:
            fout.write(struct.pack('<QII', offset, comp_size, orig_size))
            fout.write(bf)          # 1024 bytes main bloom filter
            fout.write(chunk_hash)  # 32 bytes SHA-256 hash chain entry
            fout.write(struct.pack('<QQ', min_ts, max_ts))  # 16 bytes timestamp range
            fout.write(field_bf)    # 512 bytes field-value bloom filter

        # Footer: chain_hash(32) + jt_offset(8) + num_chunks(4) = 44 bytes
        chain_hash = prev_hash if prev_hash is not None else b'\x00' * 32
        fout.write(chain_hash)
        fout.write(struct.pack('<QI', jump_table_offset, len(jump_table)))

        output_size = fout.tell()

    num_chunks = len(jump_table)
    bloom_kb = num_chunks * bloom.BLOOM_BYTES / 1024
    bloom_pct = num_chunks * bloom.BLOOM_BYTES / output_size * 100 if output_size else 0
    ratio = input_size / output_size if output_size else 0

    print(f"Format:  {FORMAT_NAMES[fmt]}", file=sys.stderr)
    print(f"Input:   {input_size / 1024 / 1024:.2f} MB", file=sys.stderr)
    print(f"Output:  {output_size / 1024 / 1024:.2f} MB", file=sys.stderr)
    print(f"Ratio:   {ratio:.2f}x", file=sys.stderr)
    print(f"Chunks:  {num_chunks}", file=sys.stderr)
    print(f"Bloom:   {bloom_kb:.1f} KB ({bloom_pct:.1f}% of output)", file=sys.stderr)
