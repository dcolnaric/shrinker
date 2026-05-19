"""Compress log files into the .logz seekable compressed format."""

import hashlib
import json
import re
import struct
import sys
import zstandard as zstd

import bloom

CHUNK_SIZE = 64 * 1024   # 64 KB — SIMD-aligned for the future C rewrite
DICT_SIZE = 112 * 1024   # zstd dictionary target size in bytes
TRAIN_LIMIT = 10 * 1024 * 1024  # cap dictionary training at 10 MB so startup stays fast

VERSION = 2  # v1 = no bloom/hash, v2 = bloom + SHA-256 hash chain in jump table
FOOTER_SIZE = 44        # chain_hash(32) + jt_offset(8) + num_chunks(4)
JUMP_ENTRY_SIZE = 1072  # offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + hash(32)

FORMAT_JSON = 0
FORMAT_SYSLOG = 1
FORMAT_PLAINTEXT = 2
FORMAT_NAMES = {FORMAT_JSON: 'json', FORMAT_SYSLOG: 'syslog', FORMAT_PLAINTEXT: 'plaintext'}
FORMAT_BY_NAME = {'json': FORMAT_JSON, 'syslog': FORMAT_SYSLOG, 'plaintext': FORMAT_PLAINTEXT}

SYSLOG_RE = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s')


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
    jump_table = []  # accumulates (chunk_offset, comp_size, orig_size, bloom_bytes, chunk_hash)
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

            chunk_offset = fout.tell()  # absolute byte offset stored in jump table
            comp = compressor.compress(raw)
            fout.write(comp)
            jump_table.append((chunk_offset, len(comp), len(raw), bf, chunk_hash))

        # --- Jump table ---
        jump_table_offset = fout.tell()
        for offset, comp_size, orig_size, bf, chunk_hash in jump_table:
            fout.write(struct.pack('<QII', offset, comp_size, orig_size))
            fout.write(bf)          # 1024 bytes bloom filter
            fout.write(chunk_hash)  # 32 bytes SHA-256 hash chain entry

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
