import json
import re
import struct
import sys
import zstandard as zstd

import bloom

CHUNK_SIZE = 64 * 1024
DICT_SIZE = 112 * 1024
TRAIN_LIMIT = 10 * 1024 * 1024
VERSION = 2

FORMAT_JSON = 0
FORMAT_SYSLOG = 1
FORMAT_PLAINTEXT = 2
FORMAT_NAMES = {FORMAT_JSON: 'json', FORMAT_SYSLOG: 'syslog', FORMAT_PLAINTEXT: 'plaintext'}
FORMAT_BY_NAME = {'json': FORMAT_JSON, 'syslog': FORMAT_SYSLOG, 'plaintext': FORMAT_PLAINTEXT}

SYSLOG_RE = re.compile(r'^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s')


def detect_format(path):
    lines = []
    with open(path, 'rb') as f:
        for _ in range(5):
            line = f.readline()
            if not line:
                break
            lines.append(line.decode('utf-8', errors='replace').rstrip())
    if not lines:
        return FORMAT_PLAINTEXT
    threshold = max(1, min(3, len(lines)))
    if sum(1 for l in lines if _try_json(l)) >= threshold:
        return FORMAT_JSON
    if sum(1 for l in lines if SYSLOG_RE.match(l)) >= threshold:
        return FORMAT_SYSLOG
    return FORMAT_PLAINTEXT


def _try_json(line):
    try:
        json.loads(line)
        return True
    except (json.JSONDecodeError, ValueError):
        return False


def _train_dict(path):
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
        return None
    try:
        return zstd.train_dictionary(DICT_SIZE, samples)
    except zstd.ZstdError:
        return None


def run(args):
    _compress(args.input, args.output, getattr(args, 'format', None))


def _compress(input_path, output_path, fmt_name=None):
    fmt = FORMAT_BY_NAME[fmt_name] if fmt_name else detect_format(input_path)

    print("Training dictionary...", file=sys.stderr)
    zdict = _train_dict(input_path)
    dict_data = zdict.as_bytes() if zdict else b''

    if zdict:
        compressor = zstd.ZstdCompressor(dict_data=zdict, level=3)
    else:
        compressor = zstd.ZstdCompressor(level=3)

    input_size = 0
    jump_table = []  # (chunk_offset, comp_size, orig_size, bloom_bytes)

    with open(input_path, 'rb') as fin, open(output_path, 'wb') as fout:
        fout.write(b'LOGZ')
        fout.write(struct.pack('<H', VERSION))
        fout.write(struct.pack('B', fmt))
        fout.write(struct.pack('<I', len(dict_data)))
        fout.write(dict_data)

        while True:
            raw = fin.read(CHUNK_SIZE)
            if not raw:
                break
            input_size += len(raw)
            bf = bloom.build(raw)
            chunk_offset = fout.tell()
            comp = compressor.compress(raw)
            fout.write(comp)
            jump_table.append((chunk_offset, len(comp), len(raw), bf))

        jump_table_offset = fout.tell()
        for offset, comp_size, orig_size, bf in jump_table:
            fout.write(struct.pack('<QII', offset, comp_size, orig_size))
            fout.write(bf)
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
