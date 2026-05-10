import struct
import sys
import zstandard as zstd

import bloom

MAGIC = b'LOGZ'


def run(args):
    output_path = getattr(args, 'output', None)
    if output_path:
        with open(output_path, 'wb') as fout:
            _decompress(args.file, fout)
    else:
        _decompress(args.file, sys.stdout.buffer)


def _decompress(logz_path, fout):
    with open(logz_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC:
            print(f"error: not a .logz file (bad magic: {magic!r})", file=sys.stderr)
            sys.exit(1)

        version = struct.unpack('<H', f.read(2))[0]
        f.read(1)  # FORMAT byte — not needed for decompression
        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        f.seek(-12, 2)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            if version >= 2:
                f.read(bloom.BLOOM_BYTES)  # skip bloom bytes
            jump_table.append((offset, comp_size, orig_size))

        output_size = 0
        for offset, comp_size, orig_size in jump_table:
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)
            fout.write(raw)
            output_size += len(raw)

    print(f"Chunks:  {num_chunks}", file=sys.stderr)
    print(f"Output:  {output_size / 1024 / 1024:.2f} MB", file=sys.stderr)
