import struct
import sys
import zstandard as zstd


def run(args):
    _search(args.file, args.query)


def _search(logz_path, query):
    query_bytes = query.encode('utf-8')

    with open(logz_path, 'rb') as f:
        f.seek(-12, 2)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        f.seek(7)
        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        f.seek(jump_table_offset)
        jump_table = [struct.unpack('<QII', f.read(16)) for _ in range(num_chunks)]

        matches = 0
        chunks_scanned = 0

        for offset, comp_size, orig_size in jump_table:
            chunks_scanned += 1
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)

            if query_bytes not in raw:
                continue

            for line in raw.split(b'\n'):
                if line and query_bytes in line:
                    print(line.decode('utf-8', errors='replace'))
                    matches += 1

    print(f"Matches: {matches}  |  Chunks scanned: {chunks_scanned} / {num_chunks}", file=sys.stderr)
