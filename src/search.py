import struct
import sys
import zstandard as zstd

import bloom


def run(args):
    _search(args.file, args.query)


def _search(logz_path, query):
    query_bytes = query.encode('utf-8')

    with open(logz_path, 'rb') as f:
        f.seek(-12, 2)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        f.seek(4)
        version = struct.unpack('<H', f.read(2))[0]

        f.seek(7)
        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            bf = f.read(bloom.BLOOM_BYTES) if version >= 2 else None
            jump_table.append((offset, comp_size, orig_size, bf))

        matches = 0
        chunks_scanned = 0
        skipped_by_bloom = 0

        for offset, comp_size, orig_size, bf in jump_table:
            if bf is not None and not bloom.query_present(bf, query_bytes):
                skipped_by_bloom += 1
                continue
            chunks_scanned += 1
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)

            if query_bytes not in raw:
                continue

            for line in raw.split(b'\n'):
                if line and query_bytes in line:
                    print(line.decode('utf-8', errors='replace'))
                    matches += 1

    print(
        f"Matches: {matches}  |  Chunks scanned: {chunks_scanned} / {num_chunks}  |  Skipped by bloom: {skipped_by_bloom}",
        file=sys.stderr,
    )
