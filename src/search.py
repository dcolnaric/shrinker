"""Search a .logz file for a query string without full decompression."""

import struct
import sys
import zstandard as zstd

import bloom


def run(args):
    """CLI entry point — delegates to _search with parsed argparse namespace.

    Args:
        args: argparse.Namespace with .file and .query.
    """
    _search(args.file, args.query)


def _search(logz_path, query):
    """Search a .logz file and print every line that contains the query string.

    Uses per-chunk bloom filters to skip chunks that cannot possibly contain the
    query. Only chunks that pass the bloom check are decompressed — on a typical
    UUID search this skips 95-99% of chunks.

    Matching lines are printed to stdout. A summary line (matches, chunks
    scanned, chunks skipped) is printed to stderr.

    Args:
        logz_path: Path to the .logz compressed file.
        query:     Search string (UTF-8). Matched as a literal byte sequence.
    """
    query_bytes = query.encode('utf-8')

    with open(logz_path, 'rb') as f:
        # Footer is always the last 12 bytes — seek there first to find the jump table
        f.seek(-12, 2)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        # Version determines whether bloom filters are present in the jump table
        f.seek(4)
        version = struct.unpack('<H', f.read(2))[0]

        # Load the shared dictionary; without it zstd cannot decompress v2 chunks
        f.seek(7)
        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        # Read the full jump table into memory — it's small (1040 bytes per chunk)
        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            # v1 files have no bloom bytes; read them only when the version supports it
            bf = f.read(bloom.BLOOM_BYTES) if version >= 2 else None
            jump_table.append((offset, comp_size, orig_size, bf))

        matches = 0
        chunks_scanned = 0
        skipped_by_bloom = 0

        for offset, comp_size, orig_size, bf in jump_table:
            if bf is not None and not bloom.query_present(bf, query_bytes):
                # Bloom filter guarantees no false negatives — safe to skip entirely
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
        f"Matches: {matches}  |  Chunks scanned: {chunks_scanned} / {num_chunks}  |  Skipped by bloom: {skipped_by_bloom}",
        file=sys.stderr,
    )
