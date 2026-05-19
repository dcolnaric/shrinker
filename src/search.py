"""Search a .logz file for a query string without full decompression."""

import struct
import sys
import zstandard as zstd

import bloom

FOOTER_SIZE = 44        # chain_hash(32) + jt_offset(8) + num_chunks(4)
JUMP_ENTRY_SIZE = 1072  # offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + hash(32)


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
        # Read header fields in order
        f.seek(4)
        version = struct.unpack('<H', f.read(2))[0]
        if version != 2:
            print(f"error: unsupported version {version} (expected 2)", file=sys.stderr)
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

        # Read the full jump table into memory — it's small (1072 bytes per chunk)
        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            bf = f.read(bloom.BLOOM_BYTES)
            f.read(32)  # skip stored chunk_hash
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
