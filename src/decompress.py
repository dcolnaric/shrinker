"""Decompress a .logz file back to the original byte-exact log content."""

import struct
import sys
import zstandard as zstd

import bloom

MAGIC = b'LOGZ'


def run(args):
    """CLI entry point — writes decompressed output to a file or stdout.

    Args:
        args: argparse.Namespace with .file and optional .output.
              When .output is absent, content is written to stdout (pipe-friendly).
    """
    output_path = getattr(args, 'output', None)
    if output_path:
        with open(output_path, 'wb') as fout:
            _decompress(args.file, fout)
    else:
        _decompress(args.file, sys.stdout.buffer)


def _decompress(logz_path, fout):
    """Decompress all chunks from a .logz file and write them to fout in order.

    Reads the jump table from the file footer to locate each chunk, then
    decompresses them sequentially using the shared dictionary from the header.
    Output is byte-exact — no bytes are added, removed, or modified.

    Args:
        logz_path: Path to the .logz file to decompress.
        fout:      Writable binary file-like object for the decompressed output.

    Exits:
        Calls sys.exit(1) if the file does not start with the LOGZ magic bytes.
    """
    with open(logz_path, 'rb') as f:
        magic = f.read(4)
        if magic != MAGIC:
            # Fail loudly rather than silently producing garbage output
            print(f"error: not a .logz file (bad magic: {magic!r})", file=sys.stderr)
            sys.exit(1)

        version = struct.unpack('<H', f.read(2))[0]
        f.read(1)  # FORMAT byte — records original log type but not needed to decompress

        dict_len = struct.unpack('<I', f.read(4))[0]
        if dict_len > 0:
            dict_data = f.read(dict_len)
            zdict = zstd.ZstdCompressionDict(dict_data)
            decompressor = zstd.ZstdDecompressor(dict_data=zdict)
        else:
            decompressor = zstd.ZstdDecompressor()

        # Footer is always 12 bytes at EOF — same bootstrap as search.py
        f.seek(-12, 2)
        jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

        f.seek(jump_table_offset)
        jump_table = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            if version >= 2:
                f.read(bloom.BLOOM_BYTES)  # bloom bytes are not needed for full decompression
            jump_table.append((offset, comp_size, orig_size))

        output_size = 0
        for offset, comp_size, orig_size in jump_table:
            f.seek(offset)
            raw = decompressor.decompress(f.read(comp_size), orig_size)
            fout.write(raw)
            output_size += len(raw)

    print(f"Chunks:  {num_chunks}", file=sys.stderr)
    print(f"Output:  {output_size / 1024 / 1024:.2f} MB", file=sys.stderr)
