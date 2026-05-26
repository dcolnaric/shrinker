"""Append new log entries to an existing .logz archive.

If the archive does not exist, behaves identically to compress
(creates a new archive from scratch).

Append protocol:
  1. Read the existing header (magic, version, format byte, dict).
  2. Read the footer to get: chain_hash (seed), jt_offset, num_old_chunks.
  3. Load the old jump table as raw bytes (we re-write them unchanged).
  4. Truncate the file at jt_offset — strips the old jump table + footer.
  5. Write new compressed chunks using the existing dictionary so that all
     chunks in the archive share the same dict.
  6. Write the combined jump table (old raw bytes + new entries).
  7. Write the new footer with the updated chain_hash, jt_offset, and
     total chunk count.
"""

import hashlib
import os
import struct
import sys
import zstandard as zstd

import bloom
import compress as compress_mod
from compress import (
    CHUNK_SIZE,
    VERSION,
    FOOTER_SIZE,
    JUMP_ENTRY_SIZE,
    _extract_timestamps,
    _extract_field_values,
)


def run(args):
    """CLI entry point for the append subcommand.

    Args:
        args: argparse.Namespace with .input, .archive, and optional .format.
    """
    _append(args.input, args.archive, getattr(args, 'format', None))


def _append(input_path, archive_path, fmt_name=None):
    """Append new log entries to an existing .logz archive.

    If the archive does not exist, creates a new one via compress._compress().

    Args:
        input_path:   Path to the input log file to append.
        archive_path: Path to the .logz archive (may not exist yet).
        fmt_name:     Optional format override — used only when creating a
                      new archive; ignored when appending to an existing one
                      (the archive's format byte takes precedence).
    """
    if not os.path.exists(archive_path):
        print("Archive not found — creating new archive.", file=sys.stderr)
        compress_mod._compress(input_path, archive_path, fmt_name)
        return

    # ------------------------------------------------------------------
    # 1. Read existing archive: header, footer, and raw jump table bytes.
    # ------------------------------------------------------------------
    with open(archive_path, 'rb') as f:
        # Header
        magic = f.read(4)
        if magic != b'LOGZ':
            print(f"error: not a .logz file (bad magic: {magic!r})",
                  file=sys.stderr)
            sys.exit(1)

        version = struct.unpack('<H', f.read(2))[0]
        if version != VERSION:
            print(f"error: unsupported version {version} (expected {VERSION})",
                  file=sys.stderr)
            sys.exit(1)

        fmt = struct.unpack('B', f.read(1))[0]   # format byte — drives bloom/ts

        dict_len = struct.unpack('<I', f.read(4))[0]
        dict_data = f.read(dict_len) if dict_len > 0 else b''

        # Footer — bootstraps everything
        f.seek(-FOOTER_SIZE, 2)
        seed_hash = f.read(32)                              # existing chain_hash
        jt_offset, num_old_chunks = struct.unpack('<QI', f.read(12))

        # Old jump table as raw bytes — we write it back verbatim;
        # each entry's offset field still points to the correct chunk
        # because we only truncate at jt_offset (chunk data is unchanged).
        f.seek(jt_offset)
        old_jt_raw = f.read(num_old_chunks * JUMP_ENTRY_SIZE)

    # ------------------------------------------------------------------
    # 2. Set up compressor using the existing dictionary.
    #    All chunks in the archive must share the same dict.
    # ------------------------------------------------------------------
    if dict_data:
        zdict_obj = zstd.ZstdCompressionDict(dict_data)
        compressor = zstd.ZstdCompressor(dict_data=zdict_obj, level=3)
    else:
        compressor = zstd.ZstdCompressor(level=3)

    # ------------------------------------------------------------------
    # 3. Truncate at jt_offset and write new chunks.
    #
    #    Hash chain initialisation:
    #      - If num_old_chunks > 0: first new chunk hashes as
    #            SHA256(seed_hash || raw)   (chains from existing archive)
    #      - If num_old_chunks == 0: first new chunk hashes as
    #            SHA256(raw)                (fresh chain, like a new archive)
    # ------------------------------------------------------------------
    new_jump_table = []   # list of (offset, comp_size, orig_size, bf, hash, min_ts, max_ts, field_bf)
    input_size = 0
    prev_hash = seed_hash if num_old_chunks > 0 else None

    with open(archive_path, 'r+b') as fout:
        fout.seek(jt_offset)
        fout.truncate()   # removes old jump table + footer

        with open(input_path, 'rb') as fin:
            while True:
                raw = fin.read(CHUNK_SIZE)
                if not raw:
                    break
                input_size += len(raw)

                # Build bloom filters
                bf       = bloom.build(raw)
                field_bf = bloom.build_field(_extract_field_values(raw, fmt))

                # Hash chain over raw bytes
                h = hashlib.sha256()
                if prev_hash is not None:
                    h.update(prev_hash)
                h.update(raw)
                chunk_hash = h.digest()
                prev_hash  = chunk_hash

                # Timestamp range
                min_ts, max_ts = _extract_timestamps(raw, fmt)

                # Compress and write
                chunk_offset = fout.tell()
                comp = compressor.compress(raw)
                fout.write(comp)

                new_jump_table.append((
                    chunk_offset, len(comp), len(raw),
                    bf, chunk_hash, min_ts, max_ts, field_bf,
                ))

        # ------------------------------------------------------------------
        # 4. Write combined jump table (old entries + new entries).
        # ------------------------------------------------------------------
        new_jt_offset = fout.tell()

        fout.write(old_jt_raw)   # old entries unchanged (offsets still valid)

        for offset, comp_size, orig_size, bf, chunk_hash, min_ts, max_ts, field_bf \
                in new_jump_table:
            fout.write(struct.pack('<QII', offset, comp_size, orig_size))
            fout.write(bf)            # 1024 bytes main bloom
            fout.write(chunk_hash)    # 32 bytes SHA-256 hash chain
            fout.write(struct.pack('<QQ', min_ts, max_ts))  # 16 bytes ts range
            fout.write(field_bf)      # 512 bytes field bloom

        # ------------------------------------------------------------------
        # 5. Write new 44-byte footer.
        #
        #    final_hash:
        #      - new chunks were added:  last new chunk's hash (prev_hash updated)
        #      - no new chunks added:    seed_hash  (prev_hash unchanged)
        #      - archive was empty + no new chunks: b'\x00' * 32
        # ------------------------------------------------------------------
        total_chunks = num_old_chunks + len(new_jump_table)
        final_hash   = prev_hash if prev_hash is not None else b'\x00' * 32

        fout.write(final_hash)
        fout.write(struct.pack('<QI', new_jt_offset, total_chunks))

        out_size = fout.tell()

    # ------------------------------------------------------------------
    # 6. Stats (to stderr, like compress.py)
    # ------------------------------------------------------------------
    fmt_names = {0: 'json', 1: 'syslog', 2: 'plaintext'}
    fmt_str = fmt_names.get(fmt, 'unknown')

    print(f"Format:   {fmt_str}",                    file=sys.stderr)
    print(f"Appended: {len(new_jump_table)} new chunks", file=sys.stderr)
    print(f"Total:    {total_chunks} chunks",         file=sys.stderr)
    print(f"Input:    {input_size / 1024 / 1024:.2f} MB", file=sys.stderr)
    print(f"Archive:  {out_size / 1024 / 1024:.2f} MB",   file=sys.stderr)
