"""Verify the SHA-256 hash chain of a .logz file, detecting any tampering."""

import hashlib
import struct
import sys
import zstandard as zstd

import bloom

MAGIC = b'LOGZ'
FOOTER_SIZE = 44        # chain_hash(32) + jt_offset(8) + num_chunks(4)
JUMP_ENTRY_SIZE = 1072  # offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + hash(32)


def verify(logz_path):
    """Verify the integrity of a .logz file by recomputing its SHA-256 hash chain.

    Reads every chunk, recomputes the hash chain over raw (pre-compression) bytes,
    and compares against the stored hashes in the jump table. Also verifies that the
    footer chain_hash matches the final chunk's hash.

    Args:
        logz_path: Path to the .logz file to verify.

    Returns:
        0 if the file is intact (VERIFIED).
        1 if any chunk hash or the footer chain hash does not match (TAMPERED).
        2 on usage or format errors.
    """
    try:
        with open(logz_path, 'rb') as f:
            magic = f.read(4)
            if magic != MAGIC:
                print(f"error: not a .logz file (bad magic: {magic!r})", file=sys.stderr)
                return 2

            version = struct.unpack('<H', f.read(2))[0]
            if version != 2:
                print(f"error: unsupported version {version} (expected 2)", file=sys.stderr)
                return 2

            f.read(1)  # FORMAT byte — not needed for verification

            dict_len = struct.unpack('<I', f.read(4))[0]
            if dict_len > 0:
                dict_data = f.read(dict_len)
                zdict = zstd.ZstdCompressionDict(dict_data)
                decompressor = zstd.ZstdDecompressor(dict_data=zdict)
            else:
                decompressor = zstd.ZstdDecompressor()

            # Bootstrap from footer
            f.seek(-FOOTER_SIZE, 2)
            footer_chain_hash = f.read(32)
            jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))

            # Read full jump table
            f.seek(jump_table_offset)
            jump_table = []
            for _ in range(num_chunks):
                offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
                f.read(bloom.BLOOM_BYTES)  # bloom filter not needed for verification
                stored_hash = f.read(32)
                jump_table.append((offset, comp_size, orig_size, stored_hash))

            # Walk every chunk and recompute hash chain over raw bytes
            prev_hash = None
            for i, (offset, comp_size, orig_size, stored_hash) in enumerate(jump_table):
                f.seek(offset)
                try:
                    raw = decompressor.decompress(f.read(comp_size), orig_size)
                except Exception:
                    # Decompression failure is itself evidence of tampering
                    print(
                        f"TAMPERED  {logz_path}  chunk {i}"
                        f"  decompression failed"
                    )
                    return 1

                h = hashlib.sha256()
                if prev_hash is not None:
                    h.update(prev_hash)
                h.update(raw)
                computed = h.digest()

                if computed != stored_hash:
                    print(
                        f"TAMPERED  {logz_path}  chunk {i}"
                        f"  expected {stored_hash.hex()[:16]}…"
                        f"  got {computed.hex()[:16]}…"
                    )
                    return 1

                prev_hash = computed

            # Footer chain_hash must equal the final chunk's hash
            if prev_hash is not None and footer_chain_hash != prev_hash:
                print(
                    f"TAMPERED  {logz_path}  footer chain_hash mismatch"
                    f"  expected {prev_hash.hex()[:16]}…"
                    f"  got {footer_chain_hash.hex()[:16]}…"
                )
                return 1

            final_hex = prev_hash.hex()[:16] if prev_hash else '(empty)'
            print(f"VERIFIED  {logz_path}  {num_chunks} chunks  chain {final_hex}…")
            return 0

    except FileNotFoundError:
        print(f"error: file not found: {logz_path}", file=sys.stderr)
        return 2
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
