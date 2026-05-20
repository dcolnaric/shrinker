import hashlib
import io
import json
import os
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import bloom
import compress
import verify as verify_module


def _make_logz(tmpdir, num_lines=200):
    """Create a .logz test file guaranteed to span multiple 64 KB chunks."""
    input_path = os.path.join(tmpdir, 'test.log')
    logz_path = os.path.join(tmpdir, 'test.logz')
    # ~900 bytes per line × 200 lines ≈ 180 KB → ensures at least 2 chunks
    lines = []
    for i in range(num_lines):
        lines.append(json.dumps({
            "timestamp": f"2024-01-01T00:{i // 60:02d}:{i % 60:02d}Z",
            "level": "INFO",
            "service": "api",
            "message": "Request processed",
            "request_id": f"req-{i:06d}",
            "payload": "A" * 700,
        }))
    with open(input_path, 'w') as f:
        f.write('\n'.join(lines))
    compress._compress(input_path, logz_path)
    return logz_path


def _read_jump_table(logz_path):
    """Return (entries, footer_chain_hash, jt_offset).

    entries: list of (offset, comp_size, orig_size, stored_hash)
    """
    with open(logz_path, 'rb') as f:
        f.seek(-compress.FOOTER_SIZE, 2)
        footer_chain_hash = f.read(32)
        jt_offset, num_chunks = struct.unpack('<QI', f.read(12))
        f.seek(jt_offset)
        entries = []
        for _ in range(num_chunks):
            offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
            f.read(bloom.BLOOM_BYTES)  # skip bloom
            stored_hash = f.read(32)
            f.read(16)                 # skip min_ts + max_ts
            entries.append((offset, comp_size, orig_size, stored_hash))
    return entries, footer_chain_hash, jt_offset


class TestVerify(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.logz_path = _make_logz(cls.tmpdir)
        cls.entries, cls.footer_chain_hash, cls.jt_offset = _read_jump_table(cls.logz_path)

    def _run_verify(self, path):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = verify_module.verify(path)
        return rc, buf.getvalue()

    def _tampered_copy(self, name, mutate_fn):
        """Copy logz_path, apply mutate_fn(bytearray), write to name, return path."""
        with open(self.logz_path, 'rb') as f:
            data = bytearray(f.read())
        mutate_fn(data)
        path = os.path.join(self.tmpdir, name)
        with open(path, 'wb') as f:
            f.write(data)
        return path

    def test_clean_returns_0(self):
        rc, _ = self._run_verify(self.logz_path)
        self.assertEqual(rc, 0)

    def test_clean_prints_verified(self):
        _, output = self._run_verify(self.logz_path)
        self.assertIn("VERIFIED", output)

    def test_tamper_chunk0_returns_1(self):
        offset, comp_size, _, _ = self.entries[0]

        def flip(data):
            data[offset + comp_size // 2] ^= 0xFF

        path = self._tampered_copy('tamper_chunk0.logz', flip)
        rc, _ = self._run_verify(path)
        self.assertEqual(rc, 1)

    def test_tamper_chunk1_returns_1(self):
        self.assertGreaterEqual(len(self.entries), 2, "Need at least 2 chunks")
        offset, comp_size, _, _ = self.entries[1]

        def flip(data):
            data[offset + comp_size // 2] ^= 0xFF

        path = self._tampered_copy('tamper_chunk1.logz', flip)
        rc, _ = self._run_verify(path)
        self.assertEqual(rc, 1)

    def test_tampered_exit_code_is_1_not_0(self):
        offset, comp_size, _, _ = self.entries[0]

        def flip(data):
            data[offset + 1] ^= 0x01

        path = self._tampered_copy('tamper_exit_code.logz', flip)
        rc, _ = self._run_verify(path)
        self.assertEqual(rc, 1)

    def test_zeroed_stored_hash_returns_1(self):
        # Stored hash for entry N is at: jt_offset + N*JUMP_ENTRY_SIZE + 16 + BLOOM_BYTES
        hash_pos = self.jt_offset + 16 + bloom.BLOOM_BYTES

        def zero_hash(data):
            data[hash_pos:hash_pos + 32] = b'\x00' * 32

        path = self._tampered_copy('zeroed_hash.logz', zero_hash)
        rc, _ = self._run_verify(path)
        self.assertEqual(rc, 1)

    def test_footer_chain_hash_equals_last_entry_hash(self):
        last_stored_hash = self.entries[-1][3]
        self.assertEqual(self.footer_chain_hash, last_stored_hash)


if __name__ == '__main__':
    unittest.main()
