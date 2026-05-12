import json
import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import bloom
import compress


class TestCompress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.input_path = os.path.join(cls.tmpdir, 'test.log')
        cls.output_path = os.path.join(cls.tmpdir, 'test.logz')

        lines = [
            json.dumps({
                "timestamp": f"2024-01-01T{i // 3600:02d}:{(i % 3600) // 60:02d}:{i % 60:02d}Z",
                "level": "INFO",
                "service": "api-gateway",
                "message": "Request processed successfully",
                "request_id": f"req-{i:06d}",
                "status": 200,
                "latency_ms": 42 + (i % 100),
            })
            for i in range(1000)
        ]
        with open(cls.input_path, 'w') as f:
            f.write('\n'.join(lines))

        compress._compress(cls.input_path, cls.output_path)

    def _read_jump_table(self):
        with open(self.output_path, 'rb') as f:
            f.seek(-12, 2)
            jump_table_offset, num_chunks = struct.unpack('<QI', f.read(12))
            f.seek(jump_table_offset)
            entries = []
            for _ in range(num_chunks):
                offset, comp_size, orig_size = struct.unpack('<QII', f.read(16))
                bf = f.read(bloom.BLOOM_BYTES)
                entries.append((offset, comp_size, orig_size, bf))
        return num_chunks, entries

    def test_magic_bytes(self):
        with open(self.output_path, 'rb') as f:
            magic = f.read(4)
        self.assertEqual(magic, b'LOGZ')

    def test_output_smaller_than_input(self):
        self.assertLess(
            os.path.getsize(self.output_path),
            os.path.getsize(self.input_path),
        )

    def test_chunk_count_greater_than_zero(self):
        num_chunks, _ = self._read_jump_table()
        self.assertGreater(num_chunks, 0)

    def test_bloom_data_exists(self):
        _, entries = self._read_jump_table()
        for _, _, _, bf in entries:
            self.assertEqual(len(bf), bloom.BLOOM_BYTES)
            self.assertGreater(sum(bf), 0, "Bloom filter bytes should not all be zero")


if __name__ == '__main__':
    unittest.main()
