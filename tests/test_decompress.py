import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import compress
import decompress

DATA_DIR = os.path.join(os.path.dirname(__file__), '..', 'data')
TEST_LOG = os.path.join(DATA_DIR, 'test.log')


class TestDecompress(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.logz_path = os.path.join(cls.tmpdir, 'test.logz')
        cls.restored_path = os.path.join(cls.tmpdir, 'restored.log')

        compress._compress(TEST_LOG, cls.logz_path)

        with open(cls.restored_path, 'wb') as fout:
            decompress._decompress(cls.logz_path, fout)

    def test_byte_exact_round_trip(self):
        result = subprocess.run(
            ['diff', TEST_LOG, self.restored_path],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 0, "diff found differences — round-trip is not lossless")

    def test_output_size_matches_input_size(self):
        input_size = os.path.getsize(TEST_LOG)
        output_size = os.path.getsize(self.restored_path)
        self.assertEqual(output_size, input_size, f"Size mismatch: input={input_size}, output={output_size}")


if __name__ == '__main__':
    unittest.main()
