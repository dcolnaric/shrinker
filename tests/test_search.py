import io
import json
import os
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import compress
import search


def _run_search(logz_path, query):
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        search._search(logz_path, query)
    matches = [l for l in stdout_buf.getvalue().splitlines() if l]
    stderr_text = stderr_buf.getvalue()
    m = re.search(r'Skipped by bloom: (\d+)', stderr_text)
    skipped = int(m.group(1)) if m else 0
    return matches, skipped


class TestSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        input_path = os.path.join(cls.tmpdir, 'test.log')
        cls.logz_path = os.path.join(cls.tmpdir, 'test.logz')

        # Build lines large enough (~900 bytes each) to guarantee multiple 64KB chunks
        # 200 lines × ~900 bytes ≈ 180 KB → 2-3 chunks
        lines = []
        for i in range(200):
            lines.append(json.dumps({
                "timestamp": f"2024-01-01T{i // 3600:02d}:{(i % 3600) // 60:02d}:{i % 60:02d}Z",
                "level": "INFO",
                "service": "payment-service",
                "message": "Request dispatched to downstream handler with full context",
                "request_id": f"req-{i:06d}-{'x' * 30}",
                "trace_id": f"trace-{i:08d}-{'y' * 30}",
                "status": 200,
                "latency_ms": 10 + i,
                "payload": "A" * 700,
            }))
        with open(input_path, 'w') as f:
            f.write('\n'.join(lines))

        compress._compress(input_path, cls.logz_path)
        cls.target_request_id = f"req-{50:06d}-" + "x" * 30

    def test_known_term_finds_exactly_one_match(self):
        matches, _ = _run_search(self.logz_path, self.target_request_id)
        self.assertEqual(len(matches), 1, f"Expected 1 match, got {len(matches)}: {matches}")

    def test_absent_term_finds_zero_matches(self):
        matches, _ = _run_search(self.logz_path, "999_definitely_not_present")
        self.assertEqual(len(matches), 0)

    def test_bloom_skips_at_least_one_chunk(self):
        _, skipped = _run_search(self.logz_path, self.target_request_id)
        self.assertGreater(skipped, 0, "Bloom filter should skip at least one chunk")


if __name__ == '__main__':
    unittest.main()
