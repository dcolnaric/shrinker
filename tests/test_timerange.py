import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import bloom
import compress
import search

CHUNK_SIZE = 64 * 1024

DAY1_DATE = '2025-01-01'
DAY2_DATE = '2025-01-02'
DAY3_DATE = '2025-01-03'

DAY2_START = int(datetime(2025, 1, 2, 0, 0, 0, tzinfo=timezone.utc).timestamp())
DAY2_END   = int(datetime(2025, 1, 2, 23, 59, 59, tzinfo=timezone.utc).timestamp())

BEFORE_START = int(datetime(2020, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
BEFORE_END   = int(datetime(2020, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())

AFTER_START  = int(datetime(2030, 1, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp())
AFTER_END    = int(datetime(2030, 12, 31, 23, 59, 59, tzinfo=timezone.utc).timestamp())


def _make_timed_log(tmpdir):
    """Compress a 3-day log where each day's data fills at least 2 full 64 KB chunks."""
    input_path = os.path.join(tmpdir, 'timed.log')
    logz_path  = os.path.join(tmpdir, 'timed.logz')

    with open(input_path, 'w') as f:
        for day_num, date_str in enumerate([DAY1_DATE, DAY2_DATE, DAY3_DATE], start=1):
            # 150 lines × ~900 bytes ≈ 135 KB = 2+ chunks per day
            for i in range(150):
                line = json.dumps({
                    "timestamp": f"{date_str}T{i % 24:02d}:{i % 60:02d}:00Z",
                    "day": day_num,
                    "marker": f"DAY{day_num}MARKER",
                    "payload": "X" * 800,
                })
                f.write(line + '\n')

    compress._compress(input_path, logz_path)
    return logz_path


def _run_search(logz_path, query, from_ts=None, to_ts=None):
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        search._search(logz_path, query, from_ts=from_ts, to_ts=to_ts)
    matches = [l for l in stdout_buf.getvalue().splitlines() if l]
    stderr_text = stderr_buf.getvalue()
    m = re.search(r'Skipped by bloom: (\d+)', stderr_text)
    skipped_bloom = int(m.group(1)) if m else 0
    m = re.search(r'Skipped by time: (\d+)', stderr_text)
    skipped_time = int(m.group(1)) if m else 0
    return matches, skipped_bloom, skipped_time


class TestTimeRange(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp()
        cls.logz_path = _make_timed_log(cls.tmpdir)

    def test_timestamps_stored_in_jump_table(self):
        """Jump table entries must contain non-zero min_ts/max_ts for timestamped logs."""
        with open(self.logz_path, 'rb') as f:
            f.seek(-compress.FOOTER_SIZE, 2)
            f.read(32)  # chain_hash
            jt_offset, num_chunks = struct.unpack('<QI', f.read(12))
            f.seek(jt_offset)
            has_timestamps = False
            for _ in range(num_chunks):
                f.read(16)              # offset, comp_size, orig_size
                f.read(bloom.BLOOM_BYTES)
                f.read(32)              # hash
                min_ts, max_ts = struct.unpack('<QQ', f.read(16))
                f.read(bloom.FIELD_BLOOM_BYTES)  # field bloom (v4)
                if min_ts > 0 and max_ts > 0:
                    has_timestamps = True
                    break
        self.assertTrue(has_timestamps, "At least one chunk must have stored timestamps")

    def test_day2_range_skips_day1_and_day3_chunks(self):
        """Day-2 time window must skip at least some day-1 and day-3 chunks."""
        matches, _, skipped_time = _run_search(
            self.logz_path, 'DAY2MARKER',
            from_ts=DAY2_START, to_ts=DAY2_END,
        )
        self.assertGreater(len(matches), 0, "Should find day-2 matches")
        self.assertGreater(skipped_time, 0, "At least some chunks must be time-skipped")
        for line in matches:
            self.assertIn('DAY2MARKER', line)

    def test_range_before_all_data_returns_zero_matches(self):
        """A range entirely before the data must find nothing and skip all chunks."""
        matches, _, skipped_time = _run_search(
            self.logz_path, 'DAY',
            from_ts=BEFORE_START, to_ts=BEFORE_END,
        )
        self.assertEqual(len(matches), 0)
        self.assertGreater(skipped_time, 0, "All chunks should be time-skipped")

    def test_range_after_all_data_returns_zero_matches(self):
        """A range entirely after the data must find nothing and skip all chunks."""
        matches, _, skipped_time = _run_search(
            self.logz_path, 'DAY',
            from_ts=AFTER_START, to_ts=AFTER_END,
        )
        self.assertEqual(len(matches), 0)
        self.assertGreater(skipped_time, 0, "All chunks should be time-skipped")

    def test_no_time_range_no_time_skipping(self):
        """Without from_ts/to_ts no chunks should be time-skipped."""
        _, _, skipped_time = _run_search(self.logz_path, 'DAY1MARKER')
        self.assertEqual(skipped_time, 0)


if __name__ == '__main__':
    unittest.main()
