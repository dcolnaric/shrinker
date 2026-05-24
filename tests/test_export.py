"""Tests for the export command (Phase 2 Step 5)."""

import csv
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import compress
import export as export_mod

# ---------------------------------------------------------------------------
# Date constants for the time-range test
# ---------------------------------------------------------------------------
DAY1 = '2025-03-01'
DAY2 = '2025-03-02'
DAY3 = '2025-03-03'

DAY2_START = int(datetime(2025, 3, 2,  0,  0,  0, tzinfo=timezone.utc).timestamp())
DAY2_END   = int(datetime(2025, 3, 2, 23, 59, 59, tzinfo=timezone.utc).timestamp())


# ---------------------------------------------------------------------------
# Test-data helpers
# ---------------------------------------------------------------------------

def _make_small_json_log(tmpdir, num_lines=50):
    """Single-chunk JSON log (~13 KB raw).

    50 lines × ~270 bytes is well under the 64 KB chunk size so there are no
    chunk-boundary line splits.  Used for tests that check exact row counts.
    """
    input_path = os.path.join(tmpdir, 'small.log')
    logz_path  = os.path.join(tmpdir, 'small.logz')
    with open(input_path, 'w') as f:
        for i in range(num_lines):
            f.write(json.dumps({
                'timestamp': f'2025-06-{(i % 28) + 1:02d}T12:00:00Z',
                'level':     'INFO',
                'user':      'admin',
                'ip':        '192.168.1.1',
                'action':    'read',
                'message':   f'Request {i}',
                'payload':   'X' * 200,
            }) + '\n')
    compress._compress(input_path, logz_path)
    return logz_path, num_lines


def _make_timed_json_log(tmpdir):
    """Multi-chunk JSON log spanning 3 days (200 lines per day × ~700 bytes ≈ 3 chunks/day).

    Enough data per day to guarantee pure per-day chunks for reliable time-range
    skip testing.
    """
    input_path = os.path.join(tmpdir, 'timed.log')
    logz_path  = os.path.join(tmpdir, 'timed.logz')
    with open(input_path, 'w') as f:
        for date_str in [DAY1, DAY2, DAY3]:
            for i in range(200):
                f.write(json.dumps({
                    'timestamp': f'{date_str}T{i % 24:02d}:{i % 60:02d}:00Z',
                    'level':     'INFO',
                    'user':      'tester',
                    'ip':        '10.0.0.1',
                    'action':    'test',
                    'message':   f'Line {i}',
                    'payload':   'Y' * 600,
                }) + '\n')
    compress._compress(input_path, logz_path)
    return logz_path


def _make_plaintext_log(tmpdir, num_lines=60):
    """Plaintext (non-JSON) log so we can verify the raw-only export path."""
    input_path = os.path.join(tmpdir, 'plain.log')
    logz_path  = os.path.join(tmpdir, 'plain.logz')
    with open(input_path, 'w') as f:
        for i in range(num_lines):
            f.write(f"INFO user=admin action=read ip=192.168.1.1 req={i} {'X' * 200}\n")
    compress._compress(input_path, logz_path)
    return logz_path, num_lines


def _run_export(logz_path, from_ts=None, to_ts=None, output_fmt='csv'):
    """Capture stdout/stderr from _export and return both as strings."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        export_mod._export(logz_path, from_ts=from_ts, to_ts=to_ts, output_fmt=output_fmt)
    return stdout_buf.getvalue(), stderr_buf.getvalue()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir    = tempfile.mkdtemp()
        cls.json_logz, cls.json_lines = _make_small_json_log(cls.tmpdir)
        cls.timed_logz                = _make_timed_json_log(cls.tmpdir)
        cls.plain_logz, cls.plain_lines = _make_plaintext_log(cls.tmpdir)

    # ------------------------------------------------------------------
    # 1. CSV export — headers
    # ------------------------------------------------------------------

    def test_csv_has_correct_headers(self):
        """CSV export must start with a header row matching EXPORT_FIELDS."""
        stdout, _ = _run_export(self.json_logz, output_fmt='csv')
        reader = csv.reader(io.StringIO(stdout))
        header = next(reader)
        self.assertEqual(header, list(export_mod.EXPORT_FIELDS))

    # ------------------------------------------------------------------
    # 2. JSON export — valid JSONL with all expected keys
    # ------------------------------------------------------------------

    def test_jsonl_output_is_valid_and_has_all_fields(self):
        """JSONL export must produce parseable objects with every EXPORT_FIELDS key."""
        stdout, _ = _run_export(self.json_logz, output_fmt='json')
        lines = [l for l in stdout.splitlines() if l]
        self.assertGreater(len(lines), 0, "Should produce at least one JSONL record")
        for line in lines:
            obj = json.loads(line)           # must not raise
            for field in export_mod.EXPORT_FIELDS:
                self.assertIn(field, obj, f"Field '{field}' missing from JSONL record")
        # Spot-check that structured fields were extracted (not all empty)
        first = json.loads(lines[0])
        self.assertEqual(first['user'],   'admin')
        self.assertEqual(first['action'], 'read')
        self.assertEqual(first['level'],  'INFO')

    # ------------------------------------------------------------------
    # 3. Time-range filter — fewer lines exported
    # ------------------------------------------------------------------

    def test_time_range_exports_fewer_lines(self):
        """Day-2-only export must produce fewer rows than the full 3-day export."""
        all_csv,  _ = _run_export(self.timed_logz, output_fmt='csv')
        day2_csv, _ = _run_export(
            self.timed_logz, from_ts=DAY2_START, to_ts=DAY2_END, output_fmt='csv',
        )
        all_rows  = list(csv.reader(io.StringIO(all_csv)))
        day2_rows = list(csv.reader(io.StringIO(day2_csv)))
        # Subtract 1 for the header row in each
        all_data  = len(all_rows)  - 1
        day2_data = len(day2_rows) - 1
        self.assertGreater(all_data,  0, "Full export must have data rows")
        self.assertGreater(day2_data, 0, "Day-2 export must have data rows")
        self.assertLess(day2_data, all_data,
                        "Day-2-only export must have fewer rows than the full export")

    # ------------------------------------------------------------------
    # 4. Plaintext — raw populated, structured fields empty
    # ------------------------------------------------------------------

    def test_plaintext_raw_populated_fields_empty(self):
        """Plaintext log export: raw non-empty, all structured fields empty."""
        stdout, _ = _run_export(self.plain_logz, output_fmt='csv')
        reader = csv.reader(io.StringIO(stdout))
        header = next(reader)
        idx = {name: i for i, name in enumerate(header)}
        rows = list(reader)
        self.assertGreater(len(rows), 0, "Should export at least one row")
        for row in rows:
            self.assertTrue(row[idx['raw']],
                            "raw column must be non-empty for every plaintext line")
            for field in ('timestamp', 'level', 'user', 'ip', 'action', 'message'):
                self.assertEqual(
                    row[idx[field]], '',
                    f"Field '{field}' must be empty for plaintext lines",
                )

    # ------------------------------------------------------------------
    # 5. CSV row count — exact match (single-chunk log, no boundary splits)
    # ------------------------------------------------------------------

    def test_csv_row_count_matches_line_count(self):
        """CSV data-row count (minus header) must equal the number of input log lines."""
        stdout, _ = _run_export(self.json_logz, output_fmt='csv')
        rows = list(csv.reader(io.StringIO(stdout)))
        data_rows = rows[1:]   # strip header
        self.assertEqual(
            len(data_rows), self.json_lines,
            f"Expected {self.json_lines} data rows, got {len(data_rows)}",
        )


if __name__ == '__main__':
    unittest.main()
