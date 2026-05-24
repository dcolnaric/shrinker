"""Tests for per-chunk field bloom filter and --user/--ip/--action/--level search."""

import io
import json
import os
import re
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import bloom
import compress
import search

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_field_log(tmpdir):
    """Compress a JSON log with two clearly separated user/action groups.

    Group A — user=admin, ip=192.168.1.1, action=login  → marker ADMIN_LOGIN
    Group B — user=alice, ip=10.0.0.1,   action=logout  → marker ALICE_LOGOUT

    400 lines × ~640 bytes ≈ 256 KB ≈ 4 chunks per group, so each group
    produces several chunks that are entirely free of the other group's field
    values — those chunks will be skipped by the field bloom filter.
    """
    input_path = os.path.join(tmpdir, 'fields.log')
    logz_path  = os.path.join(tmpdir, 'fields.logz')

    with open(input_path, 'w') as f:
        for group in [
            {'user': 'admin', 'ip': '192.168.1.1', 'action': 'login',  'marker': 'ADMIN_LOGIN'},
            {'user': 'alice', 'ip': '10.0.0.1',   'action': 'logout', 'marker': 'ALICE_LOGOUT'},
        ]:
            for i in range(400):
                line = json.dumps({**group, 'seq': i, 'payload': 'X' * 500})
                f.write(line + '\n')

    compress._compress(input_path, logz_path)
    return logz_path


def _make_plaintext_log(tmpdir):
    """Compress a plaintext log (non-JSON).  Field bloom should be all zeros."""
    input_path = os.path.join(tmpdir, 'plain.log')
    logz_path  = os.path.join(tmpdir, 'plain.logz')

    with open(input_path, 'w') as f:
        for i in range(400):
            f.write(f"user=admin action=login ip=192.168.1.1 seq={i} payload={'X' * 400}\n")

    compress._compress(input_path, logz_path)
    return logz_path


def _run_search(logz_path, query, field_filters=None):
    """Run search._search, return (matches, skipped_bloom, skipped_field)."""
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    with redirect_stdout(stdout_buf), redirect_stderr(stderr_buf):
        search._search(logz_path, query, field_filters=field_filters)
    matches = [l for l in stdout_buf.getvalue().splitlines() if l]
    stderr_text = stderr_buf.getvalue()
    m = re.search(r'Skipped by bloom: (\d+)', stderr_text)
    skipped_bloom = int(m.group(1)) if m else 0
    m = re.search(r'Skipped by field: (\d+)', stderr_text)
    skipped_field = int(m.group(1)) if m else 0
    return matches, skipped_bloom, skipped_field


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFieldSearch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir   = tempfile.mkdtemp()
        cls.logz     = _make_field_log(cls.tmpdir)
        cls.plain    = _make_plaintext_log(cls.tmpdir)

    # ------------------------------------------------------------------
    # 1. Structural: field bloom bytes must be non-zero in the jump table
    # ------------------------------------------------------------------

    def test_field_bloom_stored_in_jump_table(self):
        """JSON log must have at least one chunk with a non-zero field bloom."""
        with open(self.logz, 'rb') as f:
            f.seek(-compress.FOOTER_SIZE, 2)
            f.read(32)  # chain_hash
            jt_offset, num_chunks = struct.unpack('<QI', f.read(12))
            f.seek(jt_offset)
            has_field_bloom = False
            for _ in range(num_chunks):
                f.read(16)                # offset, comp_size, orig_size
                f.read(bloom.BLOOM_BYTES) # main bloom
                f.read(32)                # hash
                f.read(16)                # min_ts, max_ts
                fb = f.read(bloom.FIELD_BLOOM_BYTES)
                if any(fb):
                    has_field_bloom = True
                    break
        self.assertTrue(has_field_bloom,
                        "At least one chunk must have a non-zero field bloom")

    # ------------------------------------------------------------------
    # 2. --user filter
    # ------------------------------------------------------------------

    def test_user_filter_skips_non_user_chunks(self):
        """--user admin must skip alice-only chunks and return only admin lines."""
        matches, _, skipped_field = _run_search(
            self.logz, 'ADMIN_LOGIN', field_filters=[b'admin'],
        )
        self.assertGreater(len(matches), 0, "Should find admin lines")
        self.assertGreater(skipped_field, 0, "Alice-only chunks must be field-skipped")
        for line in matches:
            self.assertIn('ADMIN_LOGIN', line)

    # ------------------------------------------------------------------
    # 3. --ip filter
    # ------------------------------------------------------------------

    def test_ip_filter_finds_correct_lines(self):
        """--ip 10.0.0.1 must skip admin chunks and return alice lines."""
        matches, _, skipped_field = _run_search(
            self.logz, 'ALICE_LOGOUT', field_filters=[b'10.0.0.1'],
        )
        self.assertGreater(len(matches), 0, "Should find alice IP lines")
        self.assertGreater(skipped_field, 0, "Admin-only chunks must be field-skipped")
        for line in matches:
            self.assertIn('ALICE_LOGOUT', line)

    # ------------------------------------------------------------------
    # 4. --action filter
    # ------------------------------------------------------------------

    def test_action_filter_finds_correct_lines(self):
        """--action login must skip logout-only chunks and return login lines."""
        matches, _, skipped_field = _run_search(
            self.logz, 'ADMIN_LOGIN', field_filters=[b'login'],
        )
        self.assertGreater(len(matches), 0, "Should find login lines")
        self.assertGreater(skipped_field, 0, "Logout-only chunks must be field-skipped")
        for line in matches:
            self.assertIn('ADMIN_LOGIN', line)

    # ------------------------------------------------------------------
    # 5. Combined --user + --action (AND logic)
    # ------------------------------------------------------------------

    def test_combined_user_and_action_and_logic(self):
        """--user admin --action login (AND) must skip chunks missing either value."""
        matches, _, skipped_field = _run_search(
            self.logz, 'ADMIN_LOGIN', field_filters=[b'admin', b'login'],
        )
        self.assertGreater(len(matches), 0, "Should find admin+login lines")
        # Alice+logout chunks lack 'admin' → must be field-skipped
        self.assertGreater(skipped_field, 0,
                           "Alice/logout-only chunks must be field-skipped")
        for line in matches:
            self.assertIn('ADMIN_LOGIN', line)

    # ------------------------------------------------------------------
    # 6. Plaintext log: zero field bloom → falls back to full scan
    # ------------------------------------------------------------------

    def test_plaintext_falls_back_to_full_scan(self):
        """Plaintext logs have all-zero field bloom; field filters must not skip any chunk."""
        # Use 'user=admin' — that is the exact bloom token in key=value plaintext lines.
        # Searching for bare 'admin' would be bloom-skipped because the tokeniser
        # splits on spaces, not '=', so the stored token is 'user=admin' not 'admin'.
        matches, _, skipped_field = _run_search(
            self.plain, 'user=admin', field_filters=[b'admin'],
        )
        self.assertEqual(skipped_field, 0,
                         "No chunks should be field-skipped for plaintext logs")
        self.assertGreater(len(matches), 0, "Should still find matching lines")


if __name__ == '__main__':
    unittest.main()
