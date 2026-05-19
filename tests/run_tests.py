import os
import subprocess
import sys

TESTS = [
    ('test_compress.py', 'Compress'),
    ('test_search.py', 'Search'),
    ('test_decompress.py', 'Decompress'),
    ('test_verify.py', 'Verify'),
]

passed = 0
failed = 0
tests_dir = os.path.dirname(os.path.abspath(__file__))

for filename, label in TESTS:
    path = os.path.join(tests_dir, filename)
    result = subprocess.run(
        [sys.executable, '-m', 'unittest', '-v', path],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        print(f"PASS  {label}")
        passed += 1
    else:
        print(f"FAIL  {label}")
        output = (result.stdout + result.stderr).strip()
        if output:
            for line in output.splitlines():
                print(f"      {line}")
    failed += result.returncode != 0

print(f"\n{passed} passed, {failed} failed")
sys.exit(1 if failed else 0)
