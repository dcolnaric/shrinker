# Shrinker - Project Context for Claude Code

## What is this?
A single-binary CLI tool that compresses audit log files 10x and allows
instant search without decompression. Designed for compliance audit log
archival (SOC 2, PCI-DSS, HIPAA, SOX).

Tagline: "Audit logs that survive a 7-year subpoena. 10x smaller.
Searchable without rehydration. Single binary."

## Commands (Python — all implemented):
shrinker compress   server.log output.logz
shrinker append     server.log archive.logz
shrinker search     output.logz "payment failed"
shrinker search     output.logz "payment failed" --from 2025-01-01 --to 2025-01-31
shrinker search     output.logz --user admin --ip 192.168.1.1 --action delete --level ERROR
shrinker decompress output.logz --output restored.log
shrinker verify     output.logz
shrinker export     output.logz --from 2025-01-01 --to 2025-12-31 --format csv > audit.csv
shrinker export     output.logz --format json > audit.jsonl

## Commands (C binary — c_src/shrinker, all implemented):
./shrinker compress   <input> <output.logz>
./shrinker compress   <input> s3://bucket/key   [--lock DAYS]  # Object Lock Compliance
./shrinker append     <input> <archive.logz>    # creates archive if absent
./shrinker append     <input> s3://bucket/key   [--lock DAYS]
./shrinker search     <file.logz> <query> [--from DATE] [--to DATE]
                      [--user X] [--ip X] [--action X] [--level X]
./shrinker verify     <file.logz>
./shrinker decompress <file.logz> <output.log>
./shrinker export     <file.logz> [--from DATE] [--to DATE] [--format csv|json]
./shrinker verify-lock s3://bucket/key          # check Object Lock status
./shrinker inspect    <file.logz>   # prints header, jump table summary, totals

## Proven benchmark numbers (already validated):
- Synthetic JSON: 1.49MB → 0.41MB, 3.66x
- Real nginx logs: 6.67MB → 0.62MB, 10.72x
- Real HDFS logs: 1504MB → 183MB, 8.21x
- Seekable chunking overhead: -0.4% vs solid zstd (zero penalty)
- Jump table overhead: 5.5% (target: below 5% — tune later)
- Bloom filter skip rate: 98.8% chunks skipped on 1.5GB file (0 false positives)

### C performance on HDFS_v4.logz (183 MB compressed, 24 079 chunks):
- compress:   not re-timed (see Step 12)
- search "blk_-<id>":  47 ms  (98.9% bloom-skipped)
- search "blk_":       84 ms  (scans 329 / 24 079 chunks)
- verify:            5.3 s    (full decompress + SHA-256 every chunk)
- decompress:        8.0 s    (I/O bound — writes 1.5 GB)
- export CSV:       11.3 s    (debug+ASan; 11.2 M lines)

## .logz File Format (v4 — CURRENT):
[MAGIC: 4 bytes: 0x4C4F475A "LOGZ"]
[VERSION: 2 bytes, little-endian] — value 4
[FORMAT: 1 byte] — 0=json, 1=syslog, 2=plaintext
[DICT_LEN: 4 bytes, little-endian]
[DICT_DATA: DICT_LEN bytes - shared zstd dictionary trained on first 10MB]
[CHUNK_0..N: 64KB compressed blocks]

Jump table — JUMP_ENTRY_SIZE = 1600 bytes per entry:
  offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + chunk_hash(32) + min_ts(8) + max_ts(8) + field_bloom(512)

chunk_hash is SHA-256:
  chunk 0:  SHA256(raw_bytes)
  chunk N:  SHA256(prev_chunk_hash || raw_bytes)

min_ts / max_ts: unix epoch seconds (uint64 LE) of first/last timestamped line in chunk.
  Stored as 0/0 when no timestamps are found in the chunk.
  Timestamp extraction supports: JSON keys (timestamp/time/ts/@timestamp),
  ISO 8601 strings, unix epoch ints/floats, syslog "Jan 15 10:23:45" prefix.

field_bloom: 512-byte bloom filter (4096 bits, 3 hashes) indexing values of these JSON fields:
  user, user_id, username, ip, ip_address, action, level, severity
  Stored as 512 zero bytes for non-JSON formats (signals "no field index" to search).
  Checked before the main bloom when --user/--ip/--action/--level flags are given.

Footer — FOOTER_SIZE = 44 bytes, bootstrapped via seek(-44, EOF):
  [CHAIN_HASH: 32 bytes] — SHA256 of final chunk (convenience copy of last hash)
  [JUMP_TABLE_OFFSET: 8 bytes, little-endian]
  [NUM_CHUNKS: 4 bytes, little-endian]

IMPORTANT: v1, v2, and v3 files are rejected with a clear error. Do not add backward compatibility.
IMPORTANT: Hash chain runs over RAW (pre-compression) bytes, not compressed bytes.
IMPORTANT: Decompression failure on a chunk is treated as TAMPERED (exit 1), not error (exit 2).

## Current phase:
Phase 2 — Compliance Features in Python. COMPLETE.
Phase 3 — C core rewrite. Steps 10–21 complete.
Phase 4 — CI / packaging. Steps 22–24 complete.
Phase 5 — S3 + Object Lock. Steps 27–28 complete.

Phase 2 steps (all done):
Steps 1-2 DONE: SHA-256 hash chain in compress.py, verify command in verify.py + cli.py.
  - FOOTER_SIZE and JUMP_ENTRY_SIZE constants exported from each reader module
  - verify exit codes: 0=clean, 1=tampered (incl. decompression failure), 2=error
  - 7 tests in tests/test_verify.py, all passing
Step 3 DONE: time-range search (--from / --to flags, min/max timestamp per chunk in jump table).
  - Format bumped to v3; JUMP_ENTRY_SIZE = 1088 (added min_ts + max_ts, 8 bytes each)
  - Time-range skip happens before bloom filter check (cheaper first)
  - search stats line now includes "Skipped by time: N"
  - 5 tests in tests/test_timerange.py, all passing
Step 4 DONE: field-filter search (--user / --ip / --action / --level flags, JSON field matching).
  - Format bumped to v4; JUMP_ENTRY_SIZE = 1600 (added field_bloom, 512 bytes per chunk)
  - field_bloom indexes values of: user, user_id, username, ip, ip_address, action, level, severity
  - Non-JSON formats store 512 zero bytes → search falls back to full scan automatically
  - Skip order: time → field bloom → main bloom (cheapest first)
  - search stats line now includes "Skipped by field: N"
  - AND logic: chunk skipped if ANY requested field value is definitely absent
  - 6 tests in tests/test_field_search.py, all passing
Step 5 DONE: export command (shrinker export output.logz --from 2025-01-01 --format csv).
  - src/export.py: extracts timestamp/level/user/ip/action/message/raw per line
  - CSV (default) and JSONL output formats
  - Same chunk-level time-range skip as search.py
  - 5 tests in tests/test_export.py, all passing

Phase 3 steps:
Step 10 DONE: C project structure, Makefile, magic/version header check, footer read.
  - c_src/include/shrinker.h: all format constants, JumpEntry + FileFooter structs with _Static_assert
  - c_src/src/main.c: inspect subcommand (reads header + footer + full jump table)
  - c_src/Makefile: debug (ASan) + release targets; -Iinclude; -lzstd -lssl -lcrypto -lm
Step 11 DONE: read full jump table in C, print per-entry summaries, cross-validate chunk-0 hash.
  - fread into packed JumpEntry array in one call (x86-64 LE, safe with _Static_assert)
  - Totals: sum orig_size, global min/max timestamps
  - Cross-validation prints MISMATCH on purpose: stored hash is over raw bytes, not compressed
Step 12 DONE: compress_file() in C (c_src/src/compress.c).
  - Format detection: first 5 lines, JSON = {…}, syslog = month prefix, else plaintext
  - Dict training: ZDICT_trainFromBuffer, 160×64KB samples, 112KB target; graceful fallback if <2 samples
  - Main bloom: 1024 bytes, djb2+fnv1a+sdbm; djb2 = h*33+c (ADD, matches Python bloom.py)
  - Field bloom: 512 bytes, JSON only; zero bytes for syslog/plaintext (sentinel for search bypass)
  - Hash chain: EVP_DigestInit/Update/Final (OpenSSL 3.x); SHA256(raw) for chunk 0, SHA256(prev||raw) for N
  - Timestamps: ISO 8601 via strptime+timegm, numeric epoch via strtod, syslog "Jan DD HH:MM:SS" via sscanf
  - Jump table: dynamic array, initial cap 256, doubles on overflow
  - Footer: chain_hash(32)+jt_offset(8)+num_chunks(4), written last
  - Subcommand: ./shrinker compress <input> <output.logz>; inspect kept for debugging
  - Cross-validated: python verify PASS + decompress + diff IDENTICAL on nginx.log and test.log (JSON)
  - nginx.log (plaintext): 6.99MB → 0.71MB (9.81x), 107 chunks, VERIFIED
  - test.log (JSON): 1.56MB → 0.46MB (3.36x), 24 chunks, VERIFIED, timestamps in jump table
Step 13 DONE: search_file() in C (c_src/src/search.c).
  - Three-layer chunk skip: time range → field bloom → main bloom (cheapest first)
  - main_bloom_query: tokenises query, requires ALL tokens present (AND); fallback = hash whole query
  - field_bloom_query: hashes full value (no tokenisation), matches Python bloom.query_field_present()
  - memmem() for quick full-chunk scan before line-by-line grep
  - Stats to stderr mirror search.py format exactly
  - Subcommand: ./shrinker search <file> <query> [--from/--to/--user/--ip/--action/--level]
  - Cross-validated on HDFS_v4.logz: "blk_" → 153 157 lines — exact match with Python
  - Bug fix: bloom_djb2 was XOR (h*33^c) not ADD (h*33+c) — fixed in compress.c + search.c
Step 14 DONE: verify_file() in C (c_src/src/verify.c).
  - EVP streaming SHA-256 over raw bytes; chain: chunk 0 = SHA256(raw), N = SHA256(prev||raw)
  - Decompression failure → TAMPERED (exit 1), not error (exit 2)
  - Output (TAMPERED / VERIFIED) to stdout; operational errors to stderr
  - Cross-validated: HDFS_v4.logz → VERIFIED chain 846fc55d08efb3e0…; tamper at byte 1 000 000
    → TAMPERED chunk 140 decompression failed (identical to Python output)
  - Timing: 5.3 s for 183 MB compressed file
Step 15 DONE: decompress_file() in C (c_src/src/decompress.c).
  - Sequential decompression using jump table; sanity-check dec_size == orig_size per chunk
  - Stats to stderr match Python (Chunks: N / Output: X MB)
  - Cross-validated: 4/4 round-trips identical (C→C, Py→C, C→Py, HDFS 1504 MB)
  - Timing: 8.0 s for 1504 MB output (I/O bound)
Step 16 DONE: export_file() in C (c_src/src/export.c).
  - Time-range skip (layer 1 from search.c), full chunk decompress, line-by-line extraction
  - json_find_value scanner extracts ts/level/user/ip/action/message fields from JSON logs
  - CSV: Python csv.writer QUOTE_MINIMAL — quote only on ',', '"', '\n', '\r'; double embedded '"'
  - JSON: Python json.dumps(ensure_ascii=True) — \uXXXX for non-ASCII, � for invalid UTF-8,
          surrogate pairs for U+10000+, separators (', ', ': ')
  - Cross-validated: CSV and JSON diffs with Python produce zero output on nginx_c.logz

Step 17 DONE: Complete CLI in main.c.
  - --help for every subcommand; --version global flag
  - compress: --format json|syslog|plaintext override
  - decompress: --output <file> flag (replaces positional arg)
  - search: all 6 filters validated with clear per-flag error messages
  - export: --format csv|json validated; default csv
  - Unknown command / missing required args: exit 2
Step 18 DONE: Memory safety pass — zero valgrind errors.
  - All five commands: 0 errors, all heap freed (Valgrind 3.22, no ASan)
  - Added `make valgrind` target (no ASan — valgrind and ASan conflict)
Step 19 DONE: Benchmark C (release, -O3) vs Python on 1.5 GB HDFS dataset.
  - compress: 23.1s vs 17m 14.7s → 44.8× faster
  - search narrow: 0.099s vs 0.570s → 5.8× faster
  - search broad: 0.105s vs 0.543s → 5.2× faster
  - export CSV: 4.7s vs 47.9s → 10.2× faster
  - verify/decompress: ~equal (both delegate to same libzstd + OpenSSL)
  - Fixed export.c: zero-initialise version to silence -Wmaybe-uninitialized
Step 20 DONE: Cross-validation matrix + time-range search on JSON logs.
  - Generated data/sample.json: 1000 JSON audit records spanning 2025-01-01..31,
    sorted by timestamp → 4 chunks with non-overlapping time windows.
    Fields: timestamp (ISO 8601), user_id, ip_address, action, level.
  - Cross-validation: all 6 combinations (Py compress + C search/verify/decompress
    and C compress + Py search/verify/decompress) pass — diffs empty, chain hashes
    identical (4bd6bdddafc654b9…), hit counts match.
  - Time-range: Jan 1-10 → 1/4 chunks (3 time-skipped), Jan 22-31 → 2/4 chunks
    (2 time-skipped). C and Python results identical.
  - Field-only search (no text query) implemented:
    * cli.py: query nargs='?', default ''
    * search.py: guard bloom check when query_bytes is empty
    * main.c: query optional — argv[3] treated as query unless it starts with --
    * search.c: fix two empty-query bugs (bloom skip + memmem fast-path skip)
  - Edge cases: absent query → 0 results exit 0 (bloom skips all 4 chunks);
    future date --from 2030-01-01 → 0 results exit 0 (time skips all 4 chunks).
  - All 7 Python test suites still pass after changes.

Step 21 DONE: Append mode — extends hash chain across archive boundary.
  - New subcommand: shrinker append <input> <archive.logz>
  - If archive absent: delegates to compress_file() / _compress() — creates fresh archive
  - If archive exists:
    * Reads header (magic, version, format byte, dict) — reuses format + dict for new chunks
    * Reads footer: chain_hash (seed), jt_offset, num_old_chunks
    * Loads old jump table into memory (entries' offset fields remain valid after truncation)
    * ftruncate() at jt_offset — strips old jump table + footer in-place
    * Writes new compressed chunks starting at jt_offset using existing dict
    * Hash chain: first new chunk = SHA256(seed_hash || raw); subsequent = SHA256(prev || raw)
    * Writes combined jump table: old entries (unchanged) + new entries
    * Writes new footer: updated chain_hash, new jt_offset, total chunk count
  - C: c_src/src/append.c — append_file(); static helpers prefixed ap_ (no header conflict)
  - Python: src/append.py — imports helpers from compress.py; same protocol
  - Cross-validated: C archive verified by Python; Python archive verified by C
    Both produce chain 8f4ae2e9adb222f3… for nginx.log doubled (214 chunks)
  - search results = exactly 2× single-file results (51 376 → 102 752 "GET" hits)
  - decompress + diff against cat nginx.log nginx.log → DIFF EMPTY (byte-exact)
  - create-if-not-exists chain hash matches plain compress (67a67e202471cfa5…)
  - All 7 Python test suites still pass after changes.

Phase 4 steps:
Step 22 DONE: GitHub Actions CI — static Linux binaries.
  - .github/workflows/ci.yml: three jobs triggered on push/PR to main
      build-x86_64: ubuntu-latest, Alpine 3.19 container, EXTRA_CFLAGS="-static"
        → produces shrinker-linux-x86_64 artifact (musl static, no shared-lib deps)
      build-arm64:  ubuntu-latest + QEMU, Alpine 3.19 arm64 container, same flags
        → produces shrinker-linux-arm64 artifact (genuine ARM64 musl static)
      test:         downloads both artifacts; runs 7-suite Python test suite +
                    C binary smoke tests (compress → verify → search on data/nginx.log)
  - Makefile: added EXTRA_CFLAGS = (empty default, overridable from CLI);
    $(EXTRA_CFLAGS) appended to CFLAGS_RELEASE; -lpthread -ldl added to LIBS
  - data/nginx.log: 1000-line CI fixture committed (was fully gitignored before);
    .gitignore changed from data/ to data/* + !data/nginx.log
  - c_src/shrinker binary removed from git tracking (added to .gitignore)
  - Alpine static lib fix: zstd-dev alone does not ship libzstd.a; must also install
    zstd-static and openssl-libs-static (Alpine splits static archives into
    separate *-static packages, unlike Debian/Ubuntu)
  - PAT must have 'workflow' scope to push .github/workflows/ files
  - Bug fix: build-x86_64 smoke tests moved inside Docker container (docker run step)
    so chmod is never needed — binary built as root inside Alpine is already executable
    there; host runner cannot chmod files owned by container root
  - Bug fix: test_decompress.py was reading data/test.log (gitignored, absent in CI);
    changed TEST_LOG to data/nginx.log — the committed CI fixture works identically
    for a byte-exact round-trip test

Step 23 DONE: GitHub Releases workflow on version tags.
  - .github/workflows/release.yml: triggers on push of v* tags
  - build-x86_64 + build-arm64: same Alpine Docker approach as ci.yml;
    binary renamed to shrinker-linux-x86_64 / shrinker-linux-arm64 before
    artifact upload so download in release job gives correctly-named files
  - release job: downloads both artifacts, chmod +x (safe — runner user owns
    downloaded files), generates shrinker-checksums.txt via sha256sum,
    publishes release via softprops/action-gh-release@v2
  - Release name: "Shrinker ${{ github.ref_name }}"
  - generate_release_notes: true → auto-populated body from commits since last tag
  - make_latest: true → marks release as current latest
  - permissions: contents: write (release job only)
  - Three assets per release: shrinker-linux-x86_64, shrinker-linux-arm64,
    shrinker-checksums.txt
  - First release: v0.1.0

Step 24 DONE: install.sh one-liner installer.
  - install.sh in repo root; POSIX sh, no bashisms
  - Platform detection: Linux only; x86_64 and aarch64/arm64; clear error on unsupported
  - Downloader detection: curl preferred, wget fallback; neither → error
  - GitHub API: fetches releases/latest JSON, parses tag_name + browser_download_url
    with grep+sed (no jq dependency); matches asset URLs by "/<name>" suffix to avoid
    partial matches
  - Downloads shrinker-linux-{arch} and shrinker-checksums.txt from same release
  - SHA-256 verification: grep expected hash from checksums file, compare with
    sha256sum output; checksum mismatch → print both hashes + exit 1
  - Install path: /usr/local/bin (if writable) else ~/.local/bin (mkdir -p)
  - PATH hint printed if install dir not currently in PATH
  - Cleanup: mktemp -d workspace removed by trap on EXIT/INT/TERM
  - Tested on WSL2 Ubuntu: fetched v0.1.0, checksum OK, installed to ~/.local/bin,
    --version confirmed
  - One-liner: curl -fsSL https://raw.githubusercontent.com/dcolnaric/shrinker/main/install.sh | sh

Phase 5 steps:
Step 27 DONE: S3 direct read/write with AWS SigV4 auth.
  - All subcommands accept s3://bucket/key paths for file/archive arguments
  - compress, append: write to temp file then PUT to S3
  - search, verify, decompress, export: GET from S3 to temp file then operate
  - append with S3: HEAD to check existence; if present GET first, then PUT back
  - c_src/include/s3.h: S3Url and S3Creds structs; s3_is_url / s3_parse_url /
    s3_load_creds / s3_download / s3_upload / s3_exists declarations
  - c_src/src/s3.c: complete implementation
      * Credential chain: env vars → ~/.aws/credentials → EC2 IMDS (IMDSv1, 2 s timeout)
      * Region: AWS_DEFAULT_REGION → AWS_REGION → ~/.aws/config → "us-east-1"
      * --region flag on all subcommands overrides credential-chain region
      * AWS Signature Version 4, virtual-hosted style endpoints:
          us-east-1 → {bucket}.s3.amazonaws.com
          other     → {bucket}.s3.{region}.amazonaws.com
      * Signed headers (alphabetical): host; x-amz-content-sha256; x-amz-date
        [; x-amz-security-token if session token present]
      * SigV4 canonical request: empty canonical query string; canonical headers
        block already ends with \n, then extra \n adds required blank separator
      * s3_download: libcurl GET, write response body to file
      * s3_upload: SHA-256 file before PUT (required by SigV4); PUT with
        Content-Type: application/octet-stream
      * s3_exists: HEAD with CURLOPT_NOBODY
      * Lazy curl_global_init (called once via static flag)
      * URL encoding: unreserved chars + '/' pass through; all others → %XX (UC hex)
  - Makefile: added src/s3.c to SRCS; LIBS now includes -lcurl -lz
    (curl → ssl/crypto/z link order)
  - ci.yml + release.yml: added curl-dev curl-static zlib-dev zlib-static
    to Alpine apk packages in all three build containers
  - main.c: s3_to_tmp / tmp_to_s3 helpers; --region flag on all subcommands;
    verify now parses options loop (--region) instead of hard argc > 3 check
  - URL parsing verified: 8/8 unit tests pass (bucket/key extraction, leading-slash
    stripping, error cases)
  - SigV4 canonical request format verified: blank separator, host header,
    regional endpoint, session token, key encoding — 11/11 assertions pass
  - Local debug/valgrind builds require: sudo apt-get install libcurl4-openssl-dev
  - Static release builds use Alpine containers (curl-dev + curl-static)

Step 28 DONE: S3 Object Lock Compliance Mode — --lock flag + verify-lock subcommand.
  - New flag: --lock DAYS on compress and append
      * Only valid with an S3 output/archive path; error printed if used with local path
      * DAYS must be > 0; error printed otherwise
      * 2555 = 7 years (SOX), 365 = 1 year (SOC 2), 2190 = 6 years (HIPAA)
  - Object Lock implementation in s3.c / s3.h:
      * compute_lock_until(days): time(NULL) + days×86400 formatted as %Y-%m-%dT%H:%M:%SZ
      * s3_upload() gains int lock_days parameter
      * When lock_days > 0: lock_mode = "COMPLIANCE", retain-until computed
      * Two extra signed headers added to SigV4 canonical request (in alphabetical order):
          x-amz-object-lock-mode: COMPLIANCE
          x-amz-object-lock-retain-until-date: <ISO 8601 UTC>
        Alphabetical position: after x-amz-date, before x-amz-security-token
      * sigv4_build_auth(): 4 combinations (lock × session-token) for signed_hdrs string
      * Response body captured on PUT to detect Object Lock config errors; specific
        message printed when bucket was not created with Object Lock enabled
  - New subcommand: shrinker verify-lock s3://bucket/key [--region R]
      * HEAD request via s3_check_lock() (new s3.h / s3.c function)
      * Response headers captured with CURLOPT_HEADERFUNCTION + membuf_write
      * resp_header_val() helper: case-insensitive line-by-line header scanner
      * Extracts x-amz-object-lock-mode and x-amz-object-lock-retain-until-date
      * Prints "LOCKED — COMPLIANCE mode, retain until YYYY-MM-DD"
           or "NOT LOCKED — no Object Lock on this object"
      * Returns 0 on success, 1 on error, 2 on usage error
  - main.c:
      * tmp_to_s3() gains int lock_days parameter; passes to s3_upload()
      * compress handler: parses --lock N, validates N > 0 and S3 output required
      * append handler: same validation; direct s3_upload() call also updated
      * help_compress() + help_append(): --lock DAYS documented with examples
      * help_root(): verify-lock listed in commands section
      * help_verify_lock(): full help text
      * verify-lock subcommand handler: validates S3 URL, calls s3_check_lock(),
        formats retain-until date (ISO 8601 → YYYY-MM-DD for readability)
      * VERSION_STRING bumped to 0.2.1
  - Validation without real AWS: syntax-only with stub curl.h; full link in Alpine CI
  - Design: lock_days lives in S3 transport layer only (s3_upload / tmp_to_s3);
    compress_file() and append_file() remain pure local-file operations — clean separation

Next: Possible next steps:
  - Step 29: C test suite (replace run_tests.py with a C test runner)
  - Step 30: Real S3 round-trip integration test in CI (LocalStack)

## Strategic pivot (confirmed — do not second-guess):
ORIGINAL: DevOps cold storage cost savings tool
CURRENT:  Compliance audit log archival for mid-market SaaS doing SOC 2

Why: Cost savings is "nice to have". Regulatory retention is not optional.
- PCI-DSS 4.0: 12 months history, 3 months immediately searchable
- SOX: 7 years for financial audit logs
- HIPAA: 6 years for PHI-related audit logs
- SOC 2: minimum 1 year expected by auditors

Market gap: Nothing is a single binary that writes tamper-proof
10x-compressed archives to S3 with Object Lock and lets you grep
them with field filters without rehydration.

## File structure:
shrinker/
  src/
    compress.py    # format detection, dict training, chunked compress, bloom + hash chain
    search.py      # jump table read, bloom pre-filter, surgical decompression
    decompress.py  # reads .logz v4, verifies magic+version, decompresses all chunks
    verify.py      # reads jump table, recomputes hash chain, reports VERIFIED or TAMPERED
    export.py      # export to CSV/JSONL with time-range filter
    append.py      # append new chunks to existing archive, extending hash chain
    bloom.py       # 1024-byte bloom filter: djb2 + fnv1a + sdbm hash functions
    cli.py         # argparse: compress / append / search / decompress / verify / export subcommands
  tests/
    test_compress.py    # magic, ratio, chunk count, bloom data presence
    test_search.py      # exact match, absent term, bloom skip count
    test_decompress.py  # byte-exact round-trip via diff + size check
    test_verify.py      # clean=0, VERIFIED output, tamper chunk0, tamper chunk1,
                        # exit code 1, zeroed hash caught, footer==last hash
    test_timerange.py   # timestamps in jump table, day-range skip, before/after/no-filter
    test_field_search.py # field bloom in jump table, --user/--ip/--action filters, AND logic, plaintext fallback
    test_export.py      # CSV headers, JSONL format, time-range fewer rows, plaintext raw-only, exact row count
    run_tests.py        # runs all suites, prints PASS/FAIL, exits 1 on failure
  c_src/
    include/
      shrinker.h   # all format constants (MAGIC, VERSION, CHUNK_SIZE, bloom sizes, etc.),
                   # JumpEntry + FileFooter structs with _Static_assert size checks, public API
      s3.h         # S3Url + S3Creds structs; s3_is_url / s3_parse_url / s3_load_creds /
                   # s3_download / s3_upload(+lock_days) / s3_exists / s3_check_lock declarations
    src/
      main.c       # CLI dispatcher: compress/append/search/verify/decompress/export/verify-lock;
                   # S3 routing (s3_to_tmp / tmp_to_s3 helpers); --region on all commands;
                   # --lock DAYS on compress/append; verify-lock subcommand
      compress.c   # compress_file(): full C compression pipeline, byte-compatible with Python
      append.c     # append_file(): extend existing archive in-place, continues hash chain
      search.c     # search_file(): three-layer skip + surgical decompress + grep
      verify.c     # verify_file(): SHA-256 hash chain recomputation, TAMPERED/VERIFIED output
      decompress.c # decompress_file(): sequential full decompression, byte-exact round-trip
      export.c     # export_file(): CSV/JSONL export with Python-compatible escaping
      s3.c         # AWS SigV4 + libcurl: credential chain, GET/PUT/HEAD; Object Lock COMPLIANCE
    Makefile       # debug/valgrind/release targets; LIBS includes -lcurl -lz;
                   # EXTRA_CFLAGS overridable for static builds
  .github/
    workflows/
      ci.yml       # builds x86-64 + ARM64 static binaries; runs Python test suite
      release.yml  # triggered on v* tags; publishes GitHub Release with binaries + checksums
  install.sh       # POSIX sh one-liner installer; detects arch, downloads latest release, verifies checksum
  README.md        # benchmarks, usage, file format, project status
  CLAUDE.md        # this file
  data/
    nginx.log      # 1000-line CI fixture (committed); larger test files gitignored

## Key design decisions:
- 64KB chunks (SIMD-aligned for future AVX-512 paths)
- Shared zstd dictionary (112KB target) trained on first 10MB of input
- Bloom filter: 1024 bytes (8192 bits), 3 hashes, tokenised by JSON/syslog delimiters
- Tokens split on: spaces, quotes, colons, newlines, commas, braces, brackets
  NOTE: '=' is NOT a delimiter, so "user=admin" is one token (matters for plaintext bloom queries)
- Jump table at file tail like Parquet footer — seek to EOF-44 to bootstrap reads
- Hash chain over raw bytes (not compressed) — certifies content not encoding
- Version byte lets old readers fail cleanly rather than silently misread data
- Rehydration is 100% lossless — verified with diff (bit-exact round-trip)
- verify exit codes: 0=clean, 1=tampered, 2=usage error
- C and Python implementations are byte-compatible: all six commands cross-validate
- Static builds use Alpine Linux containers (not musl-gcc on Ubuntu): Ubuntu's libcrypto.a
  references __ctype_b_loc / __ctype_tolower_loc (glibc-specific), causing linker errors
  when mixed with musl. Alpine compiles everything (zstd, openssl) for musl natively.
- Alpine static lib split: zstd-dev + zstd-static; openssl-dev + openssl-libs-static
  (-dev provides headers + .so; *-static provides the .a needed for -static linking)
- EXTRA_CFLAGS is appended to CFLAGS_RELEASE only (not debug/valgrind — ASan + -static conflict)
- Append reuses the archive's existing dict + format byte — all chunks in one archive
  always share the same dict; training a new dict on append would corrupt decompression
- Append truncates at jt_offset (not at EOF) — old chunk data is never touched, so
  old jump table offset fields remain valid after truncation
- bloom_djb2 uses ADD variant: h = h*33 + c  (NOT XOR h*33^c)
  This matches Python bloom.py _djb2; using XOR would silently mis-query Python-compressed files
- C uses EVP streaming API (OpenSSL 3.x) for incremental SHA-256; one-shot SHA256() is deprecated
- C uses timegm() (_GNU_SOURCE) for UTC epoch from struct tm; matches Python calendar.timegm()
- Field bloom zero bytes = sentinel "no field index" — search bypasses field filter for non-JSON chunks
- CSV export: QUOTE_MINIMAL — only quote fields containing ',', '"', '\n', '\r'; double embedded '"'
- JSON export: ensure_ascii=True — non-ASCII UTF-8 → \uXXXX; invalid UTF-8 → �
- The orig_size check in inspect is hardcoded for HDFS_v4.logz; it will FAIL on any other file by design
- S3 transport is a pure download-to-tmpfile / upload-from-tmpfile wrapper; all core logic
  operates on local files — no S3-specific code in compress/search/verify/decompress/export
- SigV4 virtual-hosted style: us-east-1 uses legacy endpoint (no region prefix) for max compat
- Signed headers always include x-amz-content-sha256 (required by S3); session token added
  as x-amz-security-token when present (alphabetically after x-amz-date in signed list)
- url_encode_key preserves '/' as segment separator; all other non-unreserved bytes → %XX
- EC2 IMDS timeout: 1 s connect / 2 s total — fails fast on non-EC2 machines
- Local debug builds need: sudo apt-get install libcurl4-openssl-dev
- Alpine static link order: -lcurl -lzstd -lssl -lcrypto -lz -lm -lpthread -ldl
  (curl-static + zlib-static packages required in addition to existing openssl-libs-static)
- Object Lock headers are part of SigV4 signed-headers (alphabetical order):
  host < x-amz-content-sha256 < x-amz-date < x-amz-object-lock-mode
  < x-amz-object-lock-retain-until-date < x-amz-security-token
  Unsigned Object Lock headers would let the lock date be tampered in transit
- lock_days lives in S3 transport layer only; compress_file/append_file are pure local ops
- verify-lock is read-only (HEAD request); it never downloads the archive
- resp_header_val() case-insensitive scan handles header name variations across regions

## What we are NOT building:
- Not a database
- Not a server or daemon
- Not FedRAMP (out of reach for solo developer)
- Just a file format + CLI commands that complement S3 Object Lock
