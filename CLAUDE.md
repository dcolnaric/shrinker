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
./shrinker append     <input> <archive.logz>   # creates archive if absent
./shrinker search     <file.logz> <query> [--from DATE] [--to DATE]
                      [--user X] [--ip X] [--action X] [--level X]
./shrinker verify     <file.logz>
./shrinker decompress <file.logz> <output.log>
./shrinker export     <file.logz> [--from DATE] [--to DATE] [--format csv|json]
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
Phase 4 — CI / packaging. Step 22 complete.

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

Next: Possible next steps:
  - Step 23: C test suite (replace run_tests.py with a C test runner)
  - Step 24: single-file release tarball / GitHub Releases upload from CI
  - Step 25: S3 upload + Object Lock integration (aws-sdk-c or CLI wrapper)

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
    src/
      main.c       # CLI dispatcher: compress/append/search/verify/decompress/export/inspect subcommands
      compress.c   # compress_file(): full C compression pipeline, byte-compatible with Python
      append.c     # append_file(): extend existing archive in-place, continues hash chain
      search.c     # search_file(): three-layer skip + surgical decompress + grep
      verify.c     # verify_file(): SHA-256 hash chain recomputation, TAMPERED/VERIFIED output
      decompress.c # decompress_file(): sequential full decompression, byte-exact round-trip
      export.c     # export_file(): CSV/JSONL export with Python-compatible escaping
    Makefile       # debug/valgrind/release targets; EXTRA_CFLAGS overridable for static builds
  .github/
    workflows/
      ci.yml       # builds x86-64 + ARM64 static binaries; runs Python test suite
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

## What we are NOT building:
- Not a database
- Not a server or daemon
- Not FedRAMP (out of reach for solo developer)
- Just a file format + CLI commands that complement S3 Object Lock
