# Shrinker - Project Context for Claude Code

## What is this?
A single-binary CLI tool that compresses audit log files 10x and allows
instant search without decompression. Designed for compliance audit log
archival (SOC 2, PCI-DSS, HIPAA, SOX).

Tagline: "Audit logs that survive a 7-year subpoena. 10x smaller.
Searchable without rehydration. Single binary."

## Commands (current):
shrinker compress  server.log output.logz
shrinker search    output.logz "payment failed"
shrinker decompress output.logz --output restored.log
shrinker verify    output.logz        # Phase 2 — tamper detection

## Commands (planned Phase 2):
shrinker search output.logz "admin" --from 2025-01-01 --to 2025-01-31
shrinker search output.logz --user admin --ip 192.168.1.1
shrinker export output.logz --from 2025-01-01 --format csv > audit.csv

## Proven benchmark numbers (already validated):
- Synthetic JSON: 1.49MB → 0.41MB, 3.66x
- Real nginx logs: 6.67MB → 0.62MB, 10.72x
- Real HDFS logs: 1504MB → 183MB, 8.21x
- Seekable chunking overhead: -0.4% vs solid zstd (zero penalty)
- Jump table overhead: 5.5% (target: below 5% — tune later)
- Bloom filter skip rate: 98.8% chunks skipped on 1.5GB file (0 false positives)

## .logz File Format (v2 — CURRENT):
[MAGIC: 4 bytes: 0x4C4F475A "LOGZ"]
[VERSION: 2 bytes, little-endian] — value 2
[FORMAT: 1 byte] — 0=json, 1=syslog, 2=plaintext
[DICT_LEN: 4 bytes, little-endian]
[DICT_DATA: DICT_LEN bytes - shared zstd dictionary trained on first 10MB]
[CHUNK_0..N: 64KB compressed blocks]

Jump table — JUMP_ENTRY_SIZE = 1072 bytes per entry:
  offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + chunk_hash(32)

chunk_hash is SHA-256:
  chunk 0:  SHA256(raw_bytes)
  chunk N:  SHA256(prev_chunk_hash || raw_bytes)

Footer — FOOTER_SIZE = 44 bytes, bootstrapped via seek(-44, EOF):
  [CHAIN_HASH: 32 bytes] — SHA256 of final chunk (convenience copy of last hash)
  [JUMP_TABLE_OFFSET: 8 bytes, little-endian]
  [NUM_CHUNKS: 4 bytes, little-endian]

IMPORTANT: v1 files are rejected with a clear error. Do not add v1 compatibility.
IMPORTANT: Hash chain runs over RAW (pre-compression) bytes, not compressed bytes.
IMPORTANT: Decompression failure on a chunk is treated as TAMPERED (exit 1), not error (exit 2).

## Current phase:
Phase 2 — Compliance Features in Python.
Steps 1-2 DONE: SHA-256 hash chain in compress.py, verify command in verify.py + cli.py.
  - FOOTER_SIZE and JUMP_ENTRY_SIZE constants exported from each reader module
  - verify exit codes: 0=clean, 1=tampered (incl. decompression failure), 2=error
  - 7 tests in tests/test_verify.py, all passing
Next: Step 3 — time-range search (--from / --to flags, min/max timestamp in jump table).

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
    decompress.py  # reads .logz v2, verifies magic+version, decompresses all chunks
    verify.py      # reads jump table, recomputes hash chain, reports VERIFIED or TAMPERED
    bloom.py       # 1024-byte bloom filter: djb2 + fnv1a + sdbm hash functions
    cli.py         # argparse: compress / search / decompress / verify subcommands
  tests/
    test_compress.py   # magic, ratio, chunk count, bloom data presence
    test_search.py     # exact match, absent term, bloom skip count
    test_decompress.py # byte-exact round-trip via diff + size check
    test_verify.py     # clean=0, VERIFIED output, tamper chunk0, tamper chunk1,
                       # exit code 1, zeroed hash caught, footer==last hash
    run_tests.py       # runs all suites, prints PASS/FAIL, exits 1 on failure
  README.md        # benchmarks, usage, file format, project status
  CLAUDE.md        # this file
  data/            # gitignored - put test log files here

## Key design decisions:
- 64KB chunks (SIMD-aligned for future C rewrite)
- Shared zstd dictionary (112KB target) trained on first 10MB of input
- Bloom filter: 1024 bytes (8192 bits), 3 hashes, tokenised by JSON/syslog delimiters
- Tokens split on: spaces, quotes, colons, newlines, commas, braces, brackets
- Jump table at file tail like Parquet footer — seek to EOF-44 to bootstrap reads
- Hash chain over raw bytes (not compressed) — certifies content not encoding
- Version byte lets old readers fail cleanly rather than silently misread data
- Rehydration is 100% lossless — verified with diff (bit-exact round-trip)
- verify exit codes: 0=clean, 1=tampered, 2=usage error

## What we are NOT building:
- Not a database
- Not a server or daemon
- Not FedRAMP (out of reach for solo developer)
- Just a file format + CLI commands that complement S3 Object Lock
