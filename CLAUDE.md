# Shrinker - Project Context for Claude Code

## What is this?
A single-binary CLI tool that compresses log files into .logz format
and allows instant search without full decompression.

## Three commands:
shrinker compress server.log output.logz
shrinker search output.logz "payment failed"
shrinker decompress output.logz --output restored.log

## Proven benchmark numbers (already validated):
- Compression: 3.46x on synthetic JSON logs (6-10x expected on real logs)
- Seekable chunking overhead: -0.4% vs solid zstd (zero penalty)
- Search latency: 24ms on 1GB with no index (C rewrite target)
- Jump table overhead: 5.5% (target: below 5% — tune in Phase 5)
- Bloom filter skip rate: 23/24 chunks skipped on UUID search (0 false positives)

## .logz File Format (v2):
[MAGIC: 4 bytes: 0x4C4F475A "LOGZ"]
[VERSION: 2 bytes, little-endian] — v1 = no bloom, v2 = bloom in jump table
[FORMAT: 1 byte] — 0=json, 1=syslog, 2=plaintext
[DICT_LEN: 4 bytes, little-endian]
[DICT_DATA: DICT_LEN bytes - shared zstd dictionary trained on first 10MB]
[BLOCK_0..N: 64KB compressed chunks]
[JUMP_TABLE: per-chunk — offset(8) + comp_size(4) + orig_size(4) + bloom(1024)]
[JUMP_TABLE_OFFSET: 8 bytes]
[NUM_CHUNKS: 4 bytes]

## Current phase:
Python prototype. Phase 3 complete (decompress + lossless round-trip verified). Next: tests.

## File structure:
shrinker/
  src/
    compress.py    # format detection, dict training, chunked compress, bloom build
    search.py      # jump table read, bloom pre-filter, surgical decompression
    decompress.py  # reads .logz, verifies magic, decompresses all chunks in order
    bloom.py       # 1024-byte bloom filter: djb2 + fnv1a + sdbm hash functions
    cli.py         # argparse entry point: compress / search / decompress subcommands
  tests/
    test_compress.py   # not yet built
    test_search.py     # not yet built
  data/            # gitignored - put test log files here
  PROJECT_CONTEXT.md

## Key decisions:
- 64KB chunks (SIMD-aligned for future C rewrite)
- Shared zstd dictionary (112KB target) trained on first 10MB of input
- Bloom filter: 1024 bytes (8192 bits), 3 hashes, tokenised by JSON/syslog delimiters
- Tokens split on: spaces, quotes, colons, newlines, commas, braces, brackets
- Jump table at file tail like Parquet footer — seek to EOF-12 to bootstrap reads
- search.py reads version byte and handles v1 (no bloom) and v2 (bloom) files
- Rehydration to original bytes is 100% lossless — verified with diff (bit-exact round-trip)
- decompress.py verifies MAGIC bytes on open, exits with error if file is not .logz

## What we are NOT building:
- Not a database
- Not a server or daemon
- Just a file format + CLI commands