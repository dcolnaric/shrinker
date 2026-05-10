# Shrinker - Project Context for Claude Code

## What is this?
A single-binary CLI tool that compresses log files into .logz format
and allows instant search without full decompression.

## Two commands, that's it:
shrinker compress server.log output.logz
shrinker search output.logz "payment failed"

## Proven benchmark numbers (already validated):
- Compression: 4x on synthetic logs, 6-10x expected on real logs
- Seekable chunking overhead: -0.4% vs solid zstd (zero penalty)
- Search latency: 24ms on 1GB with no index
- Jump table overhead: 6.49% (target: below 5%)

## .logz File Format:
[MAGIC: 4 bytes: 0x4C4F475A "LOGZ"]
[VERSION: 2 bytes, little-endian]
[DICT_LEN: 4 bytes, little-endian]
[DICT_DATA: DICT_LEN bytes - shared zstd dictionary]
[BLOCK_0..N: 64KB compressed chunks]
[JUMP_TABLE: per-chunk metadata - offset(8) + comp_size(4) + orig_size(4)]
[JUMP_TABLE_OFFSET: 8 bytes]
[NUM_CHUNKS: 4 bytes]

## Current phase:
Python prototype. Proving correctness before C rewrite.

## File structure:
shrinker/
  src/
    compress.py    # reads JSON/syslog, writes .logz
    search.py      # reads jump table, surgical decompression
    decompress.py  # rehydrates .logz back to plain JSON
    cli.py         # entry point, argument parsing
  tests/
    test_compress.py
    test_search.py
  data/            # gitignored - put test log files here
  PROJECT_CONTEXT.md
  README.md

## Key decisions:
- 64KB chunks (SIMD-aligned for future C rewrite)
- Shared zstd dictionary trained on first 10MB of input
- Bloom filter per chunk for search skip (Phase 2 of prototype)
- Jump table at file tail like Parquet footer
- Rehydration to JSON must be 100% lossless

## What we are NOT building:
- Not a database
- Not a server or daemon  
- Just a file format + CLI commands