# Shrinker

Compress log files and search them without decompressing.

## The problem

Log storage is expensive. A single busy service can generate gigabytes of logs per day, most of which sit in S3 or Datadog cold storage and are rarely read. When you do need to search them, you either pay to decompress the entire archive or pay for indexed search. Shrinker is a third option: a compressed file format that lets you grep a specific string in milliseconds by skipping irrelevant chunks before they are ever decompressed.

## How it works in two commands

```sh
# Compress 6.67 MB of nginx logs to 0.62 MB
shrinker compress access.log access.logz

# Search the compressed file — no decompression step needed
shrinker search access.logz "payment failed"
```

## Benchmarks

Measured on real log files. Compression uses zstd level 3 with a shared dictionary trained on the first 10 MB of input.

| Dataset            | Input    | Output   | Ratio  |
|--------------------|----------|----------|--------|
| Synthetic JSON     | 1.49 MB  | 0.41 MB  | 3.66x  |
| Real nginx logs    | 6.67 MB  | 0.62 MB  | 10.72x |
| Real HDFS logs     | 1504 MB  | 183 MB   | 8.21x  |

Search on a 1.5 GB file: **98.8% of chunks skipped** by bloom filter — only the chunks that can possibly contain the query are decompressed.

## How it works

Log files are split into 64 KB chunks, each compressed independently with zstd using a shared dictionary. A 1024-byte bloom filter is built for each chunk by tokenising the raw bytes on JSON/syslog delimiters and hashing every token. At the end of the file, a jump table records the byte offset, compressed size, and bloom filter for every chunk — the same footer-first layout used by Parquet.

When you search, Shrinker reads the jump table from the end of the file (12 bytes), checks each chunk's bloom filter against your query, and decompresses only the chunks that could contain a match. Chunks that the bloom filter rules out are never read from disk. Decompression is 100% lossless — `shrinker decompress` produces a byte-exact copy of the original file.

## Installation

Requires Python 3.10+ and the `zstandard` package.

```sh
pip install zstandard
```

Clone the repo and run directly from the `src/` directory, or add it to your PATH:

```sh
git clone https://github.com/slashdash123/shrinker
cd shrinker
```

## Usage

**Compress**

```sh
python3 src/cli.py compress server.log server.logz
```

**Search** (no decompression required)

```sh
python3 src/cli.py search server.logz "error 500"
python3 src/cli.py search server.logz "req-000042"
```

**Decompress** (bit-exact round-trip)

```sh
python3 src/cli.py decompress server.logz --output restored.log
```

## Format support

Format is detected automatically from the first five lines of the input file.

| Format    | Detection                                      |
|-----------|------------------------------------------------|
| JSON      | Lines parse as valid JSON objects              |
| Syslog    | Lines match `MMM DD HH:MM:SS hostname` prefix  |
| Plaintext | Fallback for everything else                   |

You can override detection with `--format json`, `--format syslog`, or `--format plaintext`.

## File format

The `.logz` format stores everything needed to seek, filter, and decompress in a single self-contained file:

```
[MAGIC 4B]  [VERSION 2B]  [FORMAT 1B]
[DICT_LEN 4B]  [DICT_DATA N bytes]
[CHUNK_0 .. CHUNK_N  — compressed 64 KB blocks]
[JUMP TABLE — per chunk: offset(8) + comp_size(4) + orig_size(4) + bloom(1024)]
[JUMP_TABLE_OFFSET 8B]  [NUM_CHUNKS 4B]
```

## Project status

This is a working Python prototype. All three commands work and the round-trip is verified lossless. The C core rewrite (targeting sub-millisecond search on 1 GB files) has not started yet. Not production software.

Completed:
- [x] Compress with zstd dictionary and 64 KB seekable chunks
- [x] Per-chunk bloom filters (1024 bytes, 3 hash functions)
- [x] Jump table footer (Parquet-style)
- [x] Search with bloom pre-filter
- [x] Lossless decompression with byte-exact verification
- [x] Auto format detection (JSON / syslog / plaintext)
- [x] Test suite (compress, search, decompress)

Planned:
- [ ] C core for search hot path
- [ ] Jump table overhead below 5% (currently 5.5%)
- [ ] Streaming compress for stdin input
