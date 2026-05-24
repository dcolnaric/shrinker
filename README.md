# Shrinker

**Audit logs that survive a 7-year subpoena. 10x smaller. Searchable without rehydration. Single binary.**

Shrinker compresses audit log files and lets you grep them by keyword or date range — without ever decompressing the archive.

## The problem

Compliance frameworks (SOC 2, PCI-DSS, HIPAA, SOX) require you to retain audit logs for 1–7 years and produce specific records on demand. Most teams store raw logs in S3 and either pay for indexed search (expensive) or decompress gigabytes on every audit request (slow). Neither option fits a 7-year retention window.

Shrinker is a third option: a tamper-proof compressed file format that compresses audit logs 10x and lets you search them in milliseconds by skipping irrelevant chunks before they are ever decompressed.

## How it works in three commands

```sh
# Compress 6.67 MB of access logs to 0.62 MB (10.72x)
shrinker compress access.log access.logz

# Search by keyword — no decompression step needed
shrinker search access.logz "payment failed"

# Search within a date window — skips out-of-range chunks before bloom check
shrinker search access.logz "admin" --from 2025-01-01 --to 2025-01-31

# Verify the SHA-256 hash chain — detect any tampering since archival
shrinker verify access.logz
```

## Benchmarks

Measured on real log files. Compression uses zstd level 3 with a shared dictionary trained on the first 10 MB of input.

| Dataset            | Input    | Output   | Ratio  |
|--------------------|----------|----------|--------|
| Synthetic JSON     | 1.49 MB  | 0.41 MB  | 3.66x  |
| Real nginx logs    | 6.67 MB  | 0.62 MB  | 10.72x |
| Real HDFS logs     | 1504 MB  | 183 MB   | 8.21x  |

Search performance on a 1.5 GB file:
- **98.8% of chunks skipped** by bloom filter (0 false positives)
- Seekable chunking overhead: **−0.4%** vs solid zstd (effectively zero)
- Jump table overhead: **5.5%** of output size

## Tamper detection

Every `.logz` file contains a SHA-256 hash chain over the raw (pre-compression) bytes of each chunk:

```
chunk 0:  SHA256(raw_bytes)
chunk N:  SHA256(prev_chunk_hash || raw_bytes)
```

The final hash is stored in the file footer as a convenience copy. Running `shrinker verify` recomputes the entire chain and compares it against the stored hashes. Any modification — including a single flipped bit in any chunk — produces a mismatch.

```
$ shrinker verify access.logz
VERIFIED  access.logz  12 chunks  chain a3f1c8d92b44e7f1…
```

Exit codes: `0` = clean, `1` = tampered, `2` = error.

## Time-range search

Each chunk's jump table entry stores the first and last timestamp found in that chunk (`min_ts` / `max_ts` as unix epoch seconds). When you pass `--from` / `--to`, chunks whose timestamp range does not overlap the window are skipped before even checking the bloom filter — making date-range queries on multi-year archives fast without any external index.

Supported timestamp formats:
- JSON keys: `timestamp`, `time`, `ts`, `@timestamp` — ISO 8601 or unix epoch int/float
- Syslog: `Jan 15 10:23:45` prefix

Chunks with no recognisable timestamps are never skipped on time grounds.

## How it works

Log files are split into 64 KB chunks, each compressed independently with zstd using a shared dictionary. For each chunk, Shrinker:
1. Builds a 1024-byte bloom filter by tokenising the raw bytes on JSON/syslog delimiters
2. Computes a SHA-256 hash chained from the previous chunk
3. Extracts the first and last timestamps

All three are stored in the jump table at the end of the file — the same footer-first layout used by Parquet. When you search, Shrinker reads the jump table (a few KB), applies the time-range filter, checks bloom filters, and decompresses only the matching chunks.

## Installation

Requires Python 3.10+ and the `zstandard` package.

```sh
pip install zstandard
git clone https://github.com/slashdash123/shrinker
cd shrinker
```

## Usage

**Compress**

```sh
python3 src/cli.py compress server.log server.logz
python3 src/cli.py compress server.log server.logz --format json
```

**Search** (no decompression required)

```sh
python3 src/cli.py search server.logz "error 500"
python3 src/cli.py search server.logz "req-000042" --from 2025-01-01 --to 2025-01-31
```

**Decompress** (bit-exact round-trip)

```sh
python3 src/cli.py decompress server.logz --output restored.log
python3 src/cli.py decompress server.logz > restored.log
```

**Verify** (tamper detection)

```sh
python3 src/cli.py verify server.logz
```

## Format support

Format is detected automatically from the first five lines of the input file.

| Format    | Detection                                     |
|-----------|-----------------------------------------------|
| JSON      | Lines parse as valid JSON objects             |
| Syslog    | Lines match `MMM DD HH:MM:SS hostname` prefix |
| Plaintext | Fallback for everything else                  |

Override with `--format json`, `--format syslog`, or `--format plaintext`.

## File format (v3)

```
[MAGIC 4B "LOGZ"]  [VERSION 2B = 3]  [FORMAT 1B]
[DICT_LEN 4B]  [DICT_DATA N bytes — shared zstd dictionary]
[CHUNK_0 .. CHUNK_N — compressed 64 KB blocks]
[JUMP TABLE — 1088 bytes per entry:
    offset(8) + comp_size(4) + orig_size(4) + bloom(1024) + chunk_hash(32) + min_ts(8) + max_ts(8)]
[CHAIN_HASH 32B]  [JUMP_TABLE_OFFSET 8B]  [NUM_CHUNKS 4B]
```

The footer is always 44 bytes at EOF — seek there first to find the jump table, identical to the Parquet footer pattern.

## Compliance fit

| Regulation | Retention   | Shrinker value                                        |
|------------|-------------|-------------------------------------------------------|
| PCI-DSS 4.0 | 12 months, 3 immediately searchable | Instant search without rehydration |
| SOX        | 7 years     | 10x smaller archives + tamper-proof hash chain        |
| HIPAA      | 6 years PHI | Byte-exact decompression + date-range retrieval       |
| SOC 2      | 1 year min  | Auditor-ready: single file, verifiable, searchable    |

## Project status

Working Python prototype. All commands pass the full test suite. The C core rewrite (for sub-millisecond search on 1 GB+ files) has not started yet.

Completed:
- [x] Compress with zstd dictionary and 64 KB seekable chunks
- [x] Per-chunk bloom filters (1024 bytes, 3 hash functions)
- [x] Jump table footer (Parquet-style)
- [x] Search with bloom pre-filter
- [x] Lossless decompression with byte-exact verification
- [x] Auto format detection (JSON / syslog / plaintext)
- [x] SHA-256 hash chain for tamper detection (`verify` command)
- [x] Per-chunk timestamp index for time-range search (`--from` / `--to`)
- [x] Test suite (compress, search, decompress, verify, time-range)

Planned:
- [ ] Field-filter search (`--user`, `--ip`, `--level` flags)
- [ ] CSV export (`shrinker export --from 2025-01-01 --format csv`)
- [ ] C core for search hot path
- [ ] Jump table overhead below 5% (currently 5.5%)
- [ ] Streaming compress for stdin input
