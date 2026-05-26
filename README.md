# Shrinker

**Tamper-proof audit log archival for SOC 2, PCI-DSS, HIPAA, and SOX.**  
10x smaller. Searchable without rehydration. Single binary. No servers.

```
shrinker compress audit.log  archive.logz
shrinker verify   archive.logz                                    # → VERIFIED 24079 chunks chain 846fc55d…
shrinker search   archive.logz --user admin --from 2025-01-01 --to 2025-03-31
shrinker export   archive.logz --from 2025-01-01 --format csv > audit.csv
```

---

## The problem

Regulations require you to retain audit logs for years:

| Regulation | Retention requirement |
|---|---|
| PCI-DSS 4.0 (Req. 10.7) | 12 months total, 3 months immediately searchable |
| HIPAA (45 CFR §164.316) | 6 years |
| SOX | 7 years for financial audit logs |
| SOC 2 Type II | Minimum 1 year (auditors sample the full observation window) |

Your options today are bad:

- **Splunk / Datadog** — fast search, but $20–40/GB/day. A 100-person SaaS paying for 12-month retention runs $40,000–120,000/year just for logs nobody queries day-to-day.
- **Raw S3** — cheap, but unsearchable. When your auditor asks "show me all admin deletions in Q1 2024" eighteen months later, you're downloading and grepping gigabytes by hand.
- **Cribl Stream** — routes data to cheaper tiers, but starts at $84,000/year and requires a cluster.

Shrinker fits between them. It writes **tamper-proof, 10x-compressed, instantly-searchable archives** directly to S3. No cluster. No running service. One binary you can drop on any Linux box.

---

## How it works

```
shrinker compress audit.log archive.logz
```

Shrinker reads your log file, trains a zstd compression dictionary on the first 10 MB, then splits the input into 64 KB chunks. Each chunk is compressed independently with the shared dictionary and indexed with:

- **Bloom filter** — 1024 bytes per chunk for fast string-search pre-filtering
- **Field bloom filter** — 512 bytes per chunk for `user`, `ip`, `action`, `level` fields in JSON logs
- **Timestamp index** — min/max unix epoch per chunk for time-range pushdown
- **SHA-256 hash** — chained across all chunks for tamper detection

The result is a `.logz` file: a self-contained archive with a Parquet-style footer. No external index, no database, no daemon.

---

## Commands

### compress
```bash
shrinker compress server.log output.logz
shrinker compress server.log output.logz --format json|syslog|plaintext
```
Auto-detects format (JSON / syslog / plaintext). Trains dictionary. Writes tamper-proof archive.

### verify
```bash
shrinker verify output.logz
# VERIFIED  output.logz  24079 chunks  chain 846fc55d08efb3e0…
# TAMPERED  output.logz  chunk 3812    expected a3f7c21d…  got 00000000…
```
Recomputes the full SHA-256 hash chain and compares it against stored values. Exit code 0 = clean, 1 = tampered, 2 = error. Run this before handing logs to an auditor.

### search
```bash
# String search
shrinker search output.logz "payment failed"

# Time-range filter (skips chunks outside the window before bloom check)
shrinker search output.logz "admin" --from 2025-01-01 --to 2025-03-31

# Field filters (JSON logs)
shrinker search output.logz --user admin --ip 192.168.1.1
shrinker search output.logz --action delete --level ERROR --from 2025-01-01

# Combined
shrinker search output.logz "unauthorized" --user root --from 2025-01-01 --to 2025-01-31
```
Chunks are skipped in three layers — time range, field bloom, string bloom — before any decompression happens. On the 1.5 GB HDFS benchmark, 98.8% of chunks are skipped for a specific block ID search.

### export
```bash
shrinker export output.logz --from 2025-01-01 --to 2025-12-31 --format csv > audit.csv
shrinker export output.logz --format json > audit.jsonl
```
Exports matching log lines as CSV or JSONL. CSV columns: `timestamp, level, user, ip, action, message, raw`. Auditors can open the CSV directly in Excel. The `raw` column always contains the original unmodified log line.

### decompress
```bash
shrinker decompress output.logz --output restored.log
```
Full lossless decompression. Output is byte-exact identical to the original input file (verified with `diff`).

---

## Benchmarks

All benchmarks run on a Snapdragon X Elite (ARM64) laptop, WSL2 Ubuntu, single-threaded.  
Dataset: **1.5 GB HDFS log** (1,577,982,906 bytes, 11.2 M lines, 24,079 chunks).  
C binary compiled with `gcc -O3`. Python 3.12 with `zstandard` library.

### C vs Python — wall-clock time

| Operation | C (release) | Python | C speedup |
|---|---|---|---|
| **compress** 1.5 GB → 196 MB | 23.1 s | 17 min 14.7 s | **44.8×** |
| **search** specific block ID | 0.099 s | 0.570 s | **5.8×** |
| **search** broad term (`blk_`) | 0.105 s | 0.543 s | **5.2×** |
| **verify** hash chain | 6.4 s | 5.2 s | — ¹ |
| **decompress** → 1.5 GB | 6.1 s | 4.5 s | — ¹ |
| **export** CSV (11.2 M lines) | 4.7 s | 47.9 s | **10.2×** |

> ¹ Verify and decompress are I/O-bound and delegate the heavy work (libzstd decompression,
> OpenSSL SHA-256) to the same underlying C libraries in both implementations.
> Python's slightly faster measured time reflects OS page-cache warmth — its input file
> had just been written and was still hot in memory. On a cold cache both would
> be within measurement noise of each other.

**Headline numbers:**
- Compress is **44.8× faster** in C — the dominant cost for ingestion pipelines.
- Search is **5–6× faster** in C — still sub-second in both, bloom skip rates are identical (98.8%).
- Export is **10× faster** in C — driven by pure Python's field-extraction loop overhead.

### Compression ratios

| Dataset | Input | Output | Ratio | Notes |
|---|---|---|---|---|
| Synthetic JSON | 1.49 MB | 0.41 MB | 3.66× | Worst case — random UUIDs |
| Real nginx logs | 6.67 MB | 0.62 MB | 10.72× | Public access log dataset |
| Real HDFS logs | 1504 MB | 196 MB | 7.67× | 1.5 GB academic benchmark |

### Bloom filter skip rates on 1.5 GB HDFS (24,079 chunks)

| Query | Chunks scanned | Bloom-skipped | Skip rate | Matches |
|---|---|---|---|---|
| Specific block ID | 277 / 24,079 | 23,802 | **98.8%** | 269 lines |
| Broad term (`blk_`) | 329 / 24,079 | 23,750 | **98.6%** | 153,157 lines |

Zero false positives observed across all test runs.

---

## .logz file format (v4)

```
[MAGIC       4B]  b'LOGZ' (0x4C4F475A)
[VERSION     2B]  uint16 LE — value 4
[FORMAT      1B]  0=json  1=syslog  2=plaintext
[DICT_LEN    4B]  uint32 LE
[DICT_DATA   NB]  zstd dictionary trained on first 10 MB of input
[CHUNK_0 .. CHUNK_N]  independently compressed 64 KB blocks

Jump table (1600 bytes per entry):
  offset      uint64 LE  byte offset of chunk in file
  comp_size   uint32 LE  compressed size in bytes
  orig_size   uint32 LE  original size in bytes
  bloom       1024B      string bloom filter (djb2 + fnv1a + sdbm, 3 hashes)
  chunk_hash  32B        SHA-256(prev_hash || raw_chunk_data)
  min_ts      uint64 LE  earliest unix epoch timestamp in chunk (0 if none found)
  max_ts      uint64 LE  latest unix epoch timestamp in chunk (0 if none found)
  field_bloom 512B       field bloom filter for user/ip/action/level values (JSON only)

Footer (44 bytes, read from EOF-44):
  chain_hash         32B  SHA-256 of final chunk (integrity shortcut)
  jump_table_offset   8B  uint64 LE
  num_chunks          4B  uint32 LE
```

The format is self-contained. No external index or database is required to read, search, verify, or decompress a `.logz` file. The C and Python implementations are **byte-compatible**: a file compressed by one can be verified, searched, and decompressed by the other.

---

## Compliance notes

### Tamper detection
The SHA-256 hash chain means any modification to any chunk — even a single byte — invalidates all subsequent hashes. `shrinker verify` recomputes the full chain and reports the exact chunk where tampering occurred. This gives auditors mathematical proof that logs have not been altered since archival.

### Immutable storage
Pair Shrinker with **S3 Object Lock in Compliance Mode** to meet WORM (Write Once Read Many) requirements. Once written with Object Lock, the archive cannot be deleted or overwritten — not even by the AWS root account — until the retention period expires. This is the primitive assessed by Cohasset Associates for SEC 17a-4 and CFTC 1.31 compliance.

### SOC 2 Type II evidence
`shrinker verify` is the command an auditor runs. The output line:
```
VERIFIED  archive.logz  24079 chunks  chain 846fc55d08efb3e0…
```
provides a dated, reproducible integrity attestation. The chain hash is deterministic — running verify twice on an unmodified file produces identical output.

### Retention mapping

| Regulation | Recommended setup |
|---|---|
| SOC 2 Type II | 365-day retention, verify before each audit window |
| PCI-DSS 4.0 | 365-day retention with 90-day hot tier + S3 Object Lock |
| HIPAA | 2190-day (6-year) retention with Object Lock Compliance Mode |
| SOX | 2555-day (7-year) retention with Object Lock Compliance Mode |

---

## Installation

### C binary (Phase 3 — current)

```bash
git clone https://github.com/dcolnaric/shrinker
cd shrinker/c_src
make release          # requires: gcc, libzstd-dev, libssl-dev
./shrinker --help
```

Dependencies: `libzstd`, `libssl`/`libcrypto` (OpenSSL 3.x), `libm`.  
On Ubuntu/Debian: `apt install libzstd-dev libssl-dev`

### Python prototype

```bash
git clone https://github.com/dcolnaric/shrinker
cd shrinker
python -m venv venv && source venv/bin/activate
pip install zstandard
python src/cli.py --help
```

The Python and C implementations produce byte-identical `.logz` files and can be used interchangeably.

---

## Roadmap

**Phase 2 — Python prototype (complete)**
- [x] zstd dictionary compression with seekable 64 KB chunks
- [x] Bloom filter per chunk (98.8% skip rate on 1.5 GB dataset)
- [x] SHA-256 hash chain for tamper detection
- [x] `verify` command with exit codes for scripting
- [x] Time-range search with timestamp index in jump table
- [x] Field search (`--user`, `--ip`, `--action`, `--level`) for JSON logs
- [x] Audit export to CSV and JSONL

**Phase 3 — C core rewrite (complete)**
- [x] 44.8× compression speedup over Python
- [x] Byte-compatible with Python implementation (cross-validated on 1.5 GB HDFS dataset)
- [x] Full CLI: compress / search / verify / decompress / export with `--help` per subcommand
- [x] Memory-safe: zero valgrind errors across all commands, all heap freed
- [x] `--format` override for compress; `--output` flag for decompress
- [x] Warning-free release build (`gcc -O3 -Wall -Wextra`)

**Phase 4 — Distribution**
- [ ] Single static binary (no shared library dependencies)
- [ ] One-line install script
- [ ] GitHub Releases with SHA-256 checksums
- [ ] Cross-platform builds via GitHub Actions (Linux x86-64, Linux ARM64, macOS)

**Phase 5 — Compliance features**
- [ ] S3 direct read/write
- [ ] S3 Object Lock auto-configuration (`--lock 2555days`)
- [ ] Retention policy DSL (YAML)
- [ ] Legal hold management
- [ ] PDF audit report generation

---

## Design decisions

**Why 64 KB chunks?**  
SIMD-aligned for future AVX-512 paths. Large enough for zstd to find cross-line matches, small enough for sub-millisecond random access.

**Why a shared dictionary?**  
Log files are extremely repetitive — JSON keys, hostnames, service names, request paths repeat millions of times. A dictionary trained on the first 10 MB captures this structure and applies it to every chunk. Without a dictionary, JSON log compression is 3–4×. With a trained dictionary, it reaches 8–12× on real datasets.

**Why hash over raw bytes, not compressed bytes?**  
The chain certifies the *content* of the log, not an artifact of which compression version produced it. A future zstd version producing slightly different compressed output would not invalidate existing archives.

**Why a Parquet-style footer?**  
The jump table at the file tail means you can open any `.logz` file, seek to EOF-44, and immediately know how many chunks it contains and where to find them. No external index file to lose or corrupt.

**Why not Parquet itself?**  
Parquet is columnar — optimized for analytics queries over structured fields. Log files are row-oriented and semi-structured. Shrinker's format preserves the original log line verbatim in the `raw` field, which is what auditors need: the unmodified record, not a columnar decomposition of it.

**Why does the C binary beat Python by 44× on compress but only 10× on export?**  
Compress is CPU-bound: dict training, per-chunk zstd compression, bloom filter population, SHA-256 hashing — all implemented in C from scratch. Export is dominated by I/O (writing 11.2 M lines to stdout) with a lighter field-extraction loop; Python's overhead is proportionally smaller when the bottleneck shifts to the kernel write path.

---

## Academic context

Shrinker is the implementation component of a Masters thesis at the Faculty of Electrical Engineering and Computer Science (FERI), University of Maribor, Slovenia.

Thesis title: *"Design and implementation of an efficient format for log file archival and search using dictionary compression, Bloom filters, and cryptographic hash chains"*

---

## Contact

Domen Colnaric - software engineer  
domen.colnaric@gmail.com

---

## License

MIT
