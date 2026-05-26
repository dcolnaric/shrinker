#ifndef SHRINKER_H
#define SHRINKER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * File-format constants — must match Python src/compress.py exactly.
 * Any change here requires a VERSION bump and a new test corpus.
 * ------------------------------------------------------------------------- */

#define MAGIC             "LOGZ"   /* 4-byte magic: 0x4C 0x4F 0x47 0x5A     */
#define VERSION           4        /* current .logz format version
                                    *   v1: initial prototype
                                    *   v2: bloom filter added
                                    *   v3: min_ts / max_ts added (time range)
                                    *   v4: field_bloom added (current)        */
#define CHUNK_SIZE        65536    /* 64 KB per compressed chunk — SIMD-aligned
                                    * for future AVX-512 paths; large enough
                                    * for zstd to find cross-line matches and
                                    * small enough for sub-millisecond seeks    */
#define BLOOM_BYTES       1024     /* 8192-bit main bloom per chunk — 3 hashes
                                    * give ~1% false-positive rate at 50% fill  */
#define FIELD_BLOOM_BYTES 512      /* 4096-bit field bloom per chunk — separate
                                    * index for user/ip/action/level values;
                                    * half the size of main bloom because field
                                    * values are fewer and shorter than full-text
                                    * tokens; zero bytes = no field index        */
#define JUMP_ENTRY_SIZE   1600     /* bytes per jump-table entry (see layout)   */
#define FOOTER_SIZE       44       /* chain_hash(32)+jt_offset(8)+num_chunks(4)
                                    * — bootstrapped by seek(EOF-44, SEEK_END)   */

/* Log-format byte stored in the file header.
 * Controls bloom tokenisation, field extraction, and timestamp parsing:
 *   JSON      — djb2/fnv1a/sdbm over all tokens; field bloom for
 *               user/ip/action/level; ISO-8601 and epoch timestamps
 *   SYSLOG    — same tokenisation; no field bloom; syslog timestamp prefix
 *   PLAINTEXT — tokenisation only; field_bloom zeroed; no timestamps         */
#define FORMAT_JSON       0        /* newline-delimited JSON objects             */
#define FORMAT_SYSLOG     1        /* RFC 3164: "Jan 15 10:23:45 host proc msg"  */
#define FORMAT_PLAINTEXT  2        /* unstructured text; bloom-only, no fields   */

/* Dictionary and training constants.
 * zstd requires ≥2 samples; TRAIN_LIMIT / CHUNK_SIZE gives up to 160.
 * The trained dict is stored verbatim in the file header (after DICT_LEN)
 * so any decompressor can reconstruct every chunk independently — no
 * external dict file to lose or version-skew.                                 */
#define DICT_TARGET       (112 * 1024)          /* 112 KB target dict size     */
#define TRAIN_LIMIT       (10 * 1024 * 1024)    /* feed at most 10 MB of input */
#define MAX_TRAIN_SAMPS   160                    /* 160 × 64 KB = 10 MB         */

/* -------------------------------------------------------------------------
 * Jump-table entry (1600 bytes, no padding — layout verified by assert).
 *
 *   offset(8)+comp_size(4)+orig_size(4)+bloom(1024)+
 *   chunk_hash(32)+min_ts(8)+max_ts(8)+field_bloom(512) = 1600
 *
 * Search skip order (cheapest first, avoids decompression):
 *   1. time range  — skip if max_ts < from_ts OR min_ts > to_ts
 *   2. field bloom — skip if any requested field value is definitely absent
 *   3. main bloom  — skip if query token is definitely absent
 *   4. decompress + grep — only if all three filters pass
 * ------------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint64_t offset;                  /*  8 B — absolute byte offset of chunk
                                       *         in the .logz file             */
    uint32_t comp_size;               /*  4 B — compressed size in bytes       */
    uint32_t orig_size;               /*  4 B — original (raw) size in bytes   */
    uint8_t  bloom[BLOOM_BYTES];      /* 1024B — full-text bloom filter;
                                       *         djb2 + fnv1a + sdbm, 3 bits
                                       *         set per token                 */
    uint8_t  chunk_hash[32];          /* 32 B — SHA-256 hash-chain entry:
                                       *         chunk 0: SHA256(raw)
                                       *         chunk N: SHA256(prev||raw)    */
    uint64_t min_ts;                  /*  8 B — earliest unix epoch in chunk;
                                       *         0 = no timestamps found       */
    uint64_t max_ts;                  /*  8 B — latest unix epoch in chunk;
                                       *         0 = no timestamps found       */
    uint8_t  field_bloom[FIELD_BLOOM_BYTES]; /* 512 B — field-value bloom for
                                       *         user/ip/action/level fields;
                                       *         all zeros for non-JSON chunks */
} JumpEntry;

/* -------------------------------------------------------------------------
 * File footer (44 bytes, read from EOF-44).
 *
 *   chain_hash(32) + jt_offset(8) + num_chunks(4) = 44
 *
 * The Parquet-style footer pattern: seek to EOF-44, read num_chunks and
 * jt_offset, then seek to jt_offset to load the full jump table.  No
 * external index or database needed to open any .logz file.
 * ------------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t  chain_hash[32];   /* 32 B — SHA-256 of the final chunk;
                                 *         convenience copy of the last
                                 *         entry's chunk_hash for fast
                                 *         tamper-detection without reading
                                 *         the full jump table               */
    uint64_t jt_offset;        /*  8 B — byte offset of the jump table       */
    uint32_t num_chunks;       /*  4 B — total number of chunks              */
} FileFooter;

/* Compile-time size assertions */
_Static_assert(sizeof(JumpEntry)  == JUMP_ENTRY_SIZE,
               "JumpEntry size mismatch — check struct layout");
_Static_assert(sizeof(FileFooter) == FOOTER_SIZE,
               "FileFooter size mismatch — check struct layout");

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/* compress.c
 * format_override: FORMAT_JSON / FORMAT_SYSLOG / FORMAT_PLAINTEXT to force a
 *                  specific format, or -1 to auto-detect from the first bytes. */
int compress_file(const char *input_path, const char *output_path,
                  int format_override);

/* search.c */
int search_file(const char *logz_path, const char *query,
                const char *from_date, const char *to_date,
                const char *field_user, const char *field_ip,
                const char *field_action, const char *field_level);

/* verify.c — returns 0=verified, 1=tampered, 2=error */
int verify_file(const char *logz_path);

/* decompress.c — returns 0=success, 1=error */
int decompress_file(const char *logz_path, const char *output_path);

/* export.c — format is "csv" or "json"; returns 0=success, 1=error */
int export_file(const char *logz_path, const char *from_date,
                const char *to_date, const char *format);

/* append.c — append new entries to an existing archive, or create one.
 * format_override: FORMAT_JSON / FORMAT_SYSLOG / FORMAT_PLAINTEXT to force a
 *                  specific format when creating a new archive (ignored when
 *                  appending to an existing archive — the archive's format
 *                  byte is used instead), or -1 to auto-detect. */
int append_file(const char *input_path, const char *archive_path,
                int format_override);

#endif /* SHRINKER_H */
