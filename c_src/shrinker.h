#ifndef SHRINKER_H
#define SHRINKER_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * File-format constants — must match Python src/compress.py exactly.
 * ------------------------------------------------------------------------- */

#define MAGIC           "LOGZ"          /* 4-byte magic: 0x4C 0x4F 0x47 0x5A */
#define VERSION         4               /* current .logz format version        */
#define CHUNK_SIZE      65536           /* 64 KB per compressed chunk          */
#define JUMP_ENTRY_SIZE 1600            /* bytes per jump-table entry          */
#define FOOTER_SIZE     44              /* chain_hash(32)+jt_offset(8)+num_chunks(4) */

/* Log-format byte stored in the file header */
#define FORMAT_JSON      0
#define FORMAT_SYSLOG    1
#define FORMAT_PLAINTEXT 2

/* -------------------------------------------------------------------------
 * Jump-table entry (1600 bytes, no padding — layout verified below).
 *
 *   offset(8) + comp_size(4) + orig_size(4) + bloom(1024) +
 *   chunk_hash(32) + min_ts(8) + max_ts(8) + field_bloom(512) = 1600
 * ------------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint64_t offset;            /*  8 B — absolute byte offset of chunk       */
    uint32_t comp_size;         /*  4 B — compressed size in bytes            */
    uint32_t orig_size;         /*  4 B — original (raw) size in bytes        */
    uint8_t  bloom[1024];       /* 1024B — full-text bloom filter             */
    uint8_t  chunk_hash[32];    /* 32 B — SHA-256 hash-chain entry            */
    uint64_t min_ts;            /*  8 B — earliest unix epoch in chunk        */
    uint64_t max_ts;            /*  8 B — latest unix epoch in chunk          */
    uint8_t  field_bloom[512];  /* 512 B — field-value bloom (JSON only)      */
} JumpEntry;

/* -------------------------------------------------------------------------
 * File footer (44 bytes, read from EOF-44).
 *
 *   chain_hash(32) + jt_offset(8) + num_chunks(4) = 44
 * ------------------------------------------------------------------------- */
typedef struct __attribute__((packed)) {
    uint8_t  chain_hash[32];    /* 32 B — SHA-256 of the final chunk          */
    uint64_t jt_offset;         /*  8 B — byte offset of the jump table       */
    uint32_t num_chunks;        /*  4 B — total number of chunks              */
} FileFooter;

/* Compile-time size assertions — catch layout bugs immediately. */
_Static_assert(sizeof(JumpEntry)  == JUMP_ENTRY_SIZE,
               "JumpEntry size mismatch — check struct layout");
_Static_assert(sizeof(FileFooter) == FOOTER_SIZE,
               "FileFooter size mismatch — check struct layout");

#endif /* SHRINKER_H */
