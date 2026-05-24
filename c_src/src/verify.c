/*
 * verify.c — Shrinker C integrity verifier (Phase 3 Step 14)
 *
 * Implements verify_file(): reads every chunk of a .logz file, recomputes
 * the SHA-256 hash chain over raw (pre-compression) bytes, and compares
 * against the stored hashes in the jump table.  Also cross-checks the
 * footer chain_hash against the final computed hash.
 *
 * Output and exit codes are byte-compatible with the Python oracle
 * src/verify.py.  Verified against data/HDFS_v4.logz (Python-compressed)
 * and data/nginx_c.logz (C-compressed).
 *
 * Exit codes:  0 = VERIFIED (all chunk hashes match)
 *              1 = TAMPERED (any mismatch or decompression failure)
 *              2 = error   (bad args, bad magic/version, I/O failure)
 */

#define _FILE_OFFSET_BITS 64   /* 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <zstd.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian read helpers — same as in search.c / main.c.
 * ------------------------------------------------------------------------- */

static int read_u16_le(FILE *f, uint16_t *out)
{
    uint8_t b[2];
    if (fread(b, 1, 2, f) != 2) return -1;
    *out = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
    return 0;
}

static int read_u32_le(FILE *f, uint32_t *out)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return -1;
    *out = (uint32_t)b[0]
         | ((uint32_t)b[1] <<  8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
    return 0;
}

static int read_u64_le(FILE *f, uint64_t *out)
{
    uint8_t b[8];
    if (fread(b, 1, 8, f) != 8) return -1;
    *out = (uint64_t)b[0]
         | ((uint64_t)b[1] <<  8)
         | ((uint64_t)b[2] << 16)
         | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32)
         | ((uint64_t)b[5] << 40)
         | ((uint64_t)b[6] << 48)
         | ((uint64_t)b[7] << 56);
    return 0;
}

/* -------------------------------------------------------------------------
 * verify_file — public API
 *
 * Returns 0 = VERIFIED, 1 = TAMPERED, 2 = error.
 * All TAMPERED / VERIFIED output goes to stdout (matches Python oracle).
 * All operational errors go to stderr.
 * ------------------------------------------------------------------------- */

int verify_file(const char *logz_path)
{
    FILE *f = fopen(logz_path, "rb");
    if (!f) {
        fprintf(stderr, "error: file not found: %s\n", logz_path);
        return 2;
    }

    /* --- 1. Validate MAGIC --- */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "error: not a .logz file (bad magic)\n");
        fclose(f); return 2;
    }

    /* --- 2. Validate VERSION --- */
    uint16_t version;
    if (read_u16_le(f, &version) != 0) {
        fprintf(stderr, "error: cannot read version\n");
        fclose(f); return 2;
    }
    if (version != VERSION) {
        fprintf(stderr, "error: unsupported version %u (expected %u)\n",
                version, VERSION);
        fclose(f); return 2;
    }

    /* --- 3. Skip FORMAT byte --- */
    uint8_t fmt_byte;
    if (fread(&fmt_byte, 1, 1, f) != 1) {
        fprintf(stderr, "error: cannot read format byte\n");
        fclose(f); return 2;
    }

    /* --- 4. Read dictionary: DICT_LEN + DICT_DATA --- */
    uint32_t dict_len;
    if (read_u32_le(f, &dict_len) != 0) {
        fprintf(stderr, "error: cannot read dict_len\n");
        fclose(f); return 2;
    }

    uint8_t    *dict_buf = NULL;
    ZSTD_DDict *ddict    = NULL;

    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf) {
            fprintf(stderr, "error: OOM for dictionary (%u bytes)\n", dict_len);
            fclose(f); return 2;
        }
        if (fread(dict_buf, 1, dict_len, f) != dict_len) {
            fprintf(stderr, "error: short read on dictionary\n");
            free(dict_buf); fclose(f); return 2;
        }
        ddict = ZSTD_createDDict(dict_buf, dict_len);
        if (!ddict) {
            fprintf(stderr, "error: ZSTD_createDDict failed\n");
            free(dict_buf); fclose(f); return 2;
        }
    }

    /* --- 5. Read footer: chain_hash(32) + jt_offset(8) + num_chunks(4) --- */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek to footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    uint8_t  footer_chain_hash[32];
    uint64_t jt_offset;
    uint32_t num_chunks;

    if (fread(footer_chain_hash, 1, 32, f) != 32 ||
        read_u64_le(f, &jt_offset) != 0           ||
        read_u32_le(f, &num_chunks) != 0) {
        fprintf(stderr, "error: cannot read footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    /* --- 6. Read full jump table --- */
    JumpEntry *entries = (JumpEntry *)malloc((size_t)num_chunks * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "error: OOM for jump table (%u entries)\n", num_chunks);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    if (fseek(f, (long)jt_offset, SEEK_SET) != 0) {
        fprintf(stderr, "error: cannot seek to jump table\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    size_t n_read = fread(entries, sizeof(JumpEntry), num_chunks, f);
    if (n_read != (size_t)num_chunks) {
        fprintf(stderr, "error: read %zu of %u jump-table entries\n",
                n_read, num_chunks);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    /* --- 7. Decompression context and buffers --- */
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) {
        fprintf(stderr, "error: ZSTD_createDCtx failed\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    size_t  comp_cap = ZSTD_compressBound(CHUNK_SIZE);
    size_t  raw_cap  = CHUNK_SIZE;
    uint8_t *comp_buf = (uint8_t *)malloc(comp_cap);
    uint8_t *raw_buf  = (uint8_t *)malloc(raw_cap);
    if (!comp_buf || !raw_buf) {
        fprintf(stderr, "error: OOM for chunk buffers\n");
        free(comp_buf); free(raw_buf);
        ZSTD_freeDCtx(dctx);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 2;
    }

    /* --- 8. Walk every chunk and recompute hash chain --- */
    uint8_t prev_hash[32];
    int     has_prev = 0;      /* false for chunk 0: chain seed is implicit */
    int     result   = 0;      /* will be set to 1 on TAMPERED */

    for (uint32_t i = 0; i < num_chunks; i++) {
        JumpEntry *e = &entries[i];

        /* Grow buffers if needed (unexpected large chunk) */
        if (e->comp_size > comp_cap) {
            free(comp_buf);
            comp_cap = (size_t)e->comp_size * 2;
            comp_buf = (uint8_t *)malloc(comp_cap);
            if (!comp_buf) {
                fprintf(stderr, "error: OOM growing comp_buf\n");
                result = 2; goto cleanup;
            }
        }
        if (e->orig_size > raw_cap) {
            free(raw_buf);
            raw_cap = (size_t)e->orig_size;
            raw_buf = (uint8_t *)malloc(raw_cap);
            if (!raw_buf) {
                fprintf(stderr, "error: OOM growing raw_buf\n");
                result = 2; goto cleanup;
            }
        }

        /* Read compressed bytes */
        if (fseek(f, (long)e->offset, SEEK_SET) != 0 ||
            fread(comp_buf, 1, e->comp_size, f) != e->comp_size) {
            fprintf(stderr, "error: cannot read chunk %u\n", i);
            result = 2; goto cleanup;
        }

        /* Decompress — failure is itself evidence of tampering */
        size_t dec_size;
        if (ddict) {
            dec_size = ZSTD_decompress_usingDDict(dctx,
                           raw_buf,  e->orig_size,
                           comp_buf, e->comp_size,
                           ddict);
        } else {
            dec_size = ZSTD_decompressDCtx(dctx,
                           raw_buf,  e->orig_size,
                           comp_buf, e->comp_size);
        }

        if (ZSTD_isError(dec_size)) {
            /* Print to stdout — matches Python oracle behaviour */
            printf("TAMPERED  %s  chunk %u  decompression failed\n",
                   logz_path, i);
            result = 1; goto cleanup;
        }

        /* Recompute hash chain over RAW bytes (not compressed).
         *
         *   chunk 0: SHA256(raw_bytes)
         *   chunk N: SHA256(prev_hash || raw_bytes)
         *
         * Uses EVP streaming API (OpenSSL 3.x) — same as compress.c.
         * Hashing raw bytes means the chain certifies log *content*, not
         * a compression artefact.
         */
        uint8_t computed[32];
        {
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            if (!mdctx) {
                fprintf(stderr, "error: EVP_MD_CTX_new failed\n");
                result = 2; goto cleanup;
            }
            EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
            if (has_prev)
                EVP_DigestUpdate(mdctx, prev_hash, 32);
            EVP_DigestUpdate(mdctx, raw_buf, dec_size);
            unsigned int mdlen = 32;
            EVP_DigestFinal_ex(mdctx, computed, &mdlen);
            EVP_MD_CTX_free(mdctx);
        }

        /* Compare against the stored hash in the jump table */
        if (memcmp(computed, e->chunk_hash, 32) != 0) {
            /* Print first 16 hex chars (8 bytes) of each hash, matching Python:
             *   stored_hash.hex()[:16]   computed.hex()[:16]
             * Python formats as lowercase hex — printf %02x does the same. */
            printf("TAMPERED  %s  chunk %u  expected ", logz_path, i);
            for (int j = 0; j < 8; j++) printf("%02x", e->chunk_hash[j]);
            printf("…  got ");
            for (int j = 0; j < 8; j++) printf("%02x", computed[j]);
            printf("…\n");
            result = 1; goto cleanup;
        }

        memcpy(prev_hash, computed, 32);
        has_prev = 1;
    }

    /* --- 9. Verify footer chain_hash == final computed hash --- */
    if (has_prev && memcmp(footer_chain_hash, prev_hash, 32) != 0) {
        printf("TAMPERED  %s  footer chain_hash mismatch  expected ", logz_path);
        for (int j = 0; j < 8; j++) printf("%02x", prev_hash[j]);
        printf("…  got ");
        for (int j = 0; j < 8; j++) printf("%02x", footer_chain_hash[j]);
        printf("…\n");
        result = 1; goto cleanup;
    }

    /* --- 10. All good --- */
    {
        /* Print first 16 hex chars of the chain hash, matching Python:
         *   f"chain {prev_hash.hex()[:16]}…" */
        printf("VERIFIED  %s  %u chunks  chain ", logz_path, num_chunks);
        if (has_prev) {
            for (int j = 0; j < 8; j++) printf("%02x", prev_hash[j]);
            printf("…\n");
        } else {
            printf("(empty)\n");
        }
    }
    result = 0;

cleanup:
    free(comp_buf);
    free(raw_buf);
    ZSTD_freeDCtx(dctx);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(f);
    return result;
}
