/*
 * decompress.c — Shrinker C decompressor (Phase 3 Step 15)
 *
 * Implements decompress_file(): reads every chunk of a .logz file and
 * writes the decompressed bytes to an output file in order, producing a
 * byte-exact reconstruction of the original log.
 *
 * Output is byte-compatible with the Python oracle in src/decompress.py.
 * Verified by: diff original.log decompressed.log  (zero output = pass)
 *
 * Returns 0 on success, 1 on any error.
 */

#define _FILE_OFFSET_BITS 64   /* 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <zstd.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian read helpers — same as in search.c / verify.c.
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
 * decompress_file — public API
 * ------------------------------------------------------------------------- */

int decompress_file(const char *logz_path, const char *output_path)
{
    FILE *fin = fopen(logz_path, "rb");
    if (!fin) {
        fprintf(stderr, "error: cannot open '%s'\n", logz_path);
        return 1;
    }

    /* --- 1. Validate MAGIC --- */
    uint8_t magic[4];
    if (fread(magic, 1, 4, fin) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "error: not a .logz file (bad magic)\n");
        fclose(fin); return 1;
    }

    /* --- 2. Validate VERSION --- */
    uint16_t version;
    if (read_u16_le(fin, &version) != 0) {
        fprintf(stderr, "error: cannot read version\n");
        fclose(fin); return 1;
    }
    if (version != VERSION) {
        fprintf(stderr, "error: unsupported version %u (expected %u)\n",
                version, VERSION);
        fclose(fin); return 1;
    }

    /* --- 3. Skip FORMAT byte --- */
    uint8_t fmt_byte;
    if (fread(&fmt_byte, 1, 1, fin) != 1) {
        fprintf(stderr, "error: cannot read format byte\n");
        fclose(fin); return 1;
    }

    /* --- 4. Read shared dictionary: DICT_LEN + DICT_DATA --- */
    uint32_t dict_len;
    if (read_u32_le(fin, &dict_len) != 0) {
        fprintf(stderr, "error: cannot read dict_len\n");
        fclose(fin); return 1;
    }

    uint8_t    *dict_buf = NULL;
    ZSTD_DDict *ddict    = NULL;

    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf) {
            fprintf(stderr, "error: OOM for dictionary (%u bytes)\n", dict_len);
            fclose(fin); return 1;
        }
        if (fread(dict_buf, 1, dict_len, fin) != dict_len) {
            fprintf(stderr, "error: short read on dictionary\n");
            free(dict_buf); fclose(fin); return 1;
        }
        ddict = ZSTD_createDDict(dict_buf, dict_len);
        if (!ddict) {
            fprintf(stderr, "error: ZSTD_createDDict failed\n");
            free(dict_buf); fclose(fin); return 1;
        }
    }

    /* --- 5. Read footer: chain_hash(32) + jt_offset(8) + num_chunks(4) --- */
    if (fseek(fin, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek to footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    uint8_t  chain_hash[32];   /* not used for decompression, consumed from stream */
    uint64_t jt_offset;
    uint32_t num_chunks;

    if (fread(chain_hash, 1, 32, fin) != 32 ||
        read_u64_le(fin, &jt_offset) != 0    ||
        read_u32_le(fin, &num_chunks) != 0) {
        fprintf(stderr, "error: cannot read footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    /* --- 6. Read full jump table into memory --- */
    JumpEntry *entries = (JumpEntry *)malloc((size_t)num_chunks * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "error: OOM for jump table (%u entries)\n", num_chunks);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    if (fseek(fin, (long)jt_offset, SEEK_SET) != 0) {
        fprintf(stderr, "error: cannot seek to jump table\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    size_t n_read = fread(entries, sizeof(JumpEntry), num_chunks, fin);
    if (n_read != (size_t)num_chunks) {
        fprintf(stderr, "error: read %zu of %u jump-table entries\n",
                n_read, num_chunks);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    /* --- 7. Open output file --- */
    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        fprintf(stderr, "error: cannot open output '%s'\n", output_path);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    /* --- 8. Decompression context and buffers --- */
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) {
        fprintf(stderr, "error: ZSTD_createDCtx failed\n");
        fclose(fout);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    /* Pre-allocate at worst-case sizes; grow dynamically if a chunk exceeds
     * CHUNK_SIZE (should not happen in practice with the current compressor). */
    size_t  comp_cap = ZSTD_compressBound(CHUNK_SIZE);
    size_t  raw_cap  = CHUNK_SIZE;
    uint8_t *comp_buf = (uint8_t *)malloc(comp_cap);
    uint8_t *raw_buf  = (uint8_t *)malloc(raw_cap);
    if (!comp_buf || !raw_buf) {
        fprintf(stderr, "error: OOM for chunk buffers\n");
        free(comp_buf); free(raw_buf);
        ZSTD_freeDCtx(dctx); fclose(fout);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(fin); return 1;
    }

    /* --- 9. Decompress every chunk in order and write to output --- */
    uint64_t output_size = 0;
    int      rc          = 0;

    for (uint32_t i = 0; i < num_chunks; i++) {
        JumpEntry *e = &entries[i];

        /* Grow compressed buffer if needed */
        if (e->comp_size > comp_cap) {
            free(comp_buf);
            comp_cap = (size_t)e->comp_size * 2;
            comp_buf = (uint8_t *)malloc(comp_cap);
            if (!comp_buf) {
                fprintf(stderr, "error: OOM growing comp_buf at chunk %u\n", i);
                rc = 1; goto cleanup;
            }
        }
        /* Grow raw buffer if needed */
        if (e->orig_size > raw_cap) {
            free(raw_buf);
            raw_cap = (size_t)e->orig_size;
            raw_buf = (uint8_t *)malloc(raw_cap);
            if (!raw_buf) {
                fprintf(stderr, "error: OOM growing raw_buf at chunk %u\n", i);
                rc = 1; goto cleanup;
            }
        }

        /* Read compressed bytes from the .logz file */
        if (fseek(fin, (long)e->offset, SEEK_SET) != 0 ||
            fread(comp_buf, 1, e->comp_size, fin) != e->comp_size) {
            fprintf(stderr, "error: cannot read chunk %u (offset=%llu, size=%u)\n",
                    i, (unsigned long long)e->offset, e->comp_size);
            rc = 1; goto cleanup;
        }

        /* Decompress into raw_buf — max output is exactly orig_size */
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
            fprintf(stderr, "error: decompression failed on chunk %u: %s\n",
                    i, ZSTD_getErrorName(dec_size));
            rc = 1; goto cleanup;
        }

        /* Sanity-check: decompressed size must equal the stored orig_size */
        if (dec_size != e->orig_size) {
            fprintf(stderr,
                    "error: chunk %u size mismatch: got %zu, expected %u\n",
                    i, dec_size, e->orig_size);
            rc = 1; goto cleanup;
        }

        /* Write decompressed bytes to output */
        if (fwrite(raw_buf, 1, dec_size, fout) != dec_size) {
            fprintf(stderr, "error: write failed on chunk %u\n", i);
            rc = 1; goto cleanup;
        }
        output_size += dec_size;
    }

    /* --- 10. Stats to stderr — mirrors Python decompress.py output format ---
     *   Chunks:  107
     *   Output:  6.67 MB
     */
    fprintf(stderr, "Chunks:  %u\n", num_chunks);
    fprintf(stderr, "Output:  %.2f MB\n", (double)output_size / (1024.0 * 1024.0));

cleanup:
    free(comp_buf);
    free(raw_buf);
    ZSTD_freeDCtx(dctx);
    fclose(fout);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(fin);
    return rc;
}
