/*
 * main.c — Shrinker C prototype entry point (Phase 3 Step 10)
 *
 * Opens a .logz file, validates the header magic and version, reads the
 * footer, and prints a one-line summary identical in content to what
 * `shrinker verify` reports from the Python implementation.
 *
 * Exit codes:  0 = success
 *              1 = any error (bad args, I/O failure, wrong magic/version)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Portable little-endian readers.
 * We read byte-by-byte so the code is correct on both LE and BE hosts.
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
 * main
 * ------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage: shrinker <file.logz>\n");
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    /* --- 1. Read and validate magic (4 bytes) --- */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fprintf(stderr, "error: cannot read magic bytes\n");
        fclose(f); return 1;
    }
    if (memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "error: bad magic (got %02x%02x%02x%02x, expected 4c4f475a)\n",
                magic[0], magic[1], magic[2], magic[3]);
        fclose(f); return 1;
    }
    printf("magic:      OK (%c%c%c%c)\n", magic[0], magic[1], magic[2], magic[3]);

    /* --- 2. Read and validate version (uint16 LE) --- */
    uint16_t version;
    if (read_u16_le(f, &version) != 0) {
        fprintf(stderr, "error: cannot read version\n");
        fclose(f); return 1;
    }
    if (version != VERSION) {
        fprintf(stderr, "error: unsupported version %u (expected %u)\n",
                version, VERSION);
        fclose(f); return 1;
    }
    printf("version:    %u\n", (unsigned)version);

    /* --- 3. Seek to footer: EOF - FOOTER_SIZE --- */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek to footer\n");
        fclose(f); return 1;
    }

    /* --- 4. Read footer: chain_hash(32) + jt_offset(8) + num_chunks(4) --- */
    uint8_t  chain_hash[32];
    uint64_t jt_offset;
    uint32_t num_chunks;

    if (fread(chain_hash, 1, 32, f) != 32) {
        fprintf(stderr, "error: cannot read chain_hash\n");
        fclose(f); return 1;
    }
    if (read_u64_le(f, &jt_offset) != 0) {
        fprintf(stderr, "error: cannot read jt_offset\n");
        fclose(f); return 1;
    }
    if (read_u32_le(f, &num_chunks) != 0) {
        fprintf(stderr, "error: cannot read num_chunks\n");
        fclose(f); return 1;
    }

    /* --- 5. Print results --- */
    printf("num_chunks: %u\n", num_chunks);
    printf("jt_offset:  %llu\n", (unsigned long long)jt_offset);

    printf("chain_hash: ");
    for (int i = 0; i < 8; i++)
        printf("%02x", chain_hash[i]);
    printf("...\n");

    fclose(f);
    return 0;
}
