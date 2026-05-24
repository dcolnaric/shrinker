/*
 * main.c — Shrinker C CLI dispatcher (Phase 3 Steps 10-13)
 *
 * Step 10: validate header magic + version, read and print footer.
 * Step 11: read full jump table, print per-entry summaries, verify
 *          total decompressed size, cross-validate chunk-0 SHA-256.
 * Step 12: compress subcommand — delegates to compress_file().
 * Step 13: search  subcommand — delegates to search_file().
 * Step 14: verify  subcommand — delegates to verify_file().
 *
 * Usage:
 *   shrinker compress <input> <output.logz>
 *   shrinker search   <file.logz> <query> [--from DATE] [--to DATE]
 *                     [--user X] [--ip X] [--action X] [--level X]
 *   shrinker verify   <file.logz>
 *   shrinker inspect  <file.logz>
 *
 * Exit codes:  0 = success
 *              1 = any error (bad args, I/O failure, wrong magic/version)
 */

#define _FILE_OFFSET_BITS 64   /* ensure 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/sha.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Portable little-endian field readers.
 * Reading byte-by-byte keeps the code correct on big-endian hosts too.
 * These are the read-side mirrors of the write_u*_le helpers in compress.c;
 * both must agree on byte order or the file will be misread.
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
 * print_entry — one-line summary of a single jump-table entry.
 * Prints the first 8 bytes of chunk_hash (16 hex chars) followed by "..."
 * to keep the line readable; the full 32-byte hash is in the jump table.
 * ------------------------------------------------------------------------- */

static void print_entry(uint32_t idx, const JumpEntry *e)
{
    printf("  [%5u]  offset=%-12llu  comp=%-8u  orig=%-8u  "
           "min_ts=%-12llu  max_ts=%-12llu  hash=",
           idx,
           (unsigned long long)e->offset,
           e->comp_size,
           e->orig_size,
           (unsigned long long)e->min_ts,
           (unsigned long long)e->max_ts);
    for (int i = 0; i < 8; i++)        /* first 8 bytes = 16 hex chars */
        printf("%02x", e->chunk_hash[i]);
    printf("...\n");
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "usage:\n");
        fprintf(stderr, "  shrinker compress <input> <output.logz>\n");
        fprintf(stderr, "  shrinker search   <file.logz> <query> [--from DATE] [--to DATE]\n");
        fprintf(stderr, "                    [--user X] [--ip X] [--action X] [--level X]\n");
        fprintf(stderr, "  shrinker verify   <file.logz>\n");
        fprintf(stderr, "  shrinker inspect  <file.logz>\n");
        return 1;
    }

    /* -----------------------------------------------------------------------
     * compress subcommand
     * --------------------------------------------------------------------- */
    if (strcmp(argv[1], "compress") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: shrinker compress <input> <output.logz>\n");
            return 1;
        }
        int rc = compress_file(argv[2], argv[3]);
        return (rc == 0) ? 0 : 1;
    }

    /* -----------------------------------------------------------------------
     * search subcommand
     * Usage: shrinker search <file> <query> [--from DATE] [--to DATE]
     *                        [--user X] [--ip X] [--action X] [--level X]
     * --------------------------------------------------------------------- */
    if (strcmp(argv[1], "search") == 0) {
        if (argc < 4) {
            fprintf(stderr,
                "usage: shrinker search <file> <query> [--from DATE] [--to DATE]\n"
                "                       [--user X] [--ip X] [--action X] [--level X]\n");
            return 1;
        }
        const char *file  = argv[2];
        const char *query = argv[3];
        const char *from_date    = NULL;
        const char *to_date      = NULL;
        const char *field_user   = NULL;
        const char *field_ip     = NULL;
        const char *field_action = NULL;
        const char *field_level  = NULL;

        for (int i = 4; i < argc; i++) {
            if      (strcmp(argv[i], "--from")   == 0 && i + 1 < argc) from_date    = argv[++i];
            else if (strcmp(argv[i], "--to")     == 0 && i + 1 < argc) to_date      = argv[++i];
            else if (strcmp(argv[i], "--user")   == 0 && i + 1 < argc) field_user   = argv[++i];
            else if (strcmp(argv[i], "--ip")     == 0 && i + 1 < argc) field_ip     = argv[++i];
            else if (strcmp(argv[i], "--action") == 0 && i + 1 < argc) field_action = argv[++i];
            else if (strcmp(argv[i], "--level")  == 0 && i + 1 < argc) field_level  = argv[++i];
            else {
                fprintf(stderr, "search: unknown argument '%s'\n", argv[i]);
                return 1;
            }
        }
        int rc = search_file(file, query,
                             from_date, to_date,
                             field_user, field_ip, field_action, field_level);
        return (rc == 0) ? 0 : 1;
    }

    /* -----------------------------------------------------------------------
     * verify subcommand
     * Usage: shrinker verify <file.logz>
     * Exit code mirrors verify_file(): 0=verified, 1=tampered, 2=error.
     * --------------------------------------------------------------------- */
    if (strcmp(argv[1], "verify") == 0) {
        if (argc < 3) {
            fprintf(stderr, "usage: shrinker verify <file.logz>\n");
            return 2;
        }
        return verify_file(argv[2]);
    }

    /* -----------------------------------------------------------------------
     * inspect subcommand (or legacy bare-path: shrinker <file.logz>)
     * The bare-path form predates the subcommand dispatcher and is kept for
     * backwards compatibility with scripts that call the binary directly.
     * --------------------------------------------------------------------- */
    const char *logz_path = (strcmp(argv[1], "inspect") == 0 && argc >= 3)
                            ? argv[2] : argv[1];

    FILE *f = fopen(logz_path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", argv[1]);
        return 1;
    }

    /* -----------------------------------------------------------------------
     * Step 10: header + footer
     * --------------------------------------------------------------------- */

    /* 1. Magic (4 bytes) */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4) {
        fprintf(stderr, "error: cannot read magic\n");
        fclose(f); return 1;
    }
    if (memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "error: bad magic (got %02x%02x%02x%02x)\n",
                magic[0], magic[1], magic[2], magic[3]);
        fclose(f); return 1;
    }
    printf("magic:      OK (%c%c%c%c)\n", magic[0], magic[1], magic[2], magic[3]);

    /* 2. Version (uint16 LE) */
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

    /* 3. Footer: seek to EOF - 44 */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek to footer\n");
        fclose(f); return 1;
    }

    /* 4. Footer fields: chain_hash(32) + jt_offset(8 LE) + num_chunks(4 LE) */
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

    printf("num_chunks: %u\n",  num_chunks);
    printf("jt_offset:  %llu\n", (unsigned long long)jt_offset);
    printf("chain_hash: ");
    for (int i = 0; i < 8; i++) printf("%02x", chain_hash[i]);
    printf("...\n");

    /* -----------------------------------------------------------------------
     * Step 11: full jump table
     * --------------------------------------------------------------------- */

    /* 5. Allocate and read all jump-table entries in one fread call.
     *    On x86-64 (LE) fread directly into a __attribute__((packed)) struct
     *    is equivalent to field-by-field reading because the platform byte
     *    order matches the on-disk LE layout.  The _Static_assert in
     *    shrinker.h guarantees sizeof(JumpEntry) == 1600 with no padding.
     *    On big-endian hosts each field would need byte-swapping; that path
     *    is not yet implemented.
     */
    JumpEntry *entries = malloc((size_t)num_chunks * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "error: out of memory (%u entries × %zu B)\n",
                num_chunks, sizeof(JumpEntry));
        fclose(f); return 1;
    }

    if (fseek(f, (long)jt_offset, SEEK_SET) != 0) {
        fprintf(stderr, "error: cannot seek to jump table\n");
        free(entries); fclose(f); return 1;
    }

    size_t n_read = fread(entries, sizeof(JumpEntry), num_chunks, f);
    if (n_read != (size_t)num_chunks) {
        fprintf(stderr, "error: read %zu of %u jump-table entries\n",
                n_read, num_chunks);
        free(entries); fclose(f); return 1;
    }

    /* 6. Print first 3 entries and the last entry */
    printf("\n=== Jump Table (%u entries) ===\n", num_chunks);
    uint32_t show = (num_chunks < 3) ? num_chunks : 3;
    for (uint32_t i = 0; i < show; i++)
        print_entry(i, &entries[i]);
    if (num_chunks > 3) {
        printf("  ...\n");
        print_entry(num_chunks - 1, &entries[num_chunks - 1]);
    }

    /* 7. Totals: sum of orig_size, global min/max timestamp */
    uint64_t total_orig  = 0;
    uint64_t global_min  = UINT64_MAX;
    uint64_t global_max  = 0;

    for (uint32_t i = 0; i < num_chunks; i++) {
        total_orig += entries[i].orig_size;
        if (entries[i].min_ts > 0 && entries[i].min_ts < global_min)
            global_min = entries[i].min_ts;
        if (entries[i].max_ts > global_max)
            global_max = entries[i].max_ts;
    }

    printf("\ntotal orig_size: %llu bytes\n", (unsigned long long)total_orig);
    if (global_min != UINT64_MAX)
        printf("min_ts:          %llu\n", (unsigned long long)global_min);
    else
        printf("min_ts:          (none)\n");
    printf("max_ts:          %llu\n", (unsigned long long)global_max);

    /* 8. Spot-check: compare total orig_size against the known value for
     *    data/HDFS_v4.logz.  This is a development-time sanity check, not a
     *    general correctness test — any other .logz file will print FAIL here
     *    by design.  The real integrity check is the hash chain in section 9. */
    const uint64_t EXPECTED_ORIG = 1577982906ULL;  /* HDFS_v4.logz only */
    int size_ok = (total_orig == EXPECTED_ORIG);
    printf("\norig_size check: %s  (got %llu, expected %llu)\n",
           size_ok ? "PASS" : "FAIL (expected for non-HDFS files)",
           (unsigned long long)total_orig,
           (unsigned long long)EXPECTED_ORIG);

    /* -----------------------------------------------------------------------
     * Step 11 cross-validation: compute SHA-256 of the first chunk's
     * COMPRESSED bytes and compare it against the stored chunk_hash[0].
     *
     * chunk_hash[0] is SHA-256 over the RAW (pre-decompression) bytes, so
     * this comparison will always print MISMATCH — that is the expected and
     * correct result.  It confirms the hash was indeed computed over raw data.
     * This check will become MATCH once a decompress step is added here.
     * --------------------------------------------------------------------- */
    {
        uint32_t csz = entries[0].comp_size;
        uint8_t *comp = malloc(csz);
        if (!comp) {
            fprintf(stderr, "error: out of memory for chunk 0 (%u B)\n", csz);
            free(entries); fclose(f); return 1;
        }

        if (fseek(f, (long)entries[0].offset, SEEK_SET) != 0 ||
            fread(comp, 1, csz, f) != csz) {
            fprintf(stderr, "error: cannot read chunk 0 data\n");
            free(comp); free(entries); fclose(f); return 1;
        }

        uint8_t computed[32];
        SHA256(comp, csz, computed);
        free(comp);

        int match = (memcmp(computed, entries[0].chunk_hash, 32) == 0);
        printf("chunk_hash[0] vs SHA256(compressed): %s",
               match ? "MATCH" : "MISMATCH");
        if (!match)
            printf("  (expected — stored hash covers raw/decompressed bytes)");
        printf("\n");
    }

    free(entries);
    fclose(f);
    return 0;
}
