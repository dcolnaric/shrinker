/*
 * search.c — Shrinker C search (Phase 3 Step 13)
 *
 * Implements search_file(): reads a .logz file, applies three-layer chunk
 * skipping (time range → field bloom → main bloom), decompresses only the
 * chunks that pass all filters, then scans each line for the query string.
 *
 * Output is byte-compatible with the Python oracle in src/search.py.
 * Cross-validated on data/HDFS_v4.logz (see CLAUDE.md for numbers).
 */

#define _GNU_SOURCE            /* memmem(), timegm() */
#define _FILE_OFFSET_BITS 64   /* 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zstd.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian read helpers — mirrors of the write helpers in compress.c
 * and the read helpers in main.c.  Duplicated here to keep search.c
 * self-contained; factor to a shared util.c if a third caller appears.
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
 * Date parsing: "YYYY-MM-DD" → unix epoch (UTC).
 *
 * from_date uses midnight (00:00:00 UTC) and to_date uses end-of-day
 * (23:59:59 UTC), matching the Python _date_to_ts(end_of_day=True) logic
 * in search.py.  Returns 0 on parse failure (caller treats 0 as "no filter").
 * ------------------------------------------------------------------------- */

static uint64_t parse_date_ts(const char *s, int end_of_day)
{
    if (!s || !*s) return 0;
    struct tm tm = {0};
    char *ep = strptime(s, "%Y-%m-%d", &tm);
    if (!ep) return 0;
    if (end_of_day) {
        tm.tm_hour = 23;
        tm.tm_min  = 59;
        tm.tm_sec  = 59;
    }
    tm.tm_isdst = -1;  /* timegm ignores DST — always returns UTC */
    time_t t = timegm(&tm);
    return (t < 0) ? 0 : (uint64_t)t;
}

/* -------------------------------------------------------------------------
 * Bloom hash functions — must match compress.c and bloom.py exactly.
 * ------------------------------------------------------------------------- */

static uint32_t bloom_djb2(const uint8_t *data, size_t len)
{
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++)
        h = ((h << 5) + h) + (uint32_t)data[i];   /* h*33 + c  — standard djb2;
                                                     * matches Python bloom.py _djb2 */
    return h;
}

static uint32_t bloom_fnv1a(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261U;
    for (size_t i = 0; i < len; i++)
        h = (h ^ (uint32_t)data[i]) * 16777619U;
    return h;
}

static uint32_t bloom_sdbm(const uint8_t *data, size_t len)
{
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++)
        h = (uint32_t)data[i] + (h << 6) + (h << 16) - h;
    return h;
}

/* Returns 1 if token is *possibly* present in the filter, 0 if definitely
 * absent.  A missing bit gives a definitive false.  Used by both the main
 * bloom (8192 bits) and field bloom (4096 bits) — `bits` selects which. */
static int bloom_might_contain(const uint8_t *bf, uint32_t bits,
                               const uint8_t *token, size_t tlen)
{
    if (tlen == 0) return 0;
    uint32_t h1 = bloom_djb2 (token, tlen) % bits;
    uint32_t h2 = bloom_fnv1a(token, tlen) % bits;
    uint32_t h3 = bloom_sdbm (token, tlen) % bits;
    return ((bf[h1/8] >> (h1 % 8)) & 1) &&
           ((bf[h2/8] >> (h2 % 8)) & 1) &&
           ((bf[h3/8] >> (h3 % 8)) & 1);
}

/* -------------------------------------------------------------------------
 * Tokeniser — same delimiter set as compress.c and bloom.py.
 * Note: '=' is NOT a delimiter, so "user=admin" is one token in plain logs.
 * ------------------------------------------------------------------------- */

static int is_delim(uint8_t c)
{
    return c == ' ' || c == '"' || c == ':' || c == '\n' ||
           c == '\r' || c == '\t' || c == ',' || c == '{' ||
           c == '}' || c == '[' || c == ']';
}

/* Main bloom query: tokenise the query, then require ALL tokens present.
 *
 * Mirrors bloom.query_present() in bloom.py:
 *   tokens = [t for t in _TOKEN_RE.split(query_bytes) if t]
 *   if not tokens: tokens = [query_bytes]
 *   return all(_check_token(bf, t) for t in tokens)
 *
 * Returns 0 if query is definitely absent, 1 if possibly present. */
static int main_bloom_query(const uint8_t *bf,
                             const uint8_t *query, size_t qlen)
{
    int any_token = 0;
    size_t i = 0;
    while (i < qlen) {
        /* skip delimiters */
        while (i < qlen && is_delim(query[i])) i++;
        if (i >= qlen) break;
        size_t start = i;
        /* collect token */
        while (i < qlen && !is_delim(query[i])) i++;
        size_t tlen = i - start;
        if (tlen == 0) continue;
        any_token = 1;
        /* Any token definitely absent → whole query absent */
        if (!bloom_might_contain(bf, BLOOM_BYTES * 8, query + start, tlen))
            return 0;
    }
    /* No tokens after splitting → hash the entire query as one token */
    if (!any_token) {
        if (qlen == 0) return 0;
        return bloom_might_contain(bf, BLOOM_BYTES * 8, query, qlen);
    }
    return 1;  /* all tokens passed — query possibly present */
}

/* Field bloom query: hash full value with no tokenisation.
 *
 * Mirrors bloom.query_field_present() in bloom.py, which applies the three
 * hash functions directly to the full value bytes.  The field bloom was
 * built in the same way: Python compress.py calls bloom.build_field() which
 * also hashes full values.  C compress.c tokenises values, which is a known
 * inconsistency documented in CLAUDE.md; for Python-compressed files (all
 * test corpora) this function is correct.
 *
 * Returns 0 if value is definitely absent, 1 if possibly present. */
static int field_bloom_query(const uint8_t *fb,
                              const uint8_t *value, size_t vlen)
{
    return bloom_might_contain(fb, FIELD_BLOOM_BYTES * 8, value, vlen);
}

/* -------------------------------------------------------------------------
 * search_file — public API
 * ------------------------------------------------------------------------- */

int search_file(const char *logz_path, const char *query,
                const char *from_date, const char *to_date,
                const char *field_user, const char *field_ip,
                const char *field_action, const char *field_level)
{
    /* Parse date filters; 0 = "not set" sentinel */
    uint64_t from_ts = from_date ? parse_date_ts(from_date, 0) : 0;
    uint64_t to_ts   = to_date   ? parse_date_ts(to_date,   1) : 0;

    /* Collect active field filters into a flat array for the inner loop */
    const char *field_vals[4];
    int n_fields = 0;
    if (field_user)   field_vals[n_fields++] = field_user;
    if (field_ip)     field_vals[n_fields++] = field_ip;
    if (field_action) field_vals[n_fields++] = field_action;
    if (field_level)  field_vals[n_fields++] = field_level;

    const uint8_t *query_bytes = (const uint8_t *)query;
    size_t         query_len   = strlen(query);

    /* ---------------------------------------------------------------------- */
    FILE *f = fopen(logz_path, "rb");
    if (!f) {
        fprintf(stderr, "search: cannot open '%s'\n", logz_path);
        return 1;
    }

    /* --- 1. Validate MAGIC (4 bytes) --- */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "search: bad magic (not a .logz file)\n");
        fclose(f); return 1;
    }

    /* --- 2. Validate VERSION (uint16 LE) --- */
    uint16_t version;
    if (read_u16_le(f, &version) != 0) {
        fprintf(stderr, "search: cannot read version\n");
        fclose(f); return 1;
    }
    if (version != VERSION) {
        fprintf(stderr, "search: unsupported version %u (expected %u)\n",
                version, VERSION);
        fclose(f); return 1;
    }

    /* --- 3. Skip FORMAT byte (byte 6) --- */
    uint8_t fmt_byte;
    if (fread(&fmt_byte, 1, 1, f) != 1) {
        fprintf(stderr, "search: cannot read format byte\n");
        fclose(f); return 1;
    }

    /* --- 4. Read dictionary: DICT_LEN (4 bytes LE) + DICT_DATA --- */
    uint32_t dict_len;
    if (read_u32_le(f, &dict_len) != 0) {
        fprintf(stderr, "search: cannot read dict_len\n");
        fclose(f); return 1;
    }

    uint8_t    *dict_buf = NULL;
    ZSTD_DDict *ddict    = NULL;

    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf) {
            fprintf(stderr, "search: OOM for dictionary (%u bytes)\n", dict_len);
            fclose(f); return 1;
        }
        if (fread(dict_buf, 1, dict_len, f) != dict_len) {
            fprintf(stderr, "search: short read on dictionary\n");
            free(dict_buf); fclose(f); return 1;
        }
        ddict = ZSTD_createDDict(dict_buf, dict_len);
        if (!ddict) {
            fprintf(stderr, "search: ZSTD_createDDict failed\n");
            free(dict_buf); fclose(f); return 1;
        }
    }

    /* --- 5. Read footer at EOF-44: chain_hash(32) + jt_offset(8) + num_chunks(4) --- */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "search: cannot seek to footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    uint8_t  chain_hash[32];   /* not needed for search but consumed from stream */
    uint64_t jt_offset;
    uint32_t num_chunks;

    if (fread(chain_hash, 1, 32, f) != 32 ||
        read_u64_le(f, &jt_offset) != 0    ||
        read_u32_le(f, &num_chunks) != 0) {
        fprintf(stderr, "search: cannot read footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* --- 6. Read full jump table into memory --- */
    JumpEntry *entries = (JumpEntry *)malloc((size_t)num_chunks * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "search: OOM for jump table (%u entries × %zu B)\n",
                num_chunks, sizeof(JumpEntry));
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    if (fseek(f, (long)jt_offset, SEEK_SET) != 0) {
        fprintf(stderr, "search: cannot seek to jump table offset %llu\n",
                (unsigned long long)jt_offset);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* On x86-64 (LE) we can fread the packed struct directly — the platform
     * byte order matches the on-disk LE layout.  The _Static_assert in
     * shrinker.h guarantees sizeof(JumpEntry) == 1600 with no padding. */
    size_t n_read = fread(entries, sizeof(JumpEntry), num_chunks, f);
    if (n_read != (size_t)num_chunks) {
        fprintf(stderr, "search: read %zu of %u jump-table entries\n",
                n_read, num_chunks);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* --- 7. Prepare decompression context and buffers --- */
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) {
        fprintf(stderr, "search: ZSTD_createDCtx failed\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* Pre-allocate buffers at worst-case sizes:
     *   comp_buf: ZSTD_compressBound(CHUNK_SIZE) covers the largest possible
     *             compressed chunk (incompressible input pads slightly).
     *   raw_buf:  CHUNK_SIZE — chunks are at most 64 KB before compression.
     * Both grow dynamically if an unexpectedly large chunk is encountered
     * (e.g. a file from a future version that changed CHUNK_SIZE). */
    size_t comp_cap = ZSTD_compressBound(CHUNK_SIZE);
    size_t raw_cap  = CHUNK_SIZE;
    uint8_t *comp_buf = (uint8_t *)malloc(comp_cap);
    uint8_t *raw_buf  = (uint8_t *)malloc(raw_cap);
    if (!comp_buf || !raw_buf) {
        fprintf(stderr, "search: OOM for chunk buffers\n");
        free(comp_buf); free(raw_buf);
        ZSTD_freeDCtx(dctx);
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* --- 8. Main search loop with three-layer skip --- */
    uint64_t matches          = 0;
    uint32_t chunks_scanned   = 0;
    uint32_t skipped_by_time  = 0;
    uint32_t skipped_by_field = 0;
    uint32_t skipped_by_bloom = 0;

    for (uint32_t i = 0; i < num_chunks; i++) {
        JumpEntry *e = &entries[i];

        /* ------------------------------------------------------------------
         * Layer 1 — Time-range skip (cheapest: two integer comparisons).
         *
         * A chunk is skipped only when it has timestamps (min_ts or max_ts
         * non-zero) AND the chunk's window is entirely outside [from, to].
         * Chunks with no timestamps are always passed through — safe, not
         * lazy: we cannot assert time content for TS-free formats.
         *
         * Mirrors the Python logic in search.py _search():
         *   has_ts = (min_ts != 0 or max_ts != 0)
         *   if has_ts:
         *     if from_ts and max_ts < from_ts: skip
         *     if to_ts   and min_ts > to_ts:   skip
         * ------------------------------------------------------------------ */
        if (from_date || to_date) {
            int has_ts = (e->min_ts != 0 || e->max_ts != 0);
            if (has_ts) {
                if (from_date && e->max_ts < from_ts) { skipped_by_time++; continue; }
                if (to_date   && e->min_ts > to_ts)   { skipped_by_time++; continue; }
            }
        }

        /* ------------------------------------------------------------------
         * Layer 2 — Field bloom skip.
         *
         * Only active when:
         *   (a) at least one --user/--ip/--action/--level filter was given, AND
         *   (b) this chunk's field_bloom is non-zero (JSON logs only; syslog
         *       and plaintext store all zeros as a sentinel meaning "no field
         *       index", so they are not field-skipped — search.py: any(field_bloom))
         *
         * AND logic: if ANY requested value is definitively absent from the
         * bloom, the whole chunk is skipped.
         * ------------------------------------------------------------------ */
        if (n_fields > 0) {
            int fb_nonzero = 0;
            for (int j = 0; j < FIELD_BLOOM_BYTES; j++) {
                if (e->field_bloom[j]) { fb_nonzero = 1; break; }
            }
            if (fb_nonzero) {
                int skip = 0;
                for (int j = 0; j < n_fields && !skip; j++) {
                    const uint8_t *fv  = (const uint8_t *)field_vals[j];
                    size_t         fvl = strlen(field_vals[j]);
                    if (!field_bloom_query(e->field_bloom, fv, fvl))
                        skip = 1;
                }
                if (skip) { skipped_by_field++; continue; }
            }
        }

        /* ------------------------------------------------------------------
         * Layer 3 — Main bloom skip.
         *
         * Tokenises the query string and checks that every token is present
         * in the 1024-byte (8192-bit) bloom.  A missing bit is a definitive
         * negative — no false negatives, only false positives.
         * ------------------------------------------------------------------ */
        /* Main bloom: only active for non-empty queries.
         * An empty query (field-filter-only search) skips this layer so
         * every chunk that passes time/field filters is decompressed. */
        if (query_len > 0 && !main_bloom_query(e->bloom, query_bytes, query_len)) {
            skipped_by_bloom++;
            continue;
        }

        /* ------------------------------------------------------------------
         * All three layers passed — decompress and grep.
         * ------------------------------------------------------------------ */
        chunks_scanned++;

        /* Grow buffers if a chunk turns out to be larger than our pre-allocation
         * (should only happen for files with a different CHUNK_SIZE). */
        if (e->comp_size > comp_cap) {
            free(comp_buf);
            comp_cap  = (size_t)e->comp_size * 2;
            comp_buf  = (uint8_t *)malloc(comp_cap);
            if (!comp_buf) {
                fprintf(stderr, "search: OOM growing comp_buf\n");
                goto cleanup;
            }
        }
        if (e->orig_size > raw_cap) {
            free(raw_buf);
            raw_cap = (size_t)e->orig_size;
            raw_buf = (uint8_t *)malloc(raw_cap);
            if (!raw_buf) {
                fprintf(stderr, "search: OOM growing raw_buf\n");
                goto cleanup;
            }
        }

        /* Seek to chunk position and read compressed bytes */
        if (fseek(f, (long)e->offset, SEEK_SET) != 0 ||
            fread(comp_buf, 1, e->comp_size, f) != e->comp_size) {
            fprintf(stderr, "search: cannot read chunk %u (offset=%llu, size=%u)\n",
                    i, (unsigned long long)e->offset, e->comp_size);
            goto cleanup;
        }

        /* Decompress */
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
            fprintf(stderr, "search: decompression error on chunk %u: %s\n",
                    i, ZSTD_getErrorName(dec_size));
            goto cleanup;
        }

        /* Quick full-chunk check: handle bloom false positives cheaply.
         * Skipped when query is empty (field-filter-only) — no needle to find. */
        if (query_len > 0 &&
            memmem(raw_buf, dec_size, query_bytes, query_len) == NULL)
            continue;

        /* Scan line by line and print matches */
        const uint8_t *p   = raw_buf;
        const uint8_t *end = raw_buf + dec_size;
        while (p < end) {
            const uint8_t *nl = (const uint8_t *)
                memchr(p, '\n', (size_t)(end - p));
            size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

            /* When query is empty, every non-empty line matches. */
            if (line_len > 0 &&
                (query_len == 0 ||
                 memmem(p, line_len, query_bytes, query_len) != NULL)) {
                fwrite(p, 1, line_len, stdout);
                fputc('\n', stdout);
                matches++;
            }
            p = nl ? nl + 1 : end;
        }
    }

    /* --- 9. Stats to stderr (mirrors search.py format exactly) --- */
    fprintf(stderr,
            "Matches: %llu  |  Chunks scanned: %u / %u"
            "  |  Skipped by time: %u"
            "  |  Skipped by field: %u"
            "  |  Skipped by bloom: %u\n",
            (unsigned long long)matches,
            chunks_scanned, num_chunks,
            skipped_by_time,
            skipped_by_field,
            skipped_by_bloom);

    free(comp_buf);
    free(raw_buf);
    ZSTD_freeDCtx(dctx);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(f);
    return 0;

cleanup:
    free(comp_buf);
    free(raw_buf);
    ZSTD_freeDCtx(dctx);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(f);
    return 1;
}
