/*
 * append.c — Shrinker append mode (Phase 3 Step 21)
 *
 * append_file(): append new log entries to an existing .logz archive,
 * extending the hash chain and jump table in-place.
 *
 * If the archive does not exist, delegates to compress_file() to create
 * a fresh archive — making "append" a strict superset of "compress".
 *
 * Append protocol:
 *   1. Open the archive for read+write.  If the file is absent, fall back
 *      to compress_file() and return early.
 *   2. Read and validate the header (magic, version, format byte, dict).
 *   3. Seek to EOF-FOOTER_SIZE to read:
 *        chain_hash (32 B) — seed for the new chunk hash chain
 *        jt_offset  ( 8 B) — byte offset of the existing jump table
 *        num_chunks ( 4 B) — number of existing chunks
 *   4. Load the existing jump table (num_chunks × JumpEntry) into memory.
 *   5. Truncate the file at jt_offset — strips the old jump table + footer.
 *   6. Write new compressed chunks starting at jt_offset, using the
 *      existing dict (so all chunks in the archive share the same dict)
 *      and continuing the hash chain from chain_hash.
 *   7. Write the combined jump table: old entries first, then new entries.
 *      Old entries are still valid (their offset fields still point to the
 *      unchanged compressed chunks before jt_offset).
 *   8. Write the new footer: updated chain_hash, jt_offset, total chunks.
 *
 * Cross-validated: verify() passes on the result with full chain continuity.
 */

#define _GNU_SOURCE          /* timegm() — POSIX extension, not C99 */
#define _FILE_OFFSET_BITS 64 /* 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <unistd.h>          /* ftruncate, fileno */
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <zstd.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian write helpers — identical to compress.c.
 * ------------------------------------------------------------------------- */

static void ap_write_u32_le(FILE *f, uint32_t v)
{
    uint8_t b[4] = {
        (uint8_t)(v & 0xFF),
        (uint8_t)((v >>  8) & 0xFF),
        (uint8_t)((v >> 16) & 0xFF),
        (uint8_t)((v >> 24) & 0xFF)
    };
    fwrite(b, 1, 4, f);
}

static void ap_write_u64_le(FILE *f, uint64_t v)
{
    uint8_t b[8] = {
        (uint8_t)(v & 0xFF),
        (uint8_t)((v >>  8) & 0xFF),
        (uint8_t)((v >> 16) & 0xFF),
        (uint8_t)((v >> 24) & 0xFF),
        (uint8_t)((v >> 32) & 0xFF),
        (uint8_t)((v >> 40) & 0xFF),
        (uint8_t)((v >> 48) & 0xFF),
        (uint8_t)((v >> 56) & 0xFF)
    };
    fwrite(b, 1, 8, f);
}

/* -------------------------------------------------------------------------
 * Little-endian read helpers — identical to verify.c / search.c.
 * ------------------------------------------------------------------------- */

static int ap_read_u16_le(FILE *f, uint16_t *out)
{
    uint8_t b[2];
    if (fread(b, 1, 2, f) != 2) return -1;
    *out = (uint16_t)(b[0] | ((uint16_t)b[1] << 8));
    return 0;
}

static int ap_read_u32_le(FILE *f, uint32_t *out)
{
    uint8_t b[4];
    if (fread(b, 1, 4, f) != 4) return -1;
    *out = (uint32_t)b[0]
         | ((uint32_t)b[1] <<  8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
    return 0;
}

static int ap_read_u64_le(FILE *f, uint64_t *out)
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
 * Bloom hash functions — identical to compress.c (must match Python bloom.py).
 * djb2: h = h*33 + c  (ADD variant — NOT XOR)
 * ------------------------------------------------------------------------- */

static uint32_t ap_bloom_djb2(const uint8_t *data, size_t len)
{
    uint32_t h = 5381;
    for (size_t i = 0; i < len; i++)
        h = ((h << 5) + h) + (uint32_t)data[i];   /* h*33 + c */
    return h;
}

static uint32_t ap_bloom_fnv1a(const uint8_t *data, size_t len)
{
    uint32_t h = 2166136261U;
    for (size_t i = 0; i < len; i++)
        h = (h ^ (uint32_t)data[i]) * 16777619U;
    return h;
}

static uint32_t ap_bloom_sdbm(const uint8_t *data, size_t len)
{
    uint32_t h = 0;
    for (size_t i = 0; i < len; i++)
        h = (uint32_t)data[i] + (h << 6) + (h << 16) - h;
    return h;
}

static void ap_bloom_add(uint8_t *bf, uint32_t bits,
                         const uint8_t *token, size_t tlen)
{
    if (tlen == 0) return;
    uint32_t h1 = ap_bloom_djb2 (token, tlen) % bits;
    uint32_t h2 = ap_bloom_fnv1a(token, tlen) % bits;
    uint32_t h3 = ap_bloom_sdbm (token, tlen) % bits;
    bf[h1 / 8] |= (uint8_t)(1u << (h1 % 8));
    bf[h2 / 8] |= (uint8_t)(1u << (h2 % 8));
    bf[h3 / 8] |= (uint8_t)(1u << (h3 % 8));
}

/* -------------------------------------------------------------------------
 * Tokeniser — splits raw bytes on: space, ", :, \n, \r, \t, ,, {, }, [, ]
 * Matches the Python regex: re.split(r'[ ":\n\r\t,{}\[\]]+', ...)
 * Note: '=' is NOT a delimiter.
 * ------------------------------------------------------------------------- */

typedef void (*ap_token_cb)(const uint8_t *tok, size_t tlen, void *ud);

static int ap_is_delim(uint8_t c)
{
    return c == ' ' || c == '"' || c == ':' || c == '\n' ||
           c == '\r' || c == '\t' || c == ',' || c == '{' ||
           c == '}' || c == '[' || c == ']';
}

static void ap_tokenise(const uint8_t *data, size_t len,
                        ap_token_cb cb, void *ud)
{
    size_t i = 0;
    while (i < len) {
        while (i < len && ap_is_delim(data[i])) i++;
        if (i >= len) break;
        size_t start = i;
        while (i < len && !ap_is_delim(data[i])) i++;
        cb(data + start, i - start, ud);
    }
}

/* -------------------------------------------------------------------------
 * Main bloom filter (1024 bytes = 8192 bits).
 * ------------------------------------------------------------------------- */

static void _ap_add_token_main(const uint8_t *tok, size_t tlen, void *ud)
{
    ap_bloom_add((uint8_t *)ud, BLOOM_BYTES * 8, tok, tlen);
}

static void ap_build_main_bloom(uint8_t *bf,
                                const uint8_t *raw, size_t len)
{
    memset(bf, 0, BLOOM_BYTES);
    ap_tokenise(raw, len, _ap_add_token_main, bf);
}

/* -------------------------------------------------------------------------
 * JSON field value extractor — lightweight scanner (same logic as compress.c).
 * ------------------------------------------------------------------------- */

static const char *ap_json_find_value(const char *line, size_t line_len,
                                      const char *key, size_t *vlen_out)
{
    size_t klen = strlen(key);
    const char *p   = line;
    const char *end = line + line_len;

    while (p < end) {
        const char *q = memchr(p, '"', (size_t)(end - p));
        if (!q) break;
        q++;
        if (q + klen + 1 <= end &&
            memcmp(q, key, klen) == 0 && q[klen] == '"') {
            const char *v = q + klen + 1;
            while (v < end && (*v == ' ' || *v == '\t')) v++;
            if (v >= end || *v != ':') { p = q; continue; }
            v++;
            while (v < end && (*v == ' ' || *v == '\t')) v++;
            if (v >= end) break;

            if (*v == '"') {
                v++;
                const char *vs = v;
                while (v < end && *v != '"' && *v != '\n') v++;
                *vlen_out = (size_t)(v - vs);
                return vs;
            } else if (isdigit((unsigned char)*v) || *v == '-') {
                const char *vs = v;
                while (v < end && (isdigit((unsigned char)*v) ||
                                   *v == '.' || *v == '-')) v++;
                *vlen_out = (size_t)(v - vs);
                return vs;
            }
        }
        p = q;
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Field bloom filter (512 bytes = 4096 bits).
 * Keys: user, user_id, username, ip, ip_address, action, level, severity
 * Zero bytes for non-JSON (sentinel: "no field index").
 * ------------------------------------------------------------------------- */

static const char *AP_FIELD_KEYS[] = {
    "user", "user_id", "username",
    "ip", "ip_address",
    "action",
    "level", "severity",
    NULL
};

typedef struct { uint8_t *fb; } ApFieldBloomUD;

static void _ap_add_token_field(const uint8_t *tok, size_t tlen, void *ud)
{
    ap_bloom_add(((ApFieldBloomUD *)ud)->fb, FIELD_BLOOM_BYTES * 8, tok, tlen);
}

static void ap_build_field_bloom(uint8_t *fb,
                                 const uint8_t *raw, size_t raw_len,
                                 int fmt)
{
    memset(fb, 0, FIELD_BLOOM_BYTES);
    if (fmt != FORMAT_JSON) return;

    const char *p   = (const char *)raw;
    const char *end = p + raw_len;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

        for (int ki = 0; AP_FIELD_KEYS[ki] != NULL; ki++) {
            size_t vlen = 0;
            const char *v = ap_json_find_value(p, line_len,
                                               AP_FIELD_KEYS[ki], &vlen);
            if (v && vlen > 0) {
                ApFieldBloomUD ud = { fb };
                ap_tokenise((const uint8_t *)v, vlen, _ap_add_token_field, &ud);
            }
        }
        p = nl ? nl + 1 : end;
    }
}

/* -------------------------------------------------------------------------
 * Timestamp parsing — identical to compress.c.
 * ------------------------------------------------------------------------- */

static const char *AP_TS_KEYS[] = {
    "timestamp", "time", "ts", "@timestamp", NULL
};

static uint64_t ap_parse_iso8601(const char *s, size_t slen)
{
    if (slen < 10) return 0;
    char buf[32];
    size_t n = slen < 25 ? slen : 25;
    memcpy(buf, s, n);
    buf[n] = '\0';
    for (size_t i = 0; i < n; i++)
        if (buf[i] == 'T') buf[i] = ' ';
    struct tm tm = {0};
    char *end = strptime(buf, "%Y-%m-%d %H:%M:%S", &tm);
    if (!end) end = strptime(buf, "%Y-%m-%d", &tm);
    if (!end) return 0;
    tm.tm_isdst = -1;
    time_t t = timegm(&tm);
    return (t < 0) ? 0 : (uint64_t)t;
}

static uint64_t ap_parse_numeric_ts(const char *s, size_t slen)
{
    if (slen == 0 || slen > 20) return 0;
    char buf[24];
    memcpy(buf, s, slen);
    buf[slen] = '\0';
    char *endp;
    double v = strtod(buf, &endp);
    if (endp == buf) return 0;
    if (v < 1e9 || v > 9e9) return 0;
    return (uint64_t)v;
}

static const char *AP_MONTHS[] = {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
};

static uint64_t ap_parse_syslog_ts(const char *line, size_t line_len)
{
    if (line_len < 15) return 0;
    char buf[20];
    memcpy(buf, line, 15);
    buf[15] = '\0';
    char mon[4]; int day, hh, mm, ss;
    if (sscanf(buf, "%3s %d %d:%d:%d", mon, &day, &hh, &mm, &ss) != 5)
        return 0;
    int month = -1;
    for (int i = 0; i < 12; i++)
        if (strcmp(mon, AP_MONTHS[i]) == 0) { month = i; break; }
    if (month < 0) return 0;
    time_t now = time(NULL);
    struct tm *lt = localtime(&now);
    struct tm tm = {0};
    tm.tm_year  = lt->tm_year;
    tm.tm_mon   = month;
    tm.tm_mday  = day;
    tm.tm_hour  = hh;
    tm.tm_min   = mm;
    tm.tm_sec   = ss;
    tm.tm_isdst = -1;
    time_t t = timegm(&tm);
    return (t < 0) ? 0 : (uint64_t)t;
}

static void ap_extract_timestamps(const uint8_t *raw, size_t raw_len, int fmt,
                                   uint64_t *min_ts, uint64_t *max_ts)
{
    *min_ts = 0;
    *max_ts = 0;
    uint64_t lo = UINT64_MAX, hi = 0;
    int found = 0;

    const char *p   = (const char *)raw;
    const char *end = p + raw_len;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        uint64_t ts = 0;

        if (fmt == FORMAT_JSON) {
            for (int ki = 0; AP_TS_KEYS[ki] != NULL && ts == 0; ki++) {
                size_t vlen = 0;
                const char *v = ap_json_find_value(p, line_len,
                                                    AP_TS_KEYS[ki], &vlen);
                if (!v || vlen == 0) continue;
                ts = ap_parse_iso8601(v, vlen);
                if (!ts) ts = ap_parse_numeric_ts(v, vlen);
            }
        } else if (fmt == FORMAT_SYSLOG) {
            ts = ap_parse_syslog_ts(p, line_len);
        }

        if (ts) {
            if (ts < lo) lo = ts;
            if (ts > hi) hi = ts;
            found = 1;
        }
        p = nl ? nl + 1 : end;
    }
    if (found) { *min_ts = lo; *max_ts = hi; }
}

/* -------------------------------------------------------------------------
 * Write one jump-table entry in explicit LE byte order (same as compress.c).
 * Total: 8+4+4+1024+32+8+8+512 = 1600 bytes.
 * ------------------------------------------------------------------------- */

static void ap_write_jump_entry(FILE *fout, const JumpEntry *e)
{
    ap_write_u64_le(fout, e->offset);
    ap_write_u32_le(fout, e->comp_size);
    ap_write_u32_le(fout, e->orig_size);
    fwrite(e->bloom,       1, BLOOM_BYTES,       fout);
    fwrite(e->chunk_hash,  1, 32,                fout);
    ap_write_u64_le(fout, e->min_ts);
    ap_write_u64_le(fout, e->max_ts);
    fwrite(e->field_bloom, 1, FIELD_BLOOM_BYTES, fout);
}

/* -------------------------------------------------------------------------
 * append_file — public API
 *
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */

int append_file(const char *input_path, const char *archive_path,
                int format_override)
{
    /* -----------------------------------------------------------------------
     * 1. Try to open the archive for read+write.
     *    If the file does not exist, fall back to compress_file() to create
     *    a fresh archive.
     * --------------------------------------------------------------------- */
    FILE *f = fopen(archive_path, "r+b");
    if (!f) {
        /* File absent (or unreadable) — create a new archive */
        fprintf(stderr, "append: archive not found — creating new archive\n");
        return compress_file(input_path, archive_path, format_override);
    }

    /* -----------------------------------------------------------------------
     * 2. Read and validate the existing header.
     *    We reuse the format byte and dictionary from the archive so that all
     *    chunks (old and new) are compressed with the same parameters.
     * --------------------------------------------------------------------- */

    /* 2a. Magic */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "append: not a .logz file (bad magic)\n");
        fclose(f); return -1;
    }

    /* 2b. Version */
    uint16_t version;
    if (ap_read_u16_le(f, &version) != 0) {
        fprintf(stderr, "append: cannot read version\n");
        fclose(f); return -1;
    }
    if (version != VERSION) {
        fprintf(stderr, "append: unsupported version %u (expected %u)\n",
                version, (unsigned)VERSION);
        fclose(f); return -1;
    }

    /* 2c. Format byte — determines bloom tokenisation, field extraction,
     *     and timestamp parsing for all chunks in this archive.
     *     We use the stored format for new chunks, ignoring format_override. */
    uint8_t fmt_byte;
    if (fread(&fmt_byte, 1, 1, f) != 1) {
        fprintf(stderr, "append: cannot read format byte\n");
        fclose(f); return -1;
    }
    int fmt = (int)fmt_byte;

    /* 2d. Dictionary length + data */
    uint32_t dict_len;
    if (ap_read_u32_le(f, &dict_len) != 0) {
        fprintf(stderr, "append: cannot read dict_len\n");
        fclose(f); return -1;
    }

    uint8_t *dict_buf = NULL;
    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf) {
            fprintf(stderr, "append: OOM for dict (%u bytes)\n", dict_len);
            fclose(f); return -1;
        }
        if (fread(dict_buf, 1, dict_len, f) != dict_len) {
            fprintf(stderr, "append: short read on dict\n");
            free(dict_buf); fclose(f); return -1;
        }
    }

    /* -----------------------------------------------------------------------
     * 3. Read footer: chain_hash, jt_offset, num_old_chunks.
     *    chain_hash is the seed for the new hash chain — the first new chunk
     *    hashes as SHA256(chain_hash || raw_bytes).
     * --------------------------------------------------------------------- */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "append: cannot seek to footer\n");
        free(dict_buf); fclose(f); return -1;
    }

    uint8_t  seed_hash[32];
    uint64_t jt_offset;
    uint32_t num_old_chunks;

    if (fread(seed_hash, 1, 32, f) != 32  ||
        ap_read_u64_le(f, &jt_offset) != 0 ||
        ap_read_u32_le(f, &num_old_chunks) != 0) {
        fprintf(stderr, "append: cannot read footer\n");
        free(dict_buf); fclose(f); return -1;
    }

    /* -----------------------------------------------------------------------
     * 4. Load the existing jump table into memory.
     *    We need it so we can re-write it after appending new chunks.
     *    The offset fields in old entries remain correct: those chunks are
     *    still at their original positions in the file (we only truncate
     *    at jt_offset, after all the chunk data).
     * --------------------------------------------------------------------- */
    JumpEntry *old_entries = NULL;
    if (num_old_chunks > 0) {
        old_entries = (JumpEntry *)malloc(
            (size_t)num_old_chunks * sizeof(JumpEntry));
        if (!old_entries) {
            fprintf(stderr, "append: OOM for old jump table (%u entries)\n",
                    num_old_chunks);
            free(dict_buf); fclose(f); return -1;
        }
        if (fseek(f, (long)jt_offset, SEEK_SET) != 0) {
            fprintf(stderr, "append: cannot seek to jump table\n");
            free(old_entries); free(dict_buf); fclose(f); return -1;
        }
        size_t n_read = fread(old_entries, sizeof(JumpEntry),
                              num_old_chunks, f);
        if (n_read != (size_t)num_old_chunks) {
            fprintf(stderr,
                    "append: read %zu of %u jump-table entries\n",
                    n_read, num_old_chunks);
            free(old_entries); free(dict_buf); fclose(f); return -1;
        }
    }

    /* -----------------------------------------------------------------------
     * 5. Truncate the file at jt_offset — removes the old jump table and
     *    footer so we can write new chunks right after the existing chunks.
     *    Then seek to jt_offset to start writing.
     * --------------------------------------------------------------------- */
    if (ftruncate(fileno(f), (off_t)jt_offset) != 0) {
        fprintf(stderr, "append: ftruncate failed\n");
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }
    if (fseek(f, (long)jt_offset, SEEK_SET) != 0) {
        fprintf(stderr, "append: cannot seek to append position\n");
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }

    /* -----------------------------------------------------------------------
     * 6. Set up compression context using the existing dictionary.
     *    Using the same dict for new chunks is required for correctness:
     *    the dict is stored once in the header and must match all chunks.
     * --------------------------------------------------------------------- */
    ZSTD_CDict *cdict   = NULL;
    int         use_dict = 0;

    if (dict_len > 0 && dict_buf) {
        cdict = ZSTD_createCDict(dict_buf, dict_len, 3);
        if (cdict) {
            use_dict = 1;
        } else {
            fprintf(stderr,
                    "append: ZSTD_createCDict failed — compressing without dict\n");
        }
    }

    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    if (!cctx) {
        fprintf(stderr, "append: ZSTD_createCCtx failed\n");
        if (cdict) ZSTD_freeCDict(cdict);
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }

    /* -----------------------------------------------------------------------
     * 7. Open input file and get its size for stats.
     * --------------------------------------------------------------------- */
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        fprintf(stderr, "append: cannot open input '%s'\n", input_path);
        ZSTD_freeCCtx(cctx);
        if (cdict) ZSTD_freeCDict(cdict);
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }

    if (fseek(fin, 0, SEEK_END) != 0) {
        fprintf(stderr, "append: fseek on input failed\n");
        fclose(fin);
        ZSTD_freeCCtx(cctx);
        if (cdict) ZSTD_freeCDict(cdict);
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }
    long in_size_l = ftell(fin);
    uint64_t in_size = (in_size_l > 0) ? (uint64_t)in_size_l : 0;
    rewind(fin);

    /* -----------------------------------------------------------------------
     * 8. Allocate working buffers and new jump-table array.
     * --------------------------------------------------------------------- */
    uint8_t *raw_buf    = (uint8_t *)malloc(CHUNK_SIZE);
    size_t   comp_bound = ZSTD_compressBound(CHUNK_SIZE);
    uint8_t *comp_buf   = (uint8_t *)malloc(comp_bound);

    uint32_t   new_cap     = 256;
    uint32_t   new_n       = 0;
    JumpEntry *new_entries = (JumpEntry *)malloc(
        (size_t)new_cap * sizeof(JumpEntry));

    if (!raw_buf || !comp_buf || !new_entries) {
        fprintf(stderr, "append: OOM for working buffers\n");
        free(raw_buf); free(comp_buf); free(new_entries);
        fclose(fin);
        ZSTD_freeCCtx(cctx);
        if (cdict) ZSTD_freeCDict(cdict);
        free(old_entries); free(dict_buf); fclose(f); return -1;
    }

    /* -----------------------------------------------------------------------
     * 9. Hash chain initialisation.
     *
     *    If the archive already has chunks (num_old_chunks > 0), the first
     *    new chunk chains from the existing footer chain_hash:
     *       new_chunk_0 = SHA256(seed_hash || raw)
     *
     *    If the archive is empty (num_old_chunks == 0), the first new chunk
     *    has no predecessor — it hashes as a fresh chunk 0:
     *       new_chunk_0 = SHA256(raw)
     *
     *    This matches Python compress.py behaviour (prev_hash = None for
     *    chunk 0).
     * --------------------------------------------------------------------- */
    uint8_t prev_hash[32];
    memcpy(prev_hash, seed_hash, 32);
    int has_prev = (num_old_chunks > 0);

    /* Track the write position for chunk offset recording */
    uint64_t out_offset = jt_offset;

    /* -----------------------------------------------------------------------
     * 10. Main compression loop — identical logic to compress.c step 7,
     *     except we don't start the hash chain from zero.
     * --------------------------------------------------------------------- */
    int cleanup_rc = -1;

    size_t raw_len;
    while ((raw_len = fread(raw_buf, 1, CHUNK_SIZE, fin)) > 0) {

        /* Grow new_entries array if needed */
        if (new_n == new_cap) {
            new_cap *= 2;
            JumpEntry *tmp = (JumpEntry *)realloc(new_entries,
                                                   (size_t)new_cap * sizeof(JumpEntry));
            if (!tmp) {
                fprintf(stderr, "append: OOM growing new jump table\n");
                goto cleanup;
            }
            new_entries = tmp;
        }

        JumpEntry *e = &new_entries[new_n];
        e->offset    = out_offset;
        e->orig_size = (uint32_t)raw_len;

        /* 10a. Main bloom filter */
        ap_build_main_bloom(e->bloom, raw_buf, raw_len);

        /* 10b. Field bloom filter */
        ap_build_field_bloom(e->field_bloom, raw_buf, raw_len, fmt);

        /* 10c. SHA-256 hash chain over RAW bytes.
         *      chunk 0 (or first appended chunk with has_prev=0): SHA256(raw)
         *      all others: SHA256(prev_hash || raw)
         */
        {
            uint8_t hash_out[32];
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
            if (has_prev)
                EVP_DigestUpdate(mdctx, prev_hash, 32);
            EVP_DigestUpdate(mdctx, raw_buf, raw_len);
            unsigned int mdlen = 32;
            EVP_DigestFinal_ex(mdctx, hash_out, &mdlen);
            EVP_MD_CTX_free(mdctx);
            memcpy(e->chunk_hash, hash_out, 32);
            memcpy(prev_hash,     hash_out, 32);
            has_prev = 1;
        }

        /* 10d. Timestamp extraction */
        {
            uint64_t min_ts = 0, max_ts = 0;
            ap_extract_timestamps(raw_buf, raw_len, fmt, &min_ts, &max_ts);
            e->min_ts = min_ts;
            e->max_ts = max_ts;
        }

        /* 10e. Compress the raw chunk */
        size_t comp_size;
        if (use_dict && cdict) {
            comp_size = ZSTD_compress_usingCDict(cctx,
                                                  comp_buf, comp_bound,
                                                  raw_buf,  raw_len,
                                                  cdict);
        } else {
            comp_size = ZSTD_compressCCtx(cctx,
                                           comp_buf, comp_bound,
                                           raw_buf,  raw_len,
                                           3);
        }
        if (ZSTD_isError(comp_size)) {
            fprintf(stderr, "append: ZSTD error on chunk %u: %s\n",
                    new_n, ZSTD_getErrorName(comp_size));
            goto cleanup;
        }
        e->comp_size = (uint32_t)comp_size;

        fwrite(comp_buf, 1, comp_size, f);
        out_offset += comp_size;
        new_n++;
    }

    /* -----------------------------------------------------------------------
     * 11. Write the combined jump table.
     *     Old entries first (their offset fields still point to the correct
     *     positions — chunk data before jt_offset is untouched).
     *     New entries follow immediately after.
     * --------------------------------------------------------------------- */
    uint64_t new_jt_offset = out_offset;

    for (uint32_t i = 0; i < num_old_chunks; i++)
        ap_write_jump_entry(f, &old_entries[i]);
    for (uint32_t i = 0; i < new_n; i++)
        ap_write_jump_entry(f, &new_entries[i]);

    /* -----------------------------------------------------------------------
     * 12. Write the new 44-byte footer.
     *     final chain_hash:
     *       - If new chunks added:     prev_hash (last new chunk's hash)
     *       - If no new chunks added:  seed_hash (existing chain_hash)
     *         prev_hash == seed_hash in that case since the loop did not run.
     * --------------------------------------------------------------------- */
    uint32_t total_chunks = num_old_chunks + new_n;

    fwrite(prev_hash, 1, 32, f);              /* chain_hash */
    ap_write_u64_le(f, new_jt_offset);        /* jt_offset  */
    ap_write_u32_le(f, total_chunks);         /* num_chunks */

    /* -----------------------------------------------------------------------
     * 13. Stats to stdout (matches compress_file() style).
     * --------------------------------------------------------------------- */
    fflush(f);
    long out_total_l = ftell(f);
    uint64_t out_total = (out_total_l > 0) ? (uint64_t)out_total_l : 0;

    const char *fmt_name = (fmt == FORMAT_JSON)    ? "json"
                         : (fmt == FORMAT_SYSLOG)  ? "syslog"
                                                   : "plaintext";
    printf("format:     %s\n",           fmt_name);
    printf("appended:   %u new chunks\n", new_n);
    printf("total:      %u chunks\n",     total_chunks);
    printf("input:      %llu bytes\n",    (unsigned long long)in_size);
    printf("archive:    %llu bytes\n",    (unsigned long long)out_total);

    cleanup_rc = 0;

cleanup:
    free(new_entries);
    free(raw_buf);
    free(comp_buf);
    fclose(fin);
    ZSTD_freeCCtx(cctx);
    if (cdict) ZSTD_freeCDict(cdict);
    free(old_entries);
    free(dict_buf);
    fclose(f);
    return cleanup_rc;
}
