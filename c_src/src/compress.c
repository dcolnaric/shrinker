/*
 * compress.c — Shrinker C core (Phase 3 Step 12)
 *
 * Implements compress_file(): reads a log file, trains a zstd dictionary,
 * compresses in 64 KB chunks, writes bloom filters, SHA-256 hash chain,
 * timestamps, field blooms, jump table, and footer.
 *
 * Output is byte-compatible with the Python oracle in src/compress.py.
 * Verified by: python src/cli.py verify data/nginx_c.logz
 *              python src/cli.py decompress data/nginx_c.logz -o restored.log
 *              diff data/nginx.log restored.log
 */

#define _GNU_SOURCE   /* expose timegm() in <time.h> (POSIX extension, not C99) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <zstd.h>
#include <zdict.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian write helpers.
 * Writing byte-by-byte is correct on both LE and BE hosts; a direct
 * fwrite(&v) would be wrong on big-endian machines (the .logz format
 * mandates little-endian throughout).  Mirror of the read_u*_le helpers
 * in main.c.
 * ------------------------------------------------------------------------- */

static void write_u16_le(FILE *f, uint16_t v)
{
    uint8_t b[2] = { (uint8_t)(v & 0xFF), (uint8_t)((v >> 8) & 0xFF) };
    fwrite(b, 1, 2, f);
}

static void write_u32_le(FILE *f, uint32_t v)
{
    uint8_t b[4] = {
        (uint8_t)(v & 0xFF),
        (uint8_t)((v >>  8) & 0xFF),
        (uint8_t)((v >> 16) & 0xFF),
        (uint8_t)((v >> 24) & 0xFF)
    };
    fwrite(b, 1, 4, f);
}

static void write_u64_le(FILE *f, uint64_t v)
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
 * Bloom hash functions — must match Python bloom.py exactly:
 *   djb2: seed=5381, h = h*33 ^ c
 *   fnv1a: offset_basis=2166136261, prime=16777619
 *   sdbm:  h = c + (h<<6) + (h<<16) - h
 * All applied to the token bytes, result taken mod BLOOM_BITS.
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

/* Set one token in a bloom filter of `bits` bits (filter has bits/8 bytes).
 * Sets 3 independent bits — one per hash function.  A token is "present"
 * only if all 3 of its bits are set; a missing bit is a definitive negative.
 * Three hashes with different algebraic structures (multiplicative / FNV /
 * additive) minimise hash correlation while staying cheap. */
static void bloom_add(uint8_t *bf, uint32_t bits,
                      const uint8_t *token, size_t tlen)
{
    if (tlen == 0) return;
    uint32_t h1 = bloom_djb2 (token, tlen) % bits;   /* bit index in filter */
    uint32_t h2 = bloom_fnv1a(token, tlen) % bits;
    uint32_t h3 = bloom_sdbm (token, tlen) % bits;
    bf[h1 / 8] |= (uint8_t)(1u << (h1 % 8));         /* byte index / bit pos */
    bf[h2 / 8] |= (uint8_t)(1u << (h2 % 8));
    bf[h3 / 8] |= (uint8_t)(1u << (h3 % 8));
}

/* Query: returns 1 if token is *possibly* present, 0 if definitely absent.
 * Not used in compress.c but included for completeness / future use. */
static int __attribute__((unused))
bloom_query(const uint8_t *bf, uint32_t bits,
            const uint8_t *token, size_t tlen)
{
    if (tlen == 0) return 0;
    uint32_t h1 = bloom_djb2 (token, tlen) % bits;
    uint32_t h2 = bloom_fnv1a(token, tlen) % bits;
    uint32_t h3 = bloom_sdbm (token, tlen) % bits;
    return (bf[h1/8] >> (h1%8) & 1) &&
           (bf[h2/8] >> (h2%8) & 1) &&
           (bf[h3/8] >> (h3%8) & 1);
}

/* -------------------------------------------------------------------------
 * Tokeniser — splits raw bytes on: space, ", :, \n, \r, \t, ,, {, }, [, ]
 * Calls cb(token, tlen, userdata) for each non-empty token.
 * Python regex: re.split(r'[ ":\n\r\t,{}\[\]]+', ...)
 * ------------------------------------------------------------------------- */

typedef void (*token_cb)(const uint8_t *tok, size_t tlen, void *ud);

/* Returns 1 if c is a token delimiter — matches the Python regex character
 * class [ ":\n\r\t,{}\[\]] used in bloom.py.  Note: '=' is NOT a delimiter,
 * so "user=admin" is one token in plaintext logs, not two. */
static int is_delim(uint8_t c)
{
    return c == ' ' || c == '"' || c == ':' || c == '\n' ||
           c == '\r' || c == '\t' || c == ',' || c == '{' ||
           c == '}' || c == '[' || c == ']';
}

static void tokenise(const uint8_t *data, size_t len, token_cb cb, void *ud)
{
    size_t i = 0;
    while (i < len) {
        /* skip delimiters */
        while (i < len && is_delim(data[i])) i++;
        if (i >= len) break;
        size_t start = i;
        /* collect token */
        while (i < len && !is_delim(data[i])) i++;
        cb(data + start, i - start, ud);
    }
}

/* -------------------------------------------------------------------------
 * Build main bloom filter (1024 bytes = 8192 bits).
 * ------------------------------------------------------------------------- */

static void _add_token_main(const uint8_t *tok, size_t tlen, void *ud)
{
    bloom_add((uint8_t *)ud, BLOOM_BYTES * 8, tok, tlen);
}

static void build_main_bloom(uint8_t *bf, const uint8_t *raw, size_t len)
{
    memset(bf, 0, BLOOM_BYTES);
    tokenise(raw, len, _add_token_main, bf);
}

/* -------------------------------------------------------------------------
 * JSON field extraction helpers.
 * Given one JSON line and a key name, return a pointer to the value bytes
 * and set *vlen_out — or return NULL if the key is absent.
 *
 * This is a lightweight scanner, not a full JSON parser:
 *   - Finds the pattern  "key"  in the line.
 *   - Skips whitespace and expects ':'.
 *   - Handles two value types:
 *       string  — bounded by double-quotes: "value"
 *       number  — digit sequence (integer or float, possibly negative)
 *   - Does NOT handle nested objects, arrays, escaped quotes, or null/bool.
 *     For audit log fields (user, ip, action, level) these are always
 *     plain strings or small integers, so this is sufficient.
 * ------------------------------------------------------------------------- */

static const char *json_find_value(const char *line, size_t line_len,
                                   const char *key, size_t *vlen_out)
{
    size_t klen = strlen(key);
    const char *p   = line;
    const char *end = line + line_len;

    while (p < end) {
        /* Step 1: find the next opening double-quote — start of a key */
        const char *q = memchr(p, '"', (size_t)(end - p));
        if (!q) break;
        q++; /* skip the opening quote; q now points at the first key char */

        /* Step 2: check if the key matches exactly, followed by '"' */
        if (q + klen + 1 <= end &&
            memcmp(q, key, klen) == 0 && q[klen] == '"') {

            /* Step 3: skip closing quote, optional whitespace, then ':' */
            const char *v = q + klen + 1;
            while (v < end && (*v == ' ' || *v == '\t')) v++;
            if (v >= end || *v != ':') { p = q; continue; } /* false key match */
            v++; /* skip ':' */
            while (v < end && (*v == ' ' || *v == '\t')) v++;
            if (v >= end) break;

            if (*v == '"') {
                /* Step 4a: string value — collect until closing '"' or newline */
                v++; /* skip opening quote */
                const char *vs = v;
                while (v < end && *v != '"' && *v != '\n') v++;
                *vlen_out = (size_t)(v - vs);
                return vs;
            } else if (isdigit((unsigned char)*v) || *v == '-') {
                /* Step 4b: numeric value — collect digits, '.', '-' */
                const char *vs = v;
                while (v < end && (isdigit((unsigned char)*v) || *v == '.' || *v == '-')) v++;
                *vlen_out = (size_t)(v - vs);
                return vs;
            }
            /* Other value types (null, bool, array, nested object) — skip */
        }
        p = q; /* advance past the quote we just examined */
    }
    return NULL;
}

/* -------------------------------------------------------------------------
 * Field bloom (512 bytes = 4096 bits).
 * Keys to index: user, user_id, username, ip, ip_address, action, level, severity
 * Only for JSON format; for syslog/plaintext, returns zero bytes.
 * ------------------------------------------------------------------------- */

static const char *FIELD_KEYS[] = {
    "user", "user_id", "username",
    "ip", "ip_address",
    "action",
    "level", "severity",
    NULL
};

typedef struct { uint8_t *fb; } FieldBloomUD;

static void _add_token_field(const uint8_t *tok, size_t tlen, void *ud)
{
    bloom_add(((FieldBloomUD *)ud)->fb, FIELD_BLOOM_BYTES * 8, tok, tlen);
}

static void build_field_bloom(uint8_t *fb, const uint8_t *raw, size_t raw_len,
                               int fmt)
{
    memset(fb, 0, FIELD_BLOOM_BYTES);
    /* Zero bytes is the sentinel meaning "no field index" — search.py checks
     * any(field_bloom) before applying field filters, so a zero-filled bloom
     * causes the field-filter skip to be bypassed entirely for this chunk.
     * This lets syslog/plaintext chunks pass through to the main bloom check
     * without false negatives. */
    if (fmt != FORMAT_JSON) return;

    /* Split into lines, parse each JSON line for field values */
    const char *p   = (const char *)raw;
    const char *end = p + raw_len;

    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

        for (int ki = 0; FIELD_KEYS[ki] != NULL; ki++) {
            size_t vlen = 0;
            const char *v = json_find_value(p, line_len, FIELD_KEYS[ki], &vlen);
            if (v && vlen > 0) {
                FieldBloomUD ud = { fb };
                tokenise((const uint8_t *)v, vlen, _add_token_field, &ud);
            }
        }
        p = nl ? nl + 1 : end;
    }
}

/* -------------------------------------------------------------------------
 * Timestamp parsing — returns unix epoch (uint64_t) or 0 on failure.
 *
 * Supports:
 *   JSON keys: timestamp, time, ts, @timestamp  (string ISO-8601 or int/float)
 *   Syslog prefix: "Jan 15 10:23:45" (first token group)
 * ------------------------------------------------------------------------- */

static const char *TS_KEYS[] = {
    "timestamp", "time", "ts", "@timestamp", NULL
};

/* Try to parse ISO 8601 string: "2025-01-15T10:23:45" or "2025-01-15 10:23:45".
 * Trailing 'Z' and timezone offsets are silently ignored — we truncate to
 * 25 chars before the copy, which cuts off "+00:00" etc.  Precision is
 * seconds (sub-second parts are also truncated).  timegm() interprets the
 * struct tm as UTC, which matches the Python calendar.timegm() call. */
static uint64_t parse_iso8601(const char *s, size_t slen)
{
    if (slen < 10) return 0;          /* need at least "YYYY-MM-DD" */
    char buf[32];
    size_t n = slen < 25 ? slen : 25; /* cap at 25: "2025-01-15T10:23:45.123Z" */
    memcpy(buf, s, n);
    buf[n] = '\0';
    /* strptime doesn't recognise 'T' as a separator; replace with space */
    for (size_t i = 0; i < n; i++)
        if (buf[i] == 'T') buf[i] = ' ';
    struct tm tm = {0};
    char *end = strptime(buf, "%Y-%m-%d %H:%M:%S", &tm);
    if (!end) end = strptime(buf, "%Y-%m-%d", &tm); /* date-only fallback */
    if (!end) return 0;
    tm.tm_isdst = -1;   /* let timegm ignore DST — it always returns UTC */
    time_t t = timegm(&tm);
    return (t < 0) ? 0 : (uint64_t)t;
}

/* Parse a numeric string as a unix epoch (integer or float seconds).
 * The range check 1e9..9e9 accepts years ~2001–2255; anything outside
 * that window is almost certainly not a timestamp (e.g. a port number,
 * HTTP status code, or latency value). */
static uint64_t parse_numeric_ts(const char *s, size_t slen)
{
    if (slen == 0 || slen > 20) return 0; /* >20 digits can't be a valid epoch */
    char buf[24];
    memcpy(buf, s, slen);
    buf[slen] = '\0';
    char *endp;
    double v = strtod(buf, &endp);
    if (endp == buf) return 0;   /* not a number */
    if (v < 1e9 || v > 9e9) return 0;
    return (uint64_t)v;          /* truncate fractional seconds */
}

/* Syslog month names */
static const char *MONTHS[] = {
    "Jan","Feb","Mar","Apr","May","Jun",
    "Jul","Aug","Sep","Oct","Nov","Dec"
};

static uint64_t parse_syslog_ts(const char *line, size_t line_len)
{
    if (line_len < 15) return 0;  /* RFC 3164 prefix is exactly 15 chars */
    char buf[20];
    memcpy(buf, line, 15);
    buf[15] = '\0';
    /* Expected format: "Jan 15 10:23:45" — no year in RFC 3164 */
    char mon[4]; int day, hh, mm, ss;
    if (sscanf(buf, "%3s %d %d:%d:%d", mon, &day, &hh, &mm, &ss) != 5)
        return 0;
    int month = -1;
    for (int i = 0; i < 12; i++)
        if (strcmp(mon, MONTHS[i]) == 0) { month = i; break; }
    if (month < 0) return 0;
    /* RFC 3164 omits the year; we assume the current calendar year, same as
     * the Python implementation (calendar.timegm with the current year).
     * This is the standard approximation — syslog files rarely span a year
     * boundary in a single archive. */
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

/* Extract min/max unix epoch timestamps from a raw chunk.
 * Iterates line-by-line; each line is parsed according to fmt.
 * Sets *min_ts = *max_ts = 0 if no timestamps are found (stored as-is in the
 * jump table — the search path treats 0 as "unknown" and does not skip
 * such chunks when a time-range filter is active). */
static void extract_timestamps(const uint8_t *raw, size_t raw_len, int fmt,
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
            for (int ki = 0; TS_KEYS[ki] != NULL && ts == 0; ki++) {
                size_t vlen = 0;
                const char *v = json_find_value(p, line_len, TS_KEYS[ki], &vlen);
                if (!v || vlen == 0) continue;
                /* Try ISO string first, then numeric */
                ts = parse_iso8601(v, vlen);
                if (!ts) ts = parse_numeric_ts(v, vlen);
            }
        } else if (fmt == FORMAT_SYSLOG) {
            ts = parse_syslog_ts(p, line_len);
        }
        /* plaintext: no timestamp extraction */

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
 * Format detection — inspect up to the first 5 non-empty lines.
 * Returns FORMAT_JSON, FORMAT_SYSLOG, or FORMAT_PLAINTEXT.
 *
 * Scoring:
 *   JSON    — line starts with '{' and ends with '}'    (≥2 hits → JSON)
 *   Syslog  — first 3 chars match a month abbreviation  (≥2 hits → syslog)
 *   Plain   — fallback when neither threshold is reached
 *
 * Deliberately lenient (≥2 of 5, not strict majority) so that files whose
 * first line is a comment or blank still detect correctly.
 * ------------------------------------------------------------------------- */

static int detect_format(const uint8_t *data, size_t data_len)
{
    const char *p    = (const char *)data;
    const char *end  = p + data_len;
    int json_count   = 0;
    int syslog_count = 0;
    int lines_checked = 0;

    while (p < end && lines_checked < 5) {
        /* Skip blank / CR-only lines */
        while (p < end && (*p == '\n' || *p == '\r')) p++;
        if (p >= end) break;
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);
        if (line_len == 0) { p = nl ? nl + 1 : end; continue; }

        /* JSON check: starts with '{', last non-whitespace is '}' */
        if (p[0] == '{') {
            const char *ep = nl ? nl - 1 : end - 1;
            while (ep > p && (*ep == '\r' || *ep == ' ' || *ep == '\t')) ep--;
            if (*ep == '}') json_count++;
        }
        /* Syslog check: line opens with a 3-letter month abbreviation */
        if (line_len >= 3) {
            char mon[4]; memcpy(mon, p, 3); mon[3] = '\0';
            for (int i = 0; i < 12; i++) {
                if (strcmp(mon, MONTHS[i]) == 0) { syslog_count++; break; }
            }
        }
        lines_checked++;
        p = nl ? nl + 1 : end;
    }
    if (json_count   >= 2) return FORMAT_JSON;
    if (syslog_count >= 2) return FORMAT_SYSLOG;
    return FORMAT_PLAINTEXT;
}

/* -------------------------------------------------------------------------
 * Write one jump-table entry in explicit LE byte order.
 * Matches Python struct.pack exactly.
 * Total: 8+4+4+1024+32+8+8+512 = 1600 bytes.
 * ------------------------------------------------------------------------- */

static void write_jump_entry(FILE *fout, const JumpEntry *e)
{
    write_u64_le(fout, e->offset);
    write_u32_le(fout, e->comp_size);
    write_u32_le(fout, e->orig_size);
    fwrite(e->bloom,       1, BLOOM_BYTES,       fout);
    fwrite(e->chunk_hash,  1, 32,                fout);
    write_u64_le(fout, e->min_ts);
    write_u64_le(fout, e->max_ts);
    fwrite(e->field_bloom, 1, FIELD_BLOOM_BYTES, fout);
}

/* -------------------------------------------------------------------------
 * compress_file — public API
 * ------------------------------------------------------------------------- */

int compress_file(const char *input_path, const char *output_path)
{
    /* -----------------------------------------------------------------------
     * 1. Open input file and read first TRAIN_LIMIT bytes for dict training
     * --------------------------------------------------------------------- */
    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        fprintf(stderr, "compress: cannot open input '%s'\n", input_path);
        return -1;
    }

    /* Get file size */
    if (fseek(fin, 0, SEEK_END) != 0) {
        fprintf(stderr, "compress: fseek failed\n");
        fclose(fin); return -1;
    }
    long file_size_l = ftell(fin);
    if (file_size_l < 0) {
        fprintf(stderr, "compress: ftell failed\n");
        fclose(fin); return -1;
    }
    uint64_t file_size = (uint64_t)file_size_l;
    rewind(fin);

    /* Read training data (up to TRAIN_LIMIT bytes) */
    size_t train_size = (file_size < (uint64_t)TRAIN_LIMIT)
                        ? (size_t)file_size : (size_t)TRAIN_LIMIT;
    uint8_t *train_buf = (uint8_t *)malloc(train_size);
    if (!train_buf) {
        fprintf(stderr, "compress: out of memory for training buffer (%zu B)\n",
                train_size);
        fclose(fin); return -1;
    }
    size_t train_read = fread(train_buf, 1, train_size, fin);
    if (train_read != train_size) {
        fprintf(stderr, "compress: short read on training data\n");
        free(train_buf); fclose(fin); return -1;
    }

    /* -----------------------------------------------------------------------
     * 2. Detect format from first bytes
     * --------------------------------------------------------------------- */
    int fmt = detect_format(train_buf, train_read);
    const char *fmt_name = (fmt == FORMAT_JSON)     ? "json"
                         : (fmt == FORMAT_SYSLOG)   ? "syslog"
                                                    : "plaintext";
    printf("format:     %s\n", fmt_name);

    /* -----------------------------------------------------------------------
     * 3. Build sample array for ZDICT_trainFromBuffer (up to MAX_TRAIN_SAMPS
     *    samples of CHUNK_SIZE each, covering first TRAIN_LIMIT bytes).
     *
     * zstd dictionary training works best when samples are representative and
     * uniform in size.  We present each 64 KB chunk from the training window
     * as one sample — the same granularity used for compression — so the
     * dictionary captures within-chunk repetition patterns (JSON keys,
     * hostnames, service names, request paths).
     *
     * The zstd library requires ≥2 samples; files smaller than 2 × 64 KB are
     * compressed without a dictionary (still correct, just less efficient).
     * --------------------------------------------------------------------- */
    uint32_t n_train_chunks = (uint32_t)(train_read / CHUNK_SIZE);
    if (n_train_chunks > MAX_TRAIN_SAMPS) n_train_chunks = MAX_TRAIN_SAMPS;
    /* Need at least 2 samples; the library will return an error otherwise */
    int use_dict = (n_train_chunks >= 2);

    uint8_t  *dict_buf  = NULL;
    size_t    dict_size = 0;
    ZSTD_CDict *cdict  = NULL;

    if (use_dict) {
        /* Build samples array: each sample is exactly one CHUNK_SIZE slice */
        size_t  *sample_sizes = (size_t *)malloc(n_train_chunks * sizeof(size_t));
        if (!sample_sizes) { fprintf(stderr, "compress: OOM\n"); free(train_buf); fclose(fin); return -1; }
        for (uint32_t i = 0; i < n_train_chunks; i++)
            sample_sizes[i] = CHUNK_SIZE;

        dict_buf = (uint8_t *)malloc(DICT_TARGET);
        if (!dict_buf) { fprintf(stderr, "compress: OOM\n"); free(sample_sizes); free(train_buf); fclose(fin); return -1; }

        size_t dict_result = ZDICT_trainFromBuffer(
            dict_buf, DICT_TARGET,
            train_buf, sample_sizes, n_train_chunks);

        if (ZDICT_isError(dict_result)) {
            fprintf(stderr, "compress: dict training failed: %s — compressing without dict\n",
                    ZDICT_getErrorName(dict_result));
            free(dict_buf); dict_buf = NULL;
            use_dict = 0;
        } else {
            dict_size = dict_result;
            /* Create CDict at compression level 3 */
            cdict = ZSTD_createCDict(dict_buf, dict_size, 3);
            if (!cdict) {
                fprintf(stderr, "compress: ZSTD_createCDict failed — compressing without dict\n");
                free(dict_buf); dict_buf = NULL;
                use_dict = 0;
            }
        }
        free(sample_sizes);
    }
    free(train_buf);

    /* -----------------------------------------------------------------------
     * 4. Open output file and write header
     * --------------------------------------------------------------------- */
    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        fprintf(stderr, "compress: cannot open output '%s'\n", output_path);
        if (cdict)    ZSTD_freeCDict(cdict);
        if (dict_buf) free(dict_buf);
        fclose(fin); return -1;
    }

    /* 4a. Magic (4 bytes) */
    fwrite(MAGIC, 1, 4, fout);
    /* 4b. Version (uint16 LE) */
    write_u16_le(fout, (uint16_t)VERSION);
    /* 4c. Format byte */
    fwrite((uint8_t[]){(uint8_t)fmt}, 1, 1, fout);
    /* 4d. Dict length + data */
    uint32_t dict_len = use_dict ? (uint32_t)dict_size : 0;
    write_u32_le(fout, dict_len);
    if (use_dict && dict_len > 0)
        fwrite(dict_buf, 1, dict_len, fout);

    /* -----------------------------------------------------------------------
     * 5. Compression context
     * --------------------------------------------------------------------- */
    ZSTD_CCtx *cctx = ZSTD_createCCtx();
    if (!cctx) {
        fprintf(stderr, "compress: ZSTD_createCCtx failed\n");
        if (cdict) ZSTD_freeCDict(cdict);
        if (dict_buf) free(dict_buf);
        fclose(fout); fclose(fin); return -1;
    }

    /* Allocate chunk + compressed buffers */
    uint8_t *raw_buf  = (uint8_t *)malloc(CHUNK_SIZE);
    size_t   comp_bound = ZSTD_compressBound(CHUNK_SIZE);
    uint8_t *comp_buf = (uint8_t *)malloc(comp_bound);
    if (!raw_buf || !comp_buf) {
        fprintf(stderr, "compress: OOM for chunk buffers\n");
        ZSTD_freeCCtx(cctx);
        if (cdict) ZSTD_freeCDict(cdict);
        if (dict_buf) free(dict_buf);
        free(raw_buf); free(comp_buf);
        fclose(fout); fclose(fin); return -1;
    }

    /* -----------------------------------------------------------------------
     * 6. Jump table — allocated up-front with doubling growth.
     *    Initial cap of 256 covers most small files without realloc.
     *    A 1.5 GB HDFS log produces ~24 K entries; each realloc doubles so
     *    we call it at most log2(24000/256) ≈ 7 times.
     * --------------------------------------------------------------------- */
    uint32_t  cap      = 256;
    uint32_t  n_chunks = 0;
    JumpEntry *entries = (JumpEntry *)malloc((size_t)cap * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "compress: OOM for jump table\n");
        goto cleanup;
    }

    /* -----------------------------------------------------------------------
     * 7. Main compression loop.
     *    We read the file twice: first pass (above) loaded training data,
     *    then we rewind here to compress from byte 0.  The double-read
     *    keeps peak memory bounded to TRAIN_LIMIT + 2×CHUNK_SIZE regardless
     *    of input file size.
     * --------------------------------------------------------------------- */
    rewind(fin);

    /* prev_hash starts as zeros for the chain seed */
    uint8_t prev_hash[32];
    memset(prev_hash, 0, 32);

    /* Track current byte offset in output file */
    uint64_t out_offset = (uint64_t)ftell(fout);

    size_t raw_len;
    while ((raw_len = fread(raw_buf, 1, CHUNK_SIZE, fin)) > 0) {
        /* Grow jump table if needed */
        if (n_chunks == cap) {
            cap *= 2;
            JumpEntry *tmp = (JumpEntry *)realloc(entries,
                                                   (size_t)cap * sizeof(JumpEntry));
            if (!tmp) { fprintf(stderr, "compress: OOM growing jump table\n"); goto cleanup; }
            entries = tmp;
        }

        JumpEntry *e = &entries[n_chunks];

        /* 7a. Record chunk offset */
        e->offset    = out_offset;
        e->orig_size = (uint32_t)raw_len;

        /* 7b. Main bloom filter */
        build_main_bloom(e->bloom, raw_buf, raw_len);

        /* 7c. Field bloom filter */
        build_field_bloom(e->field_bloom, raw_buf, raw_len, fmt);

        /* 7d. SHA-256 hash chain over RAW (pre-compression) bytes.
         *
         *   chunk 0: SHA256(raw_bytes)
         *   chunk N: SHA256(prev_hash || raw_bytes)
         *
         * Hashing raw bytes (not compressed) means the chain certifies log
         * *content*, not an artifact of the compression algorithm.  A future
         * zstd version producing different compressed bytes would not break
         * existing archives.
         *
         * We use the EVP streaming API (OpenSSL 3.x) because we need to feed
         * two separate buffers (prev_hash then raw_buf) into one digest.  The
         * one-shot SHA256() helper in main.c is fine for single-buffer use.
         *
         * Note: EVP_MD_CTX_new/free per chunk is slightly wasteful; a future
         * optimisation would reuse the context with EVP_MD_CTX_reset().
         */
        {
            uint8_t hash_out[32];
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
            if (n_chunks > 0)
                EVP_DigestUpdate(mdctx, prev_hash, 32); /* chain: prepend prev */
            EVP_DigestUpdate(mdctx, raw_buf, raw_len);
            unsigned int mdlen = 32;
            EVP_DigestFinal_ex(mdctx, hash_out, &mdlen);
            EVP_MD_CTX_free(mdctx);
            memcpy(e->chunk_hash, hash_out, 32);
            memcpy(prev_hash,     hash_out, 32); /* carry forward for next chunk */
        }

        /* 7e. Timestamp extraction — use local vars to avoid packed-member ptr */
        {
            uint64_t min_ts = 0, max_ts = 0;
            extract_timestamps(raw_buf, raw_len, fmt, &min_ts, &max_ts);
            e->min_ts = min_ts;
            e->max_ts = max_ts;
        }

        /* 7f. Compress the raw chunk.
         *     Bloom filters, hash, and timestamps are all computed above over
         *     the raw bytes.  Compression happens last because it is the most
         *     CPU-intensive step and we want all metadata to reflect raw data.
         *     Level 3 balances speed vs ratio (same as the Python oracle). */
        size_t comp_size;
        if (use_dict && cdict) {
            /* ZSTD_CDict is pre-digested by the library; using it is faster
             * than re-loading the raw dict bytes on every call. */
            comp_size = ZSTD_compress_usingCDict(cctx,
                                                  comp_buf, comp_bound,
                                                  raw_buf,  raw_len,
                                                  cdict);
        } else {
            /* No dict: file was < 2 chunks, or training failed gracefully. */
            comp_size = ZSTD_compressCCtx(cctx,
                                           comp_buf, comp_bound,
                                           raw_buf,  raw_len,
                                           3);
        }
        if (ZSTD_isError(comp_size)) {
            fprintf(stderr, "compress: ZSTD error on chunk %u: %s\n",
                    n_chunks, ZSTD_getErrorName(comp_size));
            goto cleanup;
        }
        e->comp_size = (uint32_t)comp_size;

        /* 7g. Write compressed chunk to output */
        fwrite(comp_buf, 1, comp_size, fout);
        out_offset += comp_size;

        n_chunks++;
    }

    /* -----------------------------------------------------------------------
     * 8. Write jump table at the current end of file.
     *    The offset is recorded now so it can be written into the footer.
     *    The Python decompressor/search reads this offset from the footer,
     *    seeks here, and reads n_chunks × JUMP_ENTRY_SIZE bytes.
     * --------------------------------------------------------------------- */
    uint64_t jt_offset = (uint64_t)ftell(fout);
    for (uint32_t i = 0; i < n_chunks; i++)
        write_jump_entry(fout, &entries[i]);

    /* -----------------------------------------------------------------------
     * 9. Write 44-byte footer (Parquet-style).
     *    Readers open the file, seek to EOF-44, and read these three fields
     *    to bootstrap all subsequent access — no external index needed.
     *    chain_hash is a convenience copy of the last chunk's hash; it lets
     *    a quick integrity check skip re-reading the entire jump table.
     * --------------------------------------------------------------------- */
    fwrite(prev_hash,   1, 32,  fout);   /* chain_hash = last chunk's hash */
    write_u64_le(fout, jt_offset);       /* byte offset of the jump table  */
    write_u32_le(fout, n_chunks);        /* total number of chunks         */

    /* -----------------------------------------------------------------------
     * 10. Stats
     * --------------------------------------------------------------------- */
    fflush(fout);
    long out_size_l = ftell(fout);
    uint64_t out_size = (out_size_l > 0) ? (uint64_t)out_size_l : 0;
    double ratio = (out_size > 0 && file_size > 0)
                   ? (double)file_size / (double)out_size : 0.0;

    printf("chunks:     %u\n",          n_chunks);
    printf("input:      %llu bytes\n",  (unsigned long long)file_size);
    printf("output:     %llu bytes\n",  (unsigned long long)out_size);
    printf("ratio:      %.2fx\n",       ratio);
    printf("dict:       %s (%u bytes)\n",
           use_dict ? "yes" : "no", dict_len);

    /* Success */
    free(entries);
    free(raw_buf);
    free(comp_buf);
    ZSTD_freeCCtx(cctx);
    if (cdict)    ZSTD_freeCDict(cdict);
    if (dict_buf) free(dict_buf);
    fclose(fout);
    fclose(fin);
    return 0;

cleanup:
    free(entries);
    free(raw_buf);
    free(comp_buf);
    ZSTD_freeCCtx(cctx);
    if (cdict)    ZSTD_freeCDict(cdict);
    if (dict_buf) free(dict_buf);
    fclose(fout);
    fclose(fin);
    return -1;
}
