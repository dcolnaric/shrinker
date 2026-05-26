/*
 * export.c — Shrinker C exporter (Phase 3 Step 16)
 *
 * Implements export_file(): decompresses qualifying chunks (optionally
 * filtered by time range), extracts structured fields from each log line,
 * and writes CSV or JSONL to stdout — byte-compatible with src/export.py.
 *
 * CSV output:  Python csv.writer(lineterminator='\n', quoting=QUOTE_MINIMAL)
 * JSON output: Python json.dumps() defaults — separators (', ', ': '),
 *              ensure_ascii=True (non-ASCII encoded as \uXXXX)
 *
 * Returns 0 on success, 1 on error.
 */

#define _GNU_SOURCE            /* timegm() */
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <zstd.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Little-endian read helpers (same as other C files).
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
 * Date parser — same as search.c parse_date_ts().
 * "YYYY-MM-DD" → UTC epoch; end_of_day=1 gives 23:59:59.
 * Returns 0 on parse failure.
 * ------------------------------------------------------------------------- */

static uint64_t parse_date_ts(const char *s, int end_of_day)
{
    if (!s || !*s) return 0;
    struct tm tm = {0};
    char *ep = strptime(s, "%Y-%m-%d", &tm);
    if (!ep) return 0;
    if (end_of_day) { tm.tm_hour = 23; tm.tm_min = 59; tm.tm_sec = 59; }
    tm.tm_isdst = -1;
    time_t t = timegm(&tm);
    return (t < 0) ? 0 : (uint64_t)t;
}

/* -------------------------------------------------------------------------
 * Lightweight JSON key→value scanner (copy of compress.c json_find_value).
 *
 * Handles string values ("...") and numeric values (digits, '.', '-').
 * Returns pointer to the value bytes within `line` and sets *vlen_out,
 * or returns NULL if the key is not found.
 * ------------------------------------------------------------------------- */

static const char *json_find_value(const char *line, size_t line_len,
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
            } else if ((*v >= '0' && *v <= '9') || *v == '-') {
                const char *vs = v;
                while (v < end && ((*v >= '0' && *v <= '9') ||
                                   *v == '.' || *v == '-' || *v == 'e' ||
                                   *v == 'E' || *v == '+'))
                    v++;
                *vlen_out = (size_t)(v - vs);
                return vs;
            }
        }
        p = q;
    }
    return NULL;
}

/* Extract the first matching key from an array of candidate keys.
 * Writes the value (or "") into buf[bufsz]. */
static void extract_first(const char *line, size_t line_len,
                           const char **keys, int nkeys,
                           char *buf, size_t bufsz)
{
    for (int i = 0; i < nkeys; i++) {
        size_t vlen = 0;
        const char *v = json_find_value(line, line_len, keys[i], &vlen);
        if (v && vlen > 0) {
            size_t n = vlen < bufsz - 1 ? vlen : bufsz - 1;
            memcpy(buf, v, n);
            buf[n] = '\0';
            return;
        }
    }
    buf[0] = '\0';
}

/* -------------------------------------------------------------------------
 * CSV writer — matches Python csv.writer(lineterminator='\n',
 *              quoting=QUOTE_MINIMAL, quotechar='"', delimiter=',').
 *
 * QUOTE_MINIMAL: quote a field only if it contains the delimiter (','),
 * the quotechar ('"'), '\n', or '\r'.  Within a quoted field, '"' is
 * doubled.
 * ------------------------------------------------------------------------- */

static void write_csv_field(FILE *out, const char *s, size_t slen)
{
    /* Determine whether the field needs quoting */
    int needs_quote = 0;
    for (size_t i = 0; i < slen; i++) {
        char c = s[i];
        if (c == ',' || c == '"' || c == '\n' || c == '\r') {
            needs_quote = 1;
            break;
        }
    }
    if (!needs_quote) {
        fwrite(s, 1, slen, out);
        return;
    }
    fputc('"', out);
    for (size_t i = 0; i < slen; i++) {
        if (s[i] == '"') fputc('"', out);   /* double the quote */
        fputc(s[i], out);
    }
    fputc('"', out);
}

/* Write a full CSV row of 7 pre-split fields followed by \n. */
static void write_csv_row(FILE *out,
                          const char *ts,     size_t tslen,
                          const char *level,  size_t llen,
                          const char *user,   size_t ulen,
                          const char *ip,     size_t iplen,
                          const char *action, size_t alen,
                          const char *msg,    size_t mlen,
                          const char *raw,    size_t rlen)
{
    write_csv_field(out, ts,     tslen);  fputc(',', out);
    write_csv_field(out, level,  llen);   fputc(',', out);
    write_csv_field(out, user,   ulen);   fputc(',', out);
    write_csv_field(out, ip,     iplen);  fputc(',', out);
    write_csv_field(out, action, alen);   fputc(',', out);
    write_csv_field(out, msg,    mlen);   fputc(',', out);
    write_csv_field(out, raw,    rlen);
    fputc('\n', out);
}

/* -------------------------------------------------------------------------
 * JSON string writer — matches Python json.dumps(ensure_ascii=True).
 *
 * Escapes:  " → \"   \ → \\   \b \f \n \r \t → \b \f \n \r \t
 *           control chars (< 0x20) → \u00xx
 *           non-ASCII UTF-8 → decode to code point → \uXXXX (or surrogate pair)
 *           invalid UTF-8 byte → � (matches Python errors='replace')
 * ------------------------------------------------------------------------- */

static void write_json_string(FILE *out, const char *s, size_t slen)
{
    fputc('"', out);
    size_t i = 0;
    while (i < slen) {
        unsigned char c = (unsigned char)s[i];

        /* ---- 7-bit ASCII ---- */
        if (c == '"')        { fwrite("\\\"", 1, 2, out); i++; continue; }
        if (c == '\\')       { fwrite("\\\\", 1, 2, out); i++; continue; }
        if (c == '\b')       { fwrite("\\b",  1, 2, out); i++; continue; }
        if (c == '\f')       { fwrite("\\f",  1, 2, out); i++; continue; }
        if (c == '\n')       { fwrite("\\n",  1, 2, out); i++; continue; }
        if (c == '\r')       { fwrite("\\r",  1, 2, out); i++; continue; }
        if (c == '\t')       { fwrite("\\t",  1, 2, out); i++; continue; }
        if (c < 0x20)        { fprintf(out, "\\u%04x", (unsigned)c); i++; continue; }
        if (c < 0x80)        { fputc(c, out); i++; continue; }

        /* ---- Multi-byte UTF-8 → Unicode code point → \uXXXX ---- */
        uint32_t cp;
        size_t   seq;

        if ((c & 0xE0) == 0xC0 && i + 1 < slen &&
            ((unsigned char)s[i+1] & 0xC0) == 0x80) {
            cp  = ((uint32_t)(c & 0x1F) << 6) | ((unsigned char)s[i+1] & 0x3F);
            seq = 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < slen &&
                   ((unsigned char)s[i+1] & 0xC0) == 0x80 &&
                   ((unsigned char)s[i+2] & 0xC0) == 0x80) {
            cp  = ((uint32_t)(c & 0x0F) << 12)
                | ((uint32_t)((unsigned char)s[i+1] & 0x3F) << 6)
                | ((unsigned char)s[i+2] & 0x3F);
            seq = 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < slen &&
                   ((unsigned char)s[i+1] & 0xC0) == 0x80 &&
                   ((unsigned char)s[i+2] & 0xC0) == 0x80 &&
                   ((unsigned char)s[i+3] & 0xC0) == 0x80) {
            cp  = ((uint32_t)(c & 0x07) << 18)
                | ((uint32_t)((unsigned char)s[i+1] & 0x3F) << 12)
                | ((uint32_t)((unsigned char)s[i+2] & 0x3F) << 6)
                | ((unsigned char)s[i+3] & 0x3F);
            seq = 4;
        } else {
            /* Invalid UTF-8 byte — replacement char U+FFFD (Python errors='replace') */
            fwrite("\\ufffd", 1, 6, out);
            i++;
            continue;
        }

        if (cp <= 0xFFFF) {
            fprintf(out, "\\u%04x", cp);
        } else {
            /* Supplementary plane: encode as surrogate pair, same as Python */
            cp -= 0x10000;
            fprintf(out, "\\u%04x\\u%04x",
                    (unsigned)(0xD800 + (cp >> 10)),
                    (unsigned)(0xDC00 + (cp & 0x3FF)));
        }
        i += seq;
    }
    fputc('"', out);
}

/* Write a JSONL record matching Python json.dumps() default format:
 *   {"key": "val", ...}\n
 * Separator:  ', '  between pairs, ': ' between key and value. */
static void write_json_record(FILE *out,
                              const char *ts,     size_t tslen,
                              const char *level,  size_t llen,
                              const char *user,   size_t ulen,
                              const char *ip,     size_t iplen,
                              const char *action, size_t alen,
                              const char *msg,    size_t mlen,
                              const char *raw,    size_t rlen)
{
    fputs("{\"timestamp\": ", out); write_json_string(out, ts,     tslen);
    fputs(", \"level\": ",    out); write_json_string(out, level,  llen);
    fputs(", \"user\": ",     out); write_json_string(out, user,   ulen);
    fputs(", \"ip\": ",       out); write_json_string(out, ip,     iplen);
    fputs(", \"action\": ",   out); write_json_string(out, action, alen);
    fputs(", \"message\": ",  out); write_json_string(out, msg,    mlen);
    fputs(", \"raw\": ",      out); write_json_string(out, raw,    rlen);
    fputs("}\n",              out);
}

/* -------------------------------------------------------------------------
 * export_file — public API
 * ------------------------------------------------------------------------- */

#define FBUFSZ 4096   /* per-field extraction buffer */

int export_file(const char *logz_path, const char *from_date,
                const char *to_date, const char *format)
{
    /* --- Parse date filters --- */
    uint64_t from_ts = from_date ? parse_date_ts(from_date, 0) : 0;
    uint64_t to_ts   = to_date   ? parse_date_ts(to_date,   1) : 0;

    int fmt_csv = (format && strcmp(format, "json") == 0) ? 0 : 1; /* default csv */

    /* --- Open file --- */
    FILE *f = fopen(logz_path, "rb");
    if (!f) {
        fprintf(stderr, "error: cannot open '%s'\n", logz_path);
        return 1;
    }

    /* --- Validate MAGIC --- */
    uint8_t magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, MAGIC, 4) != 0) {
        fprintf(stderr, "error: not a .logz file (bad magic)\n");
        fclose(f); return 1;
    }

    /* --- Validate VERSION --- */
    uint16_t version = 0;
    if (read_u16_le(f, &version) != 0 || version != VERSION) {
        fprintf(stderr, "error: unsupported version %u (expected %u)\n",
                version, VERSION);
        fclose(f); return 1;
    }

    /* --- FORMAT byte — drives is_json flag --- */
    uint8_t log_fmt_byte;
    if (fread(&log_fmt_byte, 1, 1, f) != 1) {
        fprintf(stderr, "error: cannot read format byte\n");
        fclose(f); return 1;
    }
    int is_json = (log_fmt_byte == FORMAT_JSON);

    /* --- Shared dictionary --- */
    uint32_t dict_len;
    if (read_u32_le(f, &dict_len) != 0) {
        fprintf(stderr, "error: cannot read dict_len\n");
        fclose(f); return 1;
    }

    uint8_t    *dict_buf = NULL;
    ZSTD_DDict *ddict    = NULL;

    if (dict_len > 0) {
        dict_buf = (uint8_t *)malloc(dict_len);
        if (!dict_buf || fread(dict_buf, 1, dict_len, f) != dict_len) {
            fprintf(stderr, "error: cannot read dictionary\n");
            free(dict_buf); fclose(f); return 1;
        }
        ddict = ZSTD_createDDict(dict_buf, dict_len);
        if (!ddict) {
            fprintf(stderr, "error: ZSTD_createDDict failed\n");
            free(dict_buf); fclose(f); return 1;
        }
    }

    /* --- Footer: chain_hash(32) + jt_offset(8) + num_chunks(4) --- */
    if (fseek(f, -FOOTER_SIZE, SEEK_END) != 0) {
        fprintf(stderr, "error: cannot seek to footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    uint8_t  chain_hash[32];
    uint64_t jt_offset;
    uint32_t num_chunks;

    if (fread(chain_hash, 1, 32, f) != 32 ||
        read_u64_le(f, &jt_offset) != 0    ||
        read_u32_le(f, &num_chunks) != 0) {
        fprintf(stderr, "error: cannot read footer\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* --- Jump table --- */
    JumpEntry *entries = (JumpEntry *)malloc((size_t)num_chunks * sizeof(JumpEntry));
    if (!entries) {
        fprintf(stderr, "error: OOM for jump table\n");
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    if (fseek(f, (long)jt_offset, SEEK_SET) != 0 ||
        fread(entries, sizeof(JumpEntry), num_chunks, f) != (size_t)num_chunks) {
        fprintf(stderr, "error: cannot read jump table\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    /* --- Decompression context --- */
    ZSTD_DCtx *dctx = ZSTD_createDCtx();
    if (!dctx) {
        fprintf(stderr, "error: ZSTD_createDCtx failed\n");
        free(entries);
        if (ddict) ZSTD_freeDDict(ddict);
        free(dict_buf); fclose(f); return 1;
    }

    size_t   comp_cap  = ZSTD_compressBound(CHUNK_SIZE);
    size_t   raw_cap   = CHUNK_SIZE;
    uint8_t *comp_buf  = (uint8_t *)malloc(comp_cap);
    uint8_t *raw_buf   = (uint8_t *)malloc(raw_cap);

    /* Per-field extraction buffers — large enough for any realistic field */
    char *f_ts     = (char *)malloc(FBUFSZ);
    char *f_level  = (char *)malloc(FBUFSZ);
    char *f_user   = (char *)malloc(FBUFSZ);
    char *f_ip     = (char *)malloc(FBUFSZ);
    char *f_action = (char *)malloc(FBUFSZ);
    char *f_msg    = (char *)malloc(FBUFSZ);

    if (!comp_buf || !raw_buf || !f_ts || !f_level || !f_user ||
        !f_ip || !f_action || !f_msg) {
        fprintf(stderr, "error: OOM for buffers\n");
        goto cleanup_early;
    }

    /* --- CSV header --- */
    if (fmt_csv)
        fputs("timestamp,level,user,ip,action,message,raw\n", stdout);

    /* --- Main export loop --- */
    static const char *TS_KEYS[]     = { "timestamp", "time", "ts", "@timestamp" };
    static const char *LEVEL_KEYS[]  = { "level", "severity" };
    static const char *USER_KEYS[]   = { "user", "user_id", "username" };
    static const char *IP_KEYS[]     = { "ip", "ip_address" };
    static const char *ACTION_KEYS[] = { "action" };
    static const char *MSG_KEYS[]    = { "message", "msg" };

    uint64_t lines_exported   = 0;
    uint32_t chunks_processed = 0;
    uint32_t chunks_skipped   = 0;
    int      rc               = 0;

    for (uint32_t ci = 0; ci < num_chunks; ci++) {
        JumpEntry *e = &entries[ci];

        /* Time-range skip (same as search.c layer 1) */
        if (from_date || to_date) {
            int has_ts = (e->min_ts != 0 || e->max_ts != 0);
            if (has_ts) {
                if (from_date && e->max_ts < from_ts) { chunks_skipped++; continue; }
                if (to_date   && e->min_ts > to_ts)   { chunks_skipped++; continue; }
            }
        }
        chunks_processed++;

        /* Grow buffers if needed */
        if (e->comp_size > comp_cap) {
            free(comp_buf);
            comp_cap = (size_t)e->comp_size * 2;
            if (!(comp_buf = (uint8_t *)malloc(comp_cap))) {
                fprintf(stderr, "error: OOM growing comp_buf\n");
                rc = 1; goto cleanup;
            }
        }
        if (e->orig_size > raw_cap) {
            free(raw_buf);
            raw_cap = (size_t)e->orig_size;
            if (!(raw_buf = (uint8_t *)malloc(raw_cap))) {
                fprintf(stderr, "error: OOM growing raw_buf\n");
                rc = 1; goto cleanup;
            }
        }

        if (fseek(f, (long)e->offset, SEEK_SET) != 0 ||
            fread(comp_buf, 1, e->comp_size, f) != e->comp_size) {
            fprintf(stderr, "error: cannot read chunk %u\n", ci);
            rc = 1; goto cleanup;
        }

        size_t dec_size;
        if (ddict)
            dec_size = ZSTD_decompress_usingDDict(dctx, raw_buf, e->orig_size,
                                                  comp_buf, e->comp_size, ddict);
        else
            dec_size = ZSTD_decompressDCtx(dctx, raw_buf, e->orig_size,
                                           comp_buf, e->comp_size);

        if (ZSTD_isError(dec_size)) {
            fprintf(stderr, "error: decompression failed chunk %u: %s\n",
                    ci, ZSTD_getErrorName(dec_size));
            rc = 1; goto cleanup;
        }

        /* Process line by line */
        const char *p   = (const char *)raw_buf;
        const char *end = p + dec_size;

        while (p < end) {
            /* Locate next newline */
            const char *nl = memchr(p, '\n', (size_t)(end - p));
            size_t line_len = nl ? (size_t)(nl - p) : (size_t)(end - p);

            /* Skip empty lines — matches Python `if not line: continue` */
            if (line_len == 0) {
                p = nl ? nl + 1 : end;
                continue;
            }

            /* raw: line with trailing \r stripped (Python .rstrip('\r\n') on a
             * single line — the \n was already consumed as the splitter) */
            size_t raw_len = line_len;
            while (raw_len > 0 && (p[raw_len - 1] == '\r' || p[raw_len - 1] == '\n'))
                raw_len--;

            if (is_json) {
                /* Extract structured fields from the JSON key-value pairs */
                extract_first(p, line_len, TS_KEYS,     4, f_ts,     FBUFSZ);
                extract_first(p, line_len, LEVEL_KEYS,  2, f_level,  FBUFSZ);
                extract_first(p, line_len, USER_KEYS,   3, f_user,   FBUFSZ);
                extract_first(p, line_len, IP_KEYS,     2, f_ip,     FBUFSZ);
                extract_first(p, line_len, ACTION_KEYS, 1, f_action, FBUFSZ);
                extract_first(p, line_len, MSG_KEYS,    2, f_msg,    FBUFSZ);
            } else {
                /* Non-JSON: all structured fields empty, only raw populated */
                f_ts[0] = f_level[0] = f_user[0] =
                f_ip[0] = f_action[0] = f_msg[0] = '\0';
            }

            if (fmt_csv) {
                write_csv_row(stdout,
                    f_ts,     strlen(f_ts),
                    f_level,  strlen(f_level),
                    f_user,   strlen(f_user),
                    f_ip,     strlen(f_ip),
                    f_action, strlen(f_action),
                    f_msg,    strlen(f_msg),
                    p,        raw_len);
            } else {
                write_json_record(stdout,
                    f_ts,     strlen(f_ts),
                    f_level,  strlen(f_level),
                    f_user,   strlen(f_user),
                    f_ip,     strlen(f_ip),
                    f_action, strlen(f_action),
                    f_msg,    strlen(f_msg),
                    p,        raw_len);
            }
            lines_exported++;
            p = nl ? nl + 1 : end;
        }
    }

    /* --- Stats to stderr — mirrors export.py format exactly --- */
    fprintf(stderr,
            "Exported: %llu lines  |  Chunks: %u processed, %u skipped\n",
            (unsigned long long)lines_exported,
            chunks_processed, chunks_skipped);

cleanup:
    free(f_ts); free(f_level); free(f_user);
    free(f_ip); free(f_action); free(f_msg);
    free(comp_buf);
    free(raw_buf);
    ZSTD_freeDCtx(dctx);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(f);
    return rc;

cleanup_early:
    free(f_ts); free(f_level); free(f_user);
    free(f_ip); free(f_action); free(f_msg);
    free(comp_buf); free(raw_buf);
    ZSTD_freeDCtx(dctx);
    free(entries);
    if (ddict) ZSTD_freeDDict(ddict);
    free(dict_buf);
    fclose(f);
    return 1;
}
