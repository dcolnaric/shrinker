/*
 * retention.c — Retention policy YAML DSL (Phase 5 Step 29)
 *
 * Implements:
 *   retention_parse_yaml()  — hand-rolled YAML parser for retention.yaml
 *   retention_apply()       — S3 list + lock/delete enforcement + dry-run
 *
 * YAML parser design:
 *   - Line-by-line, state machine with two states: root and in-streams.
 *   - Blank lines and comment lines (leading #) are skipped.
 *   - Splits on the first ':' → key / value; strips whitespace + quotes.
 *   - List items start with "- " (after leading whitespace is stripped).
 *   - Only the fields defined in RetentionStream are recognised;
 *     unknown keys are silently ignored (forward-compat).
 *
 * Retention logic (per object):
 *   1. s3_check_lock() → is the object locked? retain-until date?
 *   2. If locked and retain-until is future: OK (print remaining days).
 *   3. If lock=true in config and object not locked (or lock expired):
 *      → apply Compliance lock for retention_days from last-modified.
 *   4. If retention_days have elapsed since last-modified and no active lock:
 *      → delete the object.
 *   5. Otherwise: OK (print days until expiry).
 */

#define _GNU_SOURCE            /* strdup, strptime, timegm */
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <fnmatch.h>           /* fnmatch() — POSIX, no extra deps */
#include "s3.h"
#include "retention.h"

/* -------------------------------------------------------------------------
 * YAML parser helpers
 * ------------------------------------------------------------------------- */

/* Strip leading whitespace in-place (advances *p). */
static void skip_ws(char **p)
{
    while (**p == ' ' || **p == '\t') (*p)++;
}

/* Strip trailing whitespace + newline from s in-place. */
static void rtrim(char *s)
{
    size_t n = strlen(s);
    while (n > 0 && ((unsigned char)s[n-1] <= ' ')) s[--n] = '\0';
}

/* Strip surrounding single or double quotes from *val in-place.
 * Advances *val past the opening quote and NUL-terminates before the closing
 * one.  No-op if the value is not quoted. */
static void strip_quotes(char **val)
{
    char q = (*val)[0];
    if (q != '"' && q != '\'') return;
    size_t n = strlen(*val);
    if (n >= 2 && (*val)[n-1] == q) {
        (*val)[n-1] = '\0';
        (*val)++;
    }
}

/* -------------------------------------------------------------------------
 * retention_parse_yaml
 * ------------------------------------------------------------------------- */

int retention_parse_yaml(const char *path, RetentionConfig *cfg)
{
    FILE *f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "retention: cannot open '%s': %s\n",
                path, strerror(errno));
        return -1;
    }

    memset(cfg, 0, sizeof(*cfg));

    char line[2048];
    int  lineno       = 0;
    int  in_streams   = 0;   /* saw "streams:" at root level */
    int  in_entry     = 0;   /* inside a "- " list item      */
    int  current      = -1;  /* index of current stream entry */

    while (fgets(line, sizeof(line), f)) {
        lineno++;

        /* Strip trailing whitespace + newline */
        rtrim(line);

        char *p = line;
        skip_ws(&p);

        /* Skip blank lines and comments */
        if (*p == '\0' || *p == '#') continue;

        /* Detect root-level "streams:" */
        if (!in_streams) {
            if (strncmp(p, "streams:", 8) == 0)
                in_streams = 1;
            /* Any other root key is ignored */
            continue;
        }

        /* --- We are inside the streams section --- */

        /* Does this line start a new list item ("- ")? */
        int new_item = 0;
        if (strncmp(p, "- ", 2) == 0) {
            new_item = 1;
            p += 2;
            skip_ws(&p);
        } else if (*p == '-' && p[1] == '\0') {
            /* bare "- " with no key on the same line — unusual, but OK */
            new_item = 1;
            p++;
            skip_ws(&p);
        }

        /* Find the first ':' to split key / value */
        char *colon = strchr(p, ':');
        if (!colon) {
            /* No colon — could be "streams:" continuation or bare "-";
             * skip silently. */
            if (new_item) {
                /* Start an empty entry — subsequent lines will fill it */
                current++;
                if (current >= RETENTION_MAX_STREAMS) {
                    fprintf(stderr,
                            "retention: line %d: too many streams (max %d)\n",
                            lineno, RETENTION_MAX_STREAMS);
                    fclose(f);
                    return -1;
                }
                cfg->num_streams = current + 1;
                in_entry = 1;
            }
            continue;
        }

        /* Split at first colon */
        *colon = '\0';
        char *key = p;
        char *val = colon + 1;
        rtrim(key);
        skip_ws(&val);
        rtrim(val);
        strip_quotes(&val);

        /* Starting a new list item? */
        if (new_item) {
            current++;
            if (current >= RETENTION_MAX_STREAMS) {
                fprintf(stderr,
                        "retention: line %d: too many streams (max %d)\n",
                        lineno, RETENTION_MAX_STREAMS);
                fclose(f);
                return -1;
            }
            cfg->num_streams = current + 1;
            in_entry = 1;
        }

        if (!in_entry || current < 0) continue;

        RetentionStream *s = &cfg->streams[current];

        if (strcmp(key, "name") == 0) {
            strncpy(s->name, val, sizeof(s->name) - 1);
        } else if (strcmp(key, "pattern") == 0) {
            strncpy(s->pattern, val, sizeof(s->pattern) - 1);
        } else if (strcmp(key, "retention_days") == 0) {
            s->retention_days = atoi(val);
        } else if (strcmp(key, "lock") == 0) {
            s->lock = (strcmp(val, "true")  == 0 ||
                       strcmp(val, "yes")   == 0 ||
                       strcmp(val, "1")     == 0);
        }
        /* Unknown keys are silently ignored (forward-compat) */
    }

    fclose(f);

    /* Validate all parsed streams */
    for (int i = 0; i < cfg->num_streams; i++) {
        RetentionStream *s = &cfg->streams[i];

        if (s->name[0] == '\0') {
            fprintf(stderr,
                    "retention: stream %d: missing required field 'name'\n",
                    i + 1);
            return -1;
        }
        if (s->pattern[0] == '\0') {
            fprintf(stderr,
                    "retention: stream '%s': missing required field 'pattern'\n",
                    s->name);
            return -1;
        }
        if (!s3_is_url(s->pattern)) {
            fprintf(stderr,
                    "retention: stream '%s': pattern must be an S3 URL "
                    "(s3://bucket/key-glob), got: %s\n",
                    s->name, s->pattern);
            return -1;
        }
        if (s->retention_days <= 0) {
            fprintf(stderr,
                    "retention: stream '%s': retention_days must be a "
                    "positive integer (got %d)\n",
                    s->name, s->retention_days);
            return -1;
        }
    }

    if (cfg->num_streams == 0) {
        fprintf(stderr,
                "retention: '%s': no streams defined — "
                "add at least one '- name:' block under 'streams:'\n", path);
        return -1;
    }

    return 0;
}

/* -------------------------------------------------------------------------
 * retention_apply helpers
 * ------------------------------------------------------------------------- */

/*
 * Parse the key-glob portion of an s3:// pattern into:
 *   bucket   — the bucket name
 *   key_glob — the key portion of the URL (may contain '*')
 *   prefix   — everything in key_glob before the first '*'
 *              (used as the S3 list prefix to narrow down results)
 *
 * Returns 0 on success, -1 on failure.
 */
static int parse_s3_glob(const char *pattern,
                          char *bucket,   size_t bucket_sz,
                          char *key_glob, size_t key_glob_sz,
                          char *prefix,   size_t prefix_sz)
{
    if (strncmp(pattern, "s3://", 5) != 0) return -1;
    const char *rest  = pattern + 5;
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;

    /* bucket */
    size_t blen = (size_t)(slash - rest);
    if (blen == 0 || blen >= bucket_sz) return -1;
    memcpy(bucket, rest, blen);
    bucket[blen] = '\0';

    /* key glob — strip leading slashes */
    const char *k = slash + 1;
    while (*k == '/') k++;
    if (strlen(k) >= key_glob_sz) return -1;
    strcpy(key_glob, k);

    /* prefix = key_glob up to (but not including) the first '*' */
    const char *star = strchr(key_glob, '*');
    if (!star) {
        /* No wildcard — use the full key as prefix */
        strncpy(prefix, key_glob, prefix_sz - 1);
        prefix[prefix_sz - 1] = '\0';
    } else {
        size_t plen = (size_t)(star - key_glob);
        if (plen >= prefix_sz) plen = prefix_sz - 1;
        memcpy(prefix, key_glob, plen);
        prefix[plen] = '\0';
    }

    return 0;
}

/*
 * Parse an ISO 8601 UTC timestamp (as returned by S3 APIs) into time_t.
 * Supports:
 *   "2025-01-15T10:30:00.000Z"  (with fractional seconds)
 *   "2025-01-15T10:30:00Z"
 *
 * Returns (time_t)-1 on failure.
 */
static time_t parse_iso8601(const char *s)
{
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    /* strptime stops at the first unrecognised char — handles both
     * "...00Z" and "...00.000Z" since strptime reads up to the 'Z'. */
    char *end = strptime(s, "%Y-%m-%dT%H:%M:%S", &tm);
    if (!end) return (time_t)-1;
    return timegm(&tm);
}

/*
 * Format time_t as "YYYY-MM-DD" (UTC, 10 chars + NUL).
 */
static void fmt_date(time_t t, char *out, size_t out_size)
{
    struct tm *gm = gmtime(&t);
    strftime(out, out_size, "%Y-%m-%d", gm);
}

/*
 * Format time_t as full ISO 8601 UTC for Object Lock retain-until.
 */
static void fmt_iso8601(time_t t, char *out, size_t out_size)
{
    struct tm *gm = gmtime(&t);
    strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", gm);
}

/* -------------------------------------------------------------------------
 * retention_apply
 * ------------------------------------------------------------------------- */

int retention_apply(const RetentionConfig *cfg,
                    const char *region_override,
                    int dry_run)
{
    /* Load AWS credentials once for all streams */
    S3Creds creds;
    if (s3_load_creds(&creds) != 0) return 1;
    if (region_override)
        strncpy(creds.region, region_override, sizeof(creds.region) - 1);

    int rc = 0;
    time_t now = time(NULL);

    for (int i = 0; i < cfg->num_streams; i++) {
        const RetentionStream *s = &cfg->streams[i];

        fprintf(stderr,
                "[%s] pattern=%s retention_days=%d lock=%s\n",
                s->name, s->pattern, s->retention_days,
                s->lock ? "true" : "false");

        /* Parse glob pattern → bucket, key_glob, prefix */
        char bucket[256], key_glob[1024], prefix[1024];
        if (parse_s3_glob(s->pattern,
                          bucket,   sizeof(bucket),
                          key_glob, sizeof(key_glob),
                          prefix,   sizeof(prefix)) != 0) {
            fprintf(stderr,
                    "retention: stream '%s': invalid S3 pattern: %s\n",
                    s->name, s->pattern);
            rc = 1;
            continue;
        }

        /* List matching objects */
        S3Object *objects = malloc(sizeof(S3Object) * S3_LIST_MAX);
        if (!objects) { perror("retention: malloc"); return 1; }

        int count = s3_list(&creds, bucket, prefix, objects, S3_LIST_MAX);
        if (count < 0) {
            fprintf(stderr,
                    "retention: stream '%s': failed to list s3://%s/%s\n",
                    s->name, bucket, prefix);
            free(objects);
            rc = 1;
            continue;
        }

        if (count == 0) {
            fprintf(stderr,
                    "  (no objects found matching prefix '%s')\n", prefix);
        }

        for (int j = 0; j < count; j++) {
            /* Apply glob filter — fnmatch pattern is the key_glob portion */
            if (fnmatch(key_glob, objects[j].key, FNM_PATHNAME) != 0)
                continue;

            /* s3://  (5) + bucket (255) + / (1) + key (1023) + NUL = 1285 */
            char s3url[1290];
            snprintf(s3url, sizeof(s3url), "s3://%s/%s",
                     bucket, objects[j].key);

            /* Parse last-modified date (from ListObjectsV2 response) */
            time_t last_mod = parse_iso8601(objects[j].last_modified);
            time_t expiry_t = (last_mod != (time_t)-1)
                              ? last_mod + (time_t)s->retention_days * 86400L
                              : (time_t)-1;
            int retention_expired = (expiry_t != (time_t)-1 && now >= expiry_t);

            /* Check existing Object Lock status */
            char lock_mode[32]  = "";
            char lock_until[40] = "";
            if (s3_check_lock(&creds, bucket, objects[j].key,
                              lock_mode, sizeof(lock_mode),
                              lock_until, sizeof(lock_until)) != 0) {
                fprintf(stderr,
                        "  ERROR: could not check lock on %s\n", s3url);
                rc = 1;
                continue;
            }

            int is_locked = (lock_mode[0] != '\0');
            int days_remaining = 0;

            if (is_locked) {
                time_t until_t = parse_iso8601(lock_until);
                if (until_t != (time_t)-1) {
                    long diff = (long)(until_t - now);
                    days_remaining = (int)(diff / 86400L);
                    if (days_remaining <= 0) {
                        /* Lock has expired — treat as unlocked */
                        is_locked      = 0;
                        days_remaining = 0;
                    }
                }
            }

            /* --- Decision logic --- */

            if (is_locked && days_remaining > 0) {
                /* Object has an active Compliance lock — nothing to do */
                printf("OK:           %s (locked %s, %d days remaining)\n",
                       s3url, lock_mode, days_remaining);

            } else if (!is_locked && s->lock && !retention_expired) {
                /* Should be locked; apply / re-apply Compliance lock.
                 * Retain-until = last_modified + retention_days.
                 * If last_mod is unknown, use today + retention_days. */
                time_t lock_until_t = (last_mod != (time_t)-1)
                    ? last_mod + (time_t)s->retention_days * 86400L
                    : now + (time_t)s->retention_days * 86400L;
                char lock_until_str[40];
                fmt_iso8601(lock_until_t, lock_until_str, sizeof(lock_until_str));
                char lock_date[16];
                fmt_date(lock_until_t, lock_date, sizeof(lock_date));

                if (dry_run) {
                    printf("WOULD LOCK:   %s (retain until %s)\n",
                           s3url, lock_date);
                } else {
                    printf("LOCK:         %s (retain until %s)\n",
                           s3url, lock_date);
                    if (s3_set_retention(&creds, bucket, objects[j].key,
                                        "COMPLIANCE", lock_until_str) != 0) {
                        fprintf(stderr,
                                "  ERROR: failed to set lock on %s\n", s3url);
                        rc = 1;
                    }
                }

            } else if (retention_expired && !is_locked) {
                /* Retention period has elapsed and there is no active lock */
                if (dry_run) {
                    printf("WOULD DELETE: %s\n", s3url);
                } else {
                    printf("DELETE:       %s\n", s3url);
                    if (s3_delete_object(&creds, bucket, objects[j].key) != 0) {
                        fprintf(stderr,
                                "  ERROR: failed to delete %s\n", s3url);
                        rc = 1;
                    }
                }

            } else {
                /* Unlocked, lock=false, within retention window */
                if (expiry_t != (time_t)-1) {
                    int days_left = (int)((expiry_t - now) / 86400L);
                    char exp_date[16];
                    fmt_date(expiry_t, exp_date, sizeof(exp_date));
                    printf("OK:           %s (unlocked, %d days until expiry %s)\n",
                           s3url, days_left, exp_date);
                } else {
                    printf("OK:           %s (unlocked, last-modified unknown)\n",
                           s3url);
                }
            }
        }  /* for each object */

        free(objects);
    }  /* for each stream */

    return rc;
}
