/*
 * s3.c — S3 read/write via libcurl + AWS Signature Version 4 (Phase 5 Steps 27–28)
 *
 * Step 27: credential chain, GET/PUT/HEAD, SigV4 signing.
 * Step 28: Object Lock COMPLIANCE mode on PUT; verify-lock via HEAD.
 *
 * Object Lock signing:
 *   When lock_days > 0 in s3_upload(), two extra headers are added to the
 *   SigV4 signed-headers list (alphabetically between x-amz-date and
 *   x-amz-security-token):
 *     x-amz-object-lock-mode: COMPLIANCE
 *     x-amz-object-lock-retain-until-date: <ISO 8601 UTC>
 *   They must be signed to prevent tampering in transit.
 *
 * s3_check_lock(): HEAD request + response-header capture.
 *   AWS returns x-amz-object-lock-mode and
 *   x-amz-object-lock-retain-until-date as response headers when the
 *   object is locked.
 */

#define _GNU_SOURCE          /* strdup, getenv */
#define _FILE_OFFSET_BITS 64 /* 64-bit file offsets */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>            /* close, unlink, lseek */
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "s3.h"

/* -------------------------------------------------------------------------
 * One-time libcurl global initialisation (lazy, single-threaded CLI)
 * ------------------------------------------------------------------------- */

static void ensure_curl_init(void)
{
    static int done = 0;
    if (!done) {
        curl_global_init(CURL_GLOBAL_DEFAULT);
        done = 1;
    }
}

/* -------------------------------------------------------------------------
 * Growing memory buffer — used for response bodies and headers
 * ------------------------------------------------------------------------- */

typedef struct {
    char  *data;
    size_t size;
    size_t alloc;
} MemBuf;

static size_t membuf_write(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    MemBuf *b = (MemBuf *)userdata;
    size_t n = size * nmemb;
    if (b->size + n + 1 > b->alloc) {
        size_t new_alloc = (b->alloc + n + 1) * 2 + 64;
        char *tmp = realloc(b->data, new_alloc);
        if (!tmp) return 0;
        b->data  = tmp;
        b->alloc = new_alloc;
    }
    memcpy(b->data + b->size, ptr, n);
    b->size += n;
    b->data[b->size] = '\0';
    return n;
}

static size_t file_write(void *ptr, size_t size, size_t nmemb, void *userdata)
{
    return fwrite(ptr, size, nmemb, (FILE *)userdata);
}

/* -------------------------------------------------------------------------
 * Crypto helpers
 * ------------------------------------------------------------------------- */

static const char HEX_LC[] = "0123456789abcdef";

static void hex_encode(const uint8_t *in, size_t len, char *out)
{
    for (size_t i = 0; i < len; i++) {
        out[i*2]   = HEX_LC[in[i] >> 4];
        out[i*2+1] = HEX_LC[in[i] & 0x0f];
    }
    out[len*2] = '\0';
}

static void hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *data, size_t data_len,
                        uint8_t out[32])
{
    unsigned int out_len = 32;
    HMAC(EVP_sha256(), key, (int)key_len, data, data_len, out, &out_len);
}

static void sha256_str_hex(const char *str, size_t len, char hex_out[65])
{
    uint8_t hash[32];
    unsigned int hlen = 32;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, str, len);
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);
    hex_encode(hash, 32, hex_out);
}

static int sha256_file_hex(const char *path, char hex_out[65])
{
    uint8_t buf[65536], hash[32];
    unsigned int hlen = 32;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        EVP_DigestUpdate(ctx, buf, n);
    fclose(f);
    EVP_DigestFinal_ex(ctx, hash, &hlen);
    EVP_MD_CTX_free(ctx);
    hex_encode(hash, 32, hex_out);
    return 0;
}

#define EMPTY_PAYLOAD_SHA256 \
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

/* -------------------------------------------------------------------------
 * URL encoding for S3 object keys (unreserved chars + '/' pass through)
 * ------------------------------------------------------------------------- */

static const char HEX_UC[] = "0123456789ABCDEF";

static void url_encode_key(const char *key, char *out, size_t out_size)
{
    size_t j = 0;
    for (size_t i = 0; key[i] && j + 4 < out_size; i++) {
        unsigned char c = (unsigned char)key[i];
        if (c == '/' || isalnum(c) || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%';
            out[j++] = HEX_UC[c >> 4];
            out[j++] = HEX_UC[c & 0x0f];
        }
    }
    out[j] = '\0';
}

/* -------------------------------------------------------------------------
 * Object Lock: compute the ISO 8601 UTC retain-until date.
 * ------------------------------------------------------------------------- */

static void compute_lock_until(int lock_days, char *out, size_t out_size)
{
    /* today + lock_days × 86400 s, expressed as UTC ISO 8601 */
    time_t t = time(NULL) + (time_t)lock_days * 86400L;
    struct tm *gmt = gmtime(&t);
    strftime(out, out_size, "%Y-%m-%dT%H:%M:%SZ", gmt);
}

/* -------------------------------------------------------------------------
 * Response-header scanner.
 *
 * AWS response headers are accumulated by membuf_write via
 * CURLOPT_HEADERFUNCTION.  Each line is "Name: value\r\n".
 * This function finds the first matching header (case-insensitive name)
 * and copies the value (stripped of surrounding whitespace) into out.
 * Returns 1 if found, 0 otherwise.
 * ------------------------------------------------------------------------- */

static int resp_header_val(const char *headers, const char *name,
                           char *out, size_t out_size)
{
    size_t nlen = strlen(name);
    const char *p = headers;
    while (*p) {
        if (strncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            p += nlen + 1;
            while (*p == ' ' || *p == '\t') p++;
            size_t i = 0;
            while (*p && *p != '\r' && *p != '\n' && i + 1 < out_size)
                out[i++] = *p++;
            /* strip trailing whitespace */
            while (i > 0 && (out[i-1] == ' ' || out[i-1] == '\t'))
                i--;
            out[i] = '\0';
            return (i > 0);
        }
        /* advance to next line */
        while (*p && *p != '\n') p++;
        if (*p == '\n') p++;
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * AWS Signature Version 4
 *
 * Signed headers are built in alphabetical order.  With Object Lock:
 *
 *   host
 *   x-amz-content-sha256
 *   x-amz-date
 *   x-amz-object-lock-mode             (only when lock_mode != "")
 *   x-amz-object-lock-retain-until-date (only when lock_until != "")
 *   x-amz-security-token               (only when session token present)
 *
 * Parameters:
 *   lock_mode  — "COMPLIANCE" or "" (empty = no Object Lock)
 *   lock_until — ISO 8601 UTC date or "" (paired with lock_mode)
 *   signed_hdrs_out — caller buffer, must be ≥ 256 bytes
 * ------------------------------------------------------------------------- */

static void sigv4_build_auth(
    const char *method,
    const char *bucket,
    const char *key,
    const char *canonical_qs,      /* sorted, percent-encoded; "" = empty */
    const char *region,
    const char *access_key,
    const char *secret_key,
    const char *session_token,    /* may be empty string, never NULL */
    const char *payload_sha256,
    const char *datetime,         /* "YYYYMMDDTHHMMSSZ" */
    const char *dateonly,         /* "YYYYMMDD" */
    const char *lock_mode,        /* "COMPLIANCE" or "" */
    const char *lock_until,       /* ISO 8601 or "" */
    char *auth_out, size_t auth_out_size,
    char  signed_hdrs_out[256])
{
    int has_token = (session_token[0] != '\0');
    int has_lock  = (lock_mode[0] != '\0' && lock_until[0] != '\0');

    /* ---- endpoint host -------------------------------------------------- */
    char host[512];
    if (strcmp(region, "us-east-1") == 0)
        snprintf(host, sizeof(host), "%s.s3.amazonaws.com", bucket);
    else
        snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com", bucket, region);

    /* ---- signed headers list (alphabetical) ----------------------------- */
    /*
     * Alphabetical order among x-amz-* headers:
     *   x-amz-content-sha256 < x-amz-date < x-amz-object-lock-* < x-amz-security-token
     * Within object-lock:
     *   x-amz-object-lock-mode < x-amz-object-lock-retain-until-date
     *   ('m' < 'r')
     */
    if (has_lock && has_token)
        strcpy(signed_hdrs_out,
               "host;x-amz-content-sha256;x-amz-date;"
               "x-amz-object-lock-mode;x-amz-object-lock-retain-until-date;"
               "x-amz-security-token");
    else if (has_lock)
        strcpy(signed_hdrs_out,
               "host;x-amz-content-sha256;x-amz-date;"
               "x-amz-object-lock-mode;x-amz-object-lock-retain-until-date");
    else if (has_token)
        strcpy(signed_hdrs_out,
               "host;x-amz-content-sha256;x-amz-date;x-amz-security-token");
    else
        strcpy(signed_hdrs_out, "host;x-amz-content-sha256;x-amz-date");

    /* ---- canonical URI -------------------------------------------------- */
    char enc_key[4096];
    url_encode_key(key, enc_key, sizeof(enc_key));
    char canonical_uri[5120];
    snprintf(canonical_uri, sizeof(canonical_uri), "/%s", enc_key);

    /* ---- canonical headers (alphabetical, each line ends with '\n') ----- */
    /*
     * Build the block dynamically so all four combinations (lock×token)
     * are handled without nested ternaries.
     */
    char canonical_hdrs[8192];
    {
        int pos = 0;
        /* host */
        pos += snprintf(canonical_hdrs + pos, sizeof(canonical_hdrs) - (size_t)pos,
                        "host:%s\n", host);
        /* x-amz-content-sha256 */
        pos += snprintf(canonical_hdrs + pos, sizeof(canonical_hdrs) - (size_t)pos,
                        "x-amz-content-sha256:%s\n", payload_sha256);
        /* x-amz-date */
        pos += snprintf(canonical_hdrs + pos, sizeof(canonical_hdrs) - (size_t)pos,
                        "x-amz-date:%s\n", datetime);
        /* x-amz-object-lock-mode (if lock) */
        if (has_lock)
            pos += snprintf(canonical_hdrs + pos,
                            sizeof(canonical_hdrs) - (size_t)pos,
                            "x-amz-object-lock-mode:%s\n", lock_mode);
        /* x-amz-object-lock-retain-until-date (if lock) */
        if (has_lock)
            pos += snprintf(canonical_hdrs + pos,
                            sizeof(canonical_hdrs) - (size_t)pos,
                            "x-amz-object-lock-retain-until-date:%s\n",
                            lock_until);
        /* x-amz-security-token (if present) */
        if (has_token)
            snprintf(canonical_hdrs + pos,
                     sizeof(canonical_hdrs) - (size_t)pos,
                     "x-amz-security-token:%s\n", session_token);
    }

    /* ---- canonical request ---------------------------------------------- */
    /* canonical_hdrs already ends with '\n'; the '\n' in "%s\n" below adds
     * the required blank-line separator before the SignedHeaders line.       */
    char canonical_req[16384];
    snprintf(canonical_req, sizeof(canonical_req),
             "%s\n"    /* method                             */
             "%s\n"    /* canonical URI                      */
             "%s\n"    /* canonical query string (may be "") */
             "%s\n"    /* canonical headers + blank separator */
             "%s\n"    /* signed headers                     */
             "%s",     /* payload hash                       */
             method, canonical_uri, canonical_qs, canonical_hdrs,
             signed_hdrs_out, payload_sha256);

    /* ---- hash the canonical request ------------------------------------ */
    char cr_hash[65];
    sha256_str_hex(canonical_req, strlen(canonical_req), cr_hash);

    /* ---- credential scope ---------------------------------------------- */
    char cred_scope[256];
    snprintf(cred_scope, sizeof(cred_scope),
             "%s/%s/s3/aws4_request", dateonly, region);

    /* ---- string to sign ------------------------------------------------- */
    char sts[1024];
    snprintf(sts, sizeof(sts),
             "AWS4-HMAC-SHA256\n"
             "%s\n"    /* datetime         */
             "%s\n"    /* credential scope */
             "%s",     /* canonical request hash */
             datetime, cred_scope, cr_hash);

    /* ---- derived signing key -------------------------------------------- */
    char aws4_secret[256];
    snprintf(aws4_secret, sizeof(aws4_secret), "AWS4%s", secret_key);

    uint8_t k_date[32], k_region[32], k_service[32], k_signing[32];
    hmac_sha256((uint8_t *)aws4_secret, strlen(aws4_secret),
                (uint8_t *)dateonly,    strlen(dateonly),    k_date);
    hmac_sha256(k_date,    32, (uint8_t *)region, strlen(region), k_region);
    hmac_sha256(k_region,  32, (uint8_t *)"s3",   2,              k_service);
    hmac_sha256(k_service, 32, (uint8_t *)"aws4_request", 12,     k_signing);

    /* ---- signature ------------------------------------------------------ */
    uint8_t sig_bytes[32];
    hmac_sha256(k_signing, 32, (uint8_t *)sts, strlen(sts), sig_bytes);
    char signature[65];
    hex_encode(sig_bytes, 32, signature);

    /* ---- Authorization header value ------------------------------------ */
    snprintf(auth_out, auth_out_size,
             "AWS4-HMAC-SHA256 "
             "Credential=%s/%s, "
             "SignedHeaders=%s, "
             "Signature=%s",
             access_key, cred_scope, signed_hdrs_out, signature);
}

/* -------------------------------------------------------------------------
 * Build the curl_slist of signed request headers and set CURLOPT_URL.
 *
 * lock_mode  — "COMPLIANCE" or "" (no lock)
 * lock_until — ISO 8601 retain-until date or ""
 *
 * Returns a curl_slist* the caller must free with curl_slist_free_all().
 * ------------------------------------------------------------------------- */

static struct curl_slist *make_signed_headers(
    CURL *ch,
    const char *method,
    const char *bucket,
    const char *key,
    const char *canonical_qs,  /* sorted encoded query string; "" = none */
    const S3Creds *creds,
    const char *payload_sha256,
    const char *lock_mode,     /* "COMPLIANCE" or "" */
    const char *lock_until)    /* ISO 8601 date  or "" */
{
    /* current UTC time */
    time_t now = time(NULL);
    struct tm *t = gmtime(&now);
    char datetime[17], dateonly[9];
    strftime(datetime, sizeof(datetime), "%Y%m%dT%H%M%SZ", t);
    strftime(dateonly, sizeof(dateonly), "%Y%m%d", t);

    /* endpoint */
    char host[512];
    if (strcmp(creds->region, "us-east-1") == 0)
        snprintf(host, sizeof(host), "%s.s3.amazonaws.com", bucket);
    else
        snprintf(host, sizeof(host), "%s.s3.%s.amazonaws.com",
                 bucket, creds->region);

    /* URL — append ?query_string when a canonical query string is present */
    char enc_key[4096];
    url_encode_key(key, enc_key, sizeof(enc_key));
    char url[5632];
    if (canonical_qs[0])
        snprintf(url, sizeof(url), "https://%s/%s?%s", host, enc_key, canonical_qs);
    else
        snprintf(url, sizeof(url), "https://%s/%s", host, enc_key);
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* build Authorization value */
    char auth_value[1024];
    char signed_hdrs[256];
    sigv4_build_auth(method, bucket, key, canonical_qs, creds->region,
                     creds->access_key, creds->secret_key, creds->session_token,
                     payload_sha256, datetime, dateonly,
                     lock_mode, lock_until,
                     auth_value, sizeof(auth_value), signed_hdrs);

    /* assemble curl_slist (Host: explicit to suppress curl's automatic one) */
    struct curl_slist *hdrs = NULL;
    char hdr[2200];

    snprintf(hdr, sizeof(hdr), "Host: %s", host);
    hdrs = curl_slist_append(hdrs, hdr);

    snprintf(hdr, sizeof(hdr), "x-amz-date: %s", datetime);
    hdrs = curl_slist_append(hdrs, hdr);

    snprintf(hdr, sizeof(hdr), "x-amz-content-sha256: %s", payload_sha256);
    hdrs = curl_slist_append(hdrs, hdr);

    /* Object Lock headers — must appear in slist (and in canonical request) */
    if (lock_mode[0] && lock_until[0]) {
        snprintf(hdr, sizeof(hdr), "x-amz-object-lock-mode: %s", lock_mode);
        hdrs = curl_slist_append(hdrs, hdr);

        snprintf(hdr, sizeof(hdr),
                 "x-amz-object-lock-retain-until-date: %s", lock_until);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    if (creds->session_token[0]) {
        snprintf(hdr, sizeof(hdr), "x-amz-security-token: %s",
                 creds->session_token);
        hdrs = curl_slist_append(hdrs, hdr);
    }

    snprintf(hdr, sizeof(hdr), "Authorization: %s", auth_value);
    hdrs = curl_slist_append(hdrs, hdr);

    return hdrs;
}

/* -------------------------------------------------------------------------
 * Credential helpers
 * ------------------------------------------------------------------------- */

static int ini_get(const char *line, const char *key,
                   char *out, size_t out_size)
{
    while (*line == ' ' || *line == '\t') line++;
    size_t klen = strlen(key);
    if (strncasecmp(line, key, klen) != 0) return 0;
    line += klen;
    while (*line == ' ' || *line == '\t') line++;
    if (*line != '=') return 0;
    line++;
    while (*line == ' ' || *line == '\t') line++;
    size_t vlen = strlen(line);
    while (vlen > 0 && (line[vlen-1] == '\n' || line[vlen-1] == '\r' ||
                        line[vlen-1] == ' '  || line[vlen-1] == '\t'))
        vlen--;
    if (vlen >= out_size) vlen = out_size - 1;
    memcpy(out, line, vlen);
    out[vlen] = '\0';
    return (vlen > 0);
}

static int json_str(const char *json, const char *key,
                    char *out, size_t out_size)
{
    char search[256];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0;
    p += strlen(search);
    while (*p == ' ' || *p == '\t' || *p == ':') p++;
    if (*p != '"') return 0;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i + 1 < out_size)
        out[i++] = *p++;
    out[i] = '\0';
    return (i > 0);
}

static int load_from_imds(S3Creds *creds)
{
    ensure_curl_init();
    CURL *ch = curl_easy_init();
    if (!ch) return -1;

    MemBuf role = {0};
    curl_easy_setopt(ch, CURLOPT_URL,
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/");
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &role);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT,       2L);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT,1L);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL,      1L);

    CURLcode rc = curl_easy_perform(ch);
    if (rc != CURLE_OK || !role.data || role.size == 0) {
        free(role.data);
        curl_easy_cleanup(ch);
        return -1;
    }
    while (role.size > 0 &&
           (role.data[role.size-1] == '\n' || role.data[role.size-1] == '\r' ||
            role.data[role.size-1] == ' '))
        role.data[--role.size] = '\0';

    char url[512];
    snprintf(url, sizeof(url),
             "http://169.254.169.254/latest/meta-data/"
             "iam/security-credentials/%s", role.data);
    free(role.data);

    MemBuf body = {0};
    curl_easy_setopt(ch, CURLOPT_URL,       url);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, &body);
    rc = curl_easy_perform(ch);
    curl_easy_cleanup(ch);

    if (rc != CURLE_OK || !body.data) { free(body.data); return -1; }

    int ok = json_str(body.data, "AccessKeyId",
                      creds->access_key, sizeof(creds->access_key))  &&
             json_str(body.data, "SecretAccessKey",
                      creds->secret_key, sizeof(creds->secret_key));
    json_str(body.data, "Token",
             creds->session_token, sizeof(creds->session_token));
    free(body.data);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

int s3_is_url(const char *path)
{
    return (strncmp(path, "s3://", 5) == 0);
}

int s3_parse_url(const char *url, S3Url *out)
{
    if (!s3_is_url(url)) return -1;
    const char *rest  = url + 5;
    const char *slash = strchr(rest, '/');
    if (!slash) return -1;

    size_t blen = (size_t)(slash - rest);
    if (blen == 0 || blen >= sizeof(out->bucket)) return -1;
    memcpy(out->bucket, rest, blen);
    out->bucket[blen] = '\0';

    const char *key = slash + 1;
    while (*key == '/') key++;
    if (*key == '\0') return -1;
    size_t klen = strlen(key);
    if (klen >= sizeof(out->key)) return -1;
    memcpy(out->key, key, klen + 1);
    return 0;
}

int s3_load_creds(S3Creds *creds)
{
    memset(creds, 0, sizeof(*creds));

    const char *reg = getenv("AWS_DEFAULT_REGION");
    if (!reg || !*reg) reg = getenv("AWS_REGION");
    if (reg && *reg)
        strncpy(creds->region, reg, sizeof(creds->region) - 1);
    else
        strcpy(creds->region, "us-east-1");

    /* Tier 1: environment variables */
    const char *kid = getenv("AWS_ACCESS_KEY_ID");
    const char *sec = getenv("AWS_SECRET_ACCESS_KEY");
    if (kid && *kid && sec && *sec) {
        strncpy(creds->access_key, kid, sizeof(creds->access_key) - 1);
        strncpy(creds->secret_key, sec, sizeof(creds->secret_key) - 1);
        const char *tok = getenv("AWS_SESSION_TOKEN");
        if (!tok) tok = getenv("AWS_SECURITY_TOKEN");
        if (tok && *tok)
            strncpy(creds->session_token, tok,
                    sizeof(creds->session_token) - 1);
        return 0;
    }

    /* Tier 2: ~/.aws/credentials + ~/.aws/config */
    const char *home = getenv("HOME");
    if (home && *home) {
        char path[1024];

        snprintf(path, sizeof(path), "%s/.aws/credentials", home);
        FILE *f = fopen(path, "r");
        if (f) {
            char line[1024];
            int in_default = 0, found_key = 0, found_secret = 0;
            while (fgets(line, sizeof(line), f)) {
                if (line[0] == '[') {
                    in_default = (strncmp(line + 1, "default]", 8) == 0);
                    continue;
                }
                if (!in_default) continue;
                if (!found_key)
                    found_key = ini_get(line, "aws_access_key_id",
                                        creds->access_key,
                                        sizeof(creds->access_key));
                if (!found_secret)
                    found_secret = ini_get(line, "aws_secret_access_key",
                                           creds->secret_key,
                                           sizeof(creds->secret_key));
                ini_get(line, "aws_session_token",
                        creds->session_token, sizeof(creds->session_token));
            }
            fclose(f);
            if (found_key && found_secret) goto region_from_config;
        }

    region_from_config:
        snprintf(path, sizeof(path), "%s/.aws/config", home);
        FILE *fc = fopen(path, "r");
        if (fc) {
            char line[1024];
            int in_default = 0;
            while (fgets(line, sizeof(line), fc)) {
                if (line[0] == '[') {
                    in_default = (strncmp(line + 1, "default]",       8)  == 0 ||
                                  strncmp(line + 1, "profile default", 15) == 0);
                    continue;
                }
                if (!in_default) continue;
                ini_get(line, "region", creds->region, sizeof(creds->region));
            }
            fclose(fc);
        }

        if (creds->access_key[0] && creds->secret_key[0]) return 0;
    }

    /* Tier 3: EC2/ECS instance metadata */
    if (load_from_imds(creds) == 0) return 0;

    fprintf(stderr,
            "s3: error: no AWS credentials found.\n"
            "  Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY, or\n"
            "  configure ~/.aws/credentials, or run on an EC2/ECS\n"
            "  instance with an attached IAM role.\n");
    return -1;
}

int s3_download(const S3Creds *creds, const char *bucket, const char *key,
                const char *local_path)
{
    ensure_curl_init();

    FILE *out = fopen(local_path, "wb");
    if (!out) {
        fprintf(stderr, "s3: cannot open '%s' for writing: ", local_path);
        perror(NULL);
        return -1;
    }

    CURL *ch = curl_easy_init();
    if (!ch) { fclose(out); return -1; }

    struct curl_slist *hdrs = make_signed_headers(
        ch, "GET", bucket, key, "", creds, EMPTY_PAYLOAD_SHA256, "", "");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, file_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     out);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,1L);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    fclose(out);

    if (rc != CURLE_OK) {
        fprintf(stderr, "s3: download failed: %s\n", curl_easy_strerror(rc));
        return -1;
    }
    if (http_code == 404) {
        fprintf(stderr, "s3: object not found: s3://%s/%s\n", bucket, key);
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        fprintf(stderr, "s3: download HTTP %ld for s3://%s/%s\n",
                http_code, bucket, key);
        return -1;
    }
    return 0;
}

int s3_upload(const S3Creds *creds, const char *bucket, const char *key,
              const char *local_path, int lock_days)
{
    ensure_curl_init();

    char payload_sha256[65];
    if (sha256_file_hex(local_path, payload_sha256) != 0) {
        fprintf(stderr, "s3: cannot hash '%s' for upload\n", local_path);
        return -1;
    }

    FILE *in = fopen(local_path, "rb");
    if (!in) {
        fprintf(stderr, "s3: cannot open '%s' for upload\n", local_path);
        return -1;
    }
    fseek(in, 0, SEEK_END);
    curl_off_t file_size = (curl_off_t)ftell(in);
    rewind(in);

    /* Object Lock parameters */
    char lock_until[40] = "";
    const char *lock_mode = "";
    if (lock_days > 0) {
        compute_lock_until(lock_days, lock_until, sizeof(lock_until));
        lock_mode = "COMPLIANCE";
    }

    CURL *ch = curl_easy_init();
    if (!ch) { fclose(in); return -1; }

    struct curl_slist *hdrs = make_signed_headers(
        ch, "PUT", bucket, key, "", creds, payload_sha256, lock_mode, lock_until);
    hdrs = curl_slist_append(hdrs, "Content-Type: application/octet-stream");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,      hdrs);
    curl_easy_setopt(ch, CURLOPT_UPLOAD,          1L);
    curl_easy_setopt(ch, CURLOPT_READDATA,        in);
    curl_easy_setopt(ch, CURLOPT_INFILESIZE_LARGE,file_size);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,  1L);

    /* capture response body — needed to detect Object Lock config errors */
    MemBuf resp = {0};
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &resp);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    fclose(in);

    if (rc != CURLE_OK) {
        fprintf(stderr, "s3: upload failed: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        /* Check for Object Lock configuration errors (AWS returns 400
         * InvalidRequest when the bucket was not created with Object Lock). */
        if (lock_days > 0 && resp.data &&
            (strstr(resp.data, "ObjectLock") != NULL ||
             strstr(resp.data, "Object Lock") != NULL ||
             strstr(resp.data, "InvalidRequest") != NULL)) {
            fprintf(stderr,
                    "s3: error: S3 bucket does not have Object Lock enabled.\n"
                    "  Object Lock must be enabled when the bucket is created\n"
                    "  (it cannot be added to an existing bucket).\n"
                    "  Create a new bucket with 'Enable Object Lock' checked.\n");
        } else {
            fprintf(stderr, "s3: upload HTTP %ld for s3://%s/%s\n",
                    http_code, bucket, key);
        }
        free(resp.data);
        return -1;
    }
    free(resp.data);
    return 0;
}

int s3_exists(const S3Creds *creds, const char *bucket, const char *key)
{
    ensure_curl_init();

    CURL *ch = curl_easy_init();
    if (!ch) return -1;

    struct curl_slist *hdrs = make_signed_headers(
        ch, "HEAD", bucket, key, "", creds, EMPTY_PAYLOAD_SHA256, "", "");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(ch, CURLOPT_NOBODY,        1L);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,1L);

    MemBuf resp = {0};
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &resp);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    free(resp.data);

    if (rc != CURLE_OK) return -1;
    if (http_code == 200) return 1;
    if (http_code == 404) return 0;
    return -1;
}

int s3_check_lock(const S3Creds *creds, const char *bucket, const char *key,
                  char *mode_out,  size_t mode_size,
                  char *until_out, size_t until_size)
{
    ensure_curl_init();

    mode_out[0]  = '\0';
    until_out[0] = '\0';

    CURL *ch = curl_easy_init();
    if (!ch) return -1;

    struct curl_slist *hdrs = make_signed_headers(
        ch, "HEAD", bucket, key, "", creds, EMPTY_PAYLOAD_SHA256, "", "");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(ch, CURLOPT_NOBODY,        1L);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,1L);

    /* collect response headers (lock info is in response headers, not body) */
    MemBuf resp_hdrs = {0};
    curl_easy_setopt(ch, CURLOPT_HEADERFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_HEADERDATA,     &resp_hdrs);

    /* discard response body */
    MemBuf resp_body = {0};
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &resp_body);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    free(resp_body.data);

    if (rc != CURLE_OK) {
        free(resp_hdrs.data);
        fprintf(stderr, "s3: verify-lock failed: %s\n",
                curl_easy_strerror(rc));
        return -1;
    }
    if (http_code == 404) {
        free(resp_hdrs.data);
        fprintf(stderr, "s3: object not found: s3://%s/%s\n", bucket, key);
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        free(resp_hdrs.data);
        fprintf(stderr, "s3: verify-lock HTTP %ld for s3://%s/%s\n",
                http_code, bucket, key);
        return -1;
    }

    /* parse Object Lock response headers (present only when object is locked) */
    if (resp_hdrs.data) {
        resp_header_val(resp_hdrs.data,
                        "x-amz-object-lock-mode",
                        mode_out, mode_size);
        resp_header_val(resp_hdrs.data,
                        "x-amz-object-lock-retain-until-date",
                        until_out, until_size);
        free(resp_hdrs.data);
    }
    return 0;
}

/* -------------------------------------------------------------------------
 * URL encoding for query-string values.
 * Like url_encode_key but encodes '/' as %2F (unreserved chars only).
 * Required for SigV4 canonical query string values.
 * ------------------------------------------------------------------------- */

static void url_encode_qs_value(const char *in, char *out, size_t out_size)
{
    size_t j = 0;
    for (size_t i = 0; in[i] && j + 4 < out_size; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%';
            out[j++] = HEX_UC[c >> 4];
            out[j++] = HEX_UC[c & 0x0f];
        }
    }
    out[j] = '\0';
}

/* -------------------------------------------------------------------------
 * Minimal XML value extractor.
 *
 * Scans `xml` starting at `start` for the first occurrence of <tag>value</tag>.
 * Copies `value` into `out` (NUL-terminated, truncated to out_size-1).
 * Returns a pointer to the character immediately after </tag>, or NULL if not found.
 * ------------------------------------------------------------------------- */

static const char *xml_find_value(const char *start,
                                   const char *tag,
                                   char *out, size_t out_size)
{
    char open_tag[128], close_tag[128];
    snprintf(open_tag,  sizeof(open_tag),  "<%s>",  tag);
    snprintf(close_tag, sizeof(close_tag), "</%s>", tag);

    const char *p = strstr(start, open_tag);
    if (!p) { if (out_size) out[0] = '\0'; return NULL; }
    p += strlen(open_tag);

    const char *end = strstr(p, close_tag);
    if (!end) { if (out_size) out[0] = '\0'; return NULL; }

    size_t len = (size_t)(end - p);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, p, len);
    out[len] = '\0';

    return end + strlen(close_tag);
}

/* -------------------------------------------------------------------------
 * s3_list — ListObjectsV2 with optional prefix, returns up to max_out entries.
 *
 * Uses list-type=2 (V2 API), max-keys=1000, optional prefix.
 * Handles pagination automatically via NextContinuationToken.
 *
 * Returns number of objects found (0..max_out) or -1 on error.
 * ------------------------------------------------------------------------- */

int s3_list(const S3Creds *creds, const char *bucket, const char *prefix,
            S3Object *out, int max_out)
{
    ensure_curl_init();

    int total = 0;
    char continuation_token[2048] = "";

    for (;;) {  /* pagination loop */
        /* Build canonical query string (params must be alphabetically sorted):
         * continuation-token < list-type < max-keys < prefix
         * Per SigV4 spec, parameter names and values must be percent-encoded. */
        char enc_prefix[4096];
        url_encode_qs_value(prefix, enc_prefix, sizeof(enc_prefix));

        /* canonical_qs must hold two percent-encoded values (each up to 3×
         * their original length) plus the fixed param names (~60 chars). */
        char canonical_qs[20480];
        if (continuation_token[0]) {
            char enc_tok[4096];
            url_encode_qs_value(continuation_token, enc_tok, sizeof(enc_tok));
            snprintf(canonical_qs, sizeof(canonical_qs),
                     "continuation-token=%s&list-type=2&max-keys=1000&prefix=%s",
                     enc_tok, enc_prefix);
        } else {
            snprintf(canonical_qs, sizeof(canonical_qs),
                     "list-type=2&max-keys=1000&prefix=%s",
                     enc_prefix);
        }

        CURL *ch = curl_easy_init();
        if (!ch) return -1;

        /* key = "" → canonical URI = "/" (bucket-level list) */
        struct curl_slist *hdrs = make_signed_headers(
            ch, "GET", bucket, "", canonical_qs, creds,
            EMPTY_PAYLOAD_SHA256, "", "");

        MemBuf body = {0};
        curl_easy_setopt(ch, CURLOPT_HTTPHEADER,    hdrs);
        curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
        curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &body);
        curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,1L);

        CURLcode rc = curl_easy_perform(ch);
        long http_code = 0;
        curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
        curl_slist_free_all(hdrs);
        curl_easy_cleanup(ch);

        if (rc != CURLE_OK) {
            fprintf(stderr, "s3: list failed: %s\n", curl_easy_strerror(rc));
            free(body.data);
            return -1;
        }
        if (http_code < 200 || http_code >= 300) {
            fprintf(stderr, "s3: list HTTP %ld for s3://%s/ prefix='%s'\n",
                    http_code, bucket, prefix);
            free(body.data);
            return -1;
        }

        /* Parse XML response — extract <Contents> blocks */
        if (body.data) {
            const char *p = body.data;
            while (total < max_out) {
                /* Find next <Contents> block */
                const char *block_start = strstr(p, "<Contents>");
                if (!block_start) break;
                block_start += strlen("<Contents>");
                const char *block_end = strstr(block_start, "</Contents>");
                if (!block_end) break;

                /* Extract Key and LastModified from this block */
                size_t blen = (size_t)(block_end - block_start);
                char block[4096];
                if (blen >= sizeof(block)) blen = sizeof(block) - 1;
                memcpy(block, block_start, blen);
                block[blen] = '\0';

                xml_find_value(block, "Key",
                               out[total].key, sizeof(out[total].key));
                xml_find_value(block, "LastModified",
                               out[total].last_modified,
                               sizeof(out[total].last_modified));

                if (out[total].key[0])   /* only count entries with a key */
                    total++;

                p = block_end + strlen("</Contents>");
            }

            /* Check for pagination */
            char is_truncated[16] = "false";
            char next_token[2048] = "";
            xml_find_value(body.data, "IsTruncated",
                           is_truncated, sizeof(is_truncated));
            xml_find_value(body.data, "NextContinuationToken",
                           next_token, sizeof(next_token));

            free(body.data);

            if (strcmp(is_truncated, "true") == 0 && next_token[0] &&
                total < max_out) {
                strncpy(continuation_token, next_token,
                        sizeof(continuation_token) - 1);
                continue;  /* fetch next page */
            }
        } else {
            free(body.data);
        }

        break;  /* done */
    }

    return total;
}

/* -------------------------------------------------------------------------
 * s3_set_retention — PutObjectRetention (sets / extends Object Lock).
 *
 * Sends PUT /{key}?retention with an XML body specifying mode and date.
 * mode should be "COMPLIANCE" or "GOVERNANCE".
 * until_date should be ISO 8601 UTC, e.g. "2032-01-15T00:00:00Z".
 *
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */

int s3_set_retention(const S3Creds *creds, const char *bucket, const char *key,
                     const char *mode, const char *until_date)
{
    ensure_curl_init();

    /* Build XML body */
    char body[512];
    int body_len = snprintf(body, sizeof(body),
        "<Retention><Mode>%s</Mode>"
        "<RetainUntilDate>%s</RetainUntilDate></Retention>",
        mode, until_date);
    if (body_len < 0 || (size_t)body_len >= sizeof(body)) {
        fprintf(stderr, "s3: set-retention: XML body too long\n");
        return -1;
    }

    /* Compute payload SHA-256 */
    char payload_sha256[65];
    sha256_str_hex(body, (size_t)body_len, payload_sha256);

    /* Write body to a temp file so CURLOPT_UPLOAD can read it via fread */
    char tmp[64];
    strcpy(tmp, "/tmp/shrinker_ret_XXXXXX");
    int fd = mkstemp(tmp);
    if (fd < 0) { perror("s3: set-retention: mkstemp"); return -1; }
    FILE *fp = fdopen(fd, "wb+");
    if (!fp) { close(fd); unlink(tmp); return -1; }
    fwrite(body, 1, (size_t)body_len, fp);
    rewind(fp);

    CURL *ch = curl_easy_init();
    if (!ch) { fclose(fp); unlink(tmp); return -1; }

    /* canonical_qs = "retention=" (empty value per SigV4 spec) */
    struct curl_slist *hdrs = make_signed_headers(
        ch, "PUT", bucket, key, "retention=", creds, payload_sha256, "", "");
    hdrs = curl_slist_append(hdrs, "Content-Type: application/xml");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,       hdrs);
    curl_easy_setopt(ch, CURLOPT_UPLOAD,           1L);
    curl_easy_setopt(ch, CURLOPT_READDATA,         fp);
    curl_easy_setopt(ch, CURLOPT_INFILESIZE_LARGE, (curl_off_t)body_len);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,   1L);

    MemBuf resp = {0};
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &resp);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    fclose(fp);
    unlink(tmp);

    if (rc != CURLE_OK) {
        fprintf(stderr, "s3: set-retention failed: %s\n", curl_easy_strerror(rc));
        free(resp.data);
        return -1;
    }
    if (http_code < 200 || http_code >= 300) {
        fprintf(stderr, "s3: set-retention HTTP %ld for s3://%s/%s\n",
                http_code, bucket, key);
        if (resp.data) fprintf(stderr, "  %.256s\n", resp.data);
        free(resp.data);
        return -1;
    }
    free(resp.data);
    return 0;
}

/* -------------------------------------------------------------------------
 * s3_delete_object — DELETE s3://bucket/key.
 *
 * Returns 0 on success, -1 on error.
 * ------------------------------------------------------------------------- */

int s3_delete_object(const S3Creds *creds, const char *bucket, const char *key)
{
    ensure_curl_init();

    CURL *ch = curl_easy_init();
    if (!ch) return -1;

    struct curl_slist *hdrs = make_signed_headers(
        ch, "DELETE", bucket, key, "", creds, EMPTY_PAYLOAD_SHA256, "", "");

    curl_easy_setopt(ch, CURLOPT_HTTPHEADER,    hdrs);
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "DELETE");
    curl_easy_setopt(ch, CURLOPT_NOBODY,        0L);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION,1L);

    MemBuf resp = {0};
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, membuf_write);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA,     &resp);

    CURLcode rc = curl_easy_perform(ch);
    long http_code = 0;
    curl_easy_getinfo(ch, CURLINFO_RESPONSE_CODE, &http_code);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(ch);
    free(resp.data);

    if (rc != CURLE_OK) {
        fprintf(stderr, "s3: delete failed: %s\n", curl_easy_strerror(rc));
        return -1;
    }
    /* 204 No Content is the success response for DELETE */
    if (http_code != 204 && (http_code < 200 || http_code >= 300)) {
        fprintf(stderr, "s3: delete HTTP %ld for s3://%s/%s\n",
                http_code, bucket, key);
        return -1;
    }
    return 0;
}
