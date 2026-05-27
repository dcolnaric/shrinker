/*
 * s3.h — S3 direct read/write (Phase 5 Steps 27–28)
 *
 * Public API for reading from and writing to Amazon S3 using libcurl
 * and AWS Signature Version 4.
 *
 * Step 27: basic GET / PUT / HEAD operations with credential chain.
 * Step 28: Object Lock Compliance Mode (--lock DAYS on compress/append)
 *          and verify-lock subcommand.
 *
 * Authentication follows the standard AWS credential chain:
 *   1. Environment: AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
 *   2. ~/.aws/credentials [default] profile
 *   3. EC2/ECS instance metadata (IAM role, IMDSv1)
 *
 * Region: AWS_DEFAULT_REGION → AWS_REGION → ~/.aws/config → "us-east-1"
 * Override with --region on any subcommand.
 */

#ifndef S3_H
#define S3_H

#include <stddef.h>   /* size_t */

/* -------------------------------------------------------------------------
 * Parsed s3://bucket/key URL
 * ------------------------------------------------------------------------- */
typedef struct {
    char bucket[256];   /* bucket name — no slashes                          */
    char key[1024];     /* object key  — no leading slash                    */
} S3Url;

/* -------------------------------------------------------------------------
 * AWS credentials loaded from the credential chain
 * ------------------------------------------------------------------------- */
typedef struct {
    char access_key[128];     /* AWS_ACCESS_KEY_ID                           */
    char secret_key[128];     /* AWS_SECRET_ACCESS_KEY                       */
    char session_token[2048]; /* AWS_SESSION_TOKEN (empty string if not used) */
    char region[64];          /* e.g. "us-east-1"                            */
} S3Creds;

/* -------------------------------------------------------------------------
 * URL detection and parsing
 * ------------------------------------------------------------------------- */

/* Returns 1 if path starts with "s3://", 0 otherwise. */
int s3_is_url(const char *path);

/* Parse "s3://bucket/key" → S3Url.
 * Returns 0 on success, -1 if the URL is missing the key component or
 * the bucket/key lengths exceed the struct fields. */
int s3_parse_url(const char *url, S3Url *out);

/* -------------------------------------------------------------------------
 * Credential loading
 * ------------------------------------------------------------------------- */

/* Load AWS credentials using the standard credential chain.
 * Region defaults to "us-east-1" if not found in any source.
 * Returns 0 on success, -1 if no credentials were found (prints error). */
int s3_load_creds(S3Creds *creds);

/* -------------------------------------------------------------------------
 * S3 operations
 * ------------------------------------------------------------------------- */

/* Download s3://bucket/key to local_path (overwrites).
 * Returns 0 on success, -1 on any failure (prints error to stderr). */
int s3_download(const S3Creds *creds, const char *bucket, const char *key,
                const char *local_path);

/* Upload local_path to s3://bucket/key.
 * Computes the SHA-256 of the file before uploading (required by SigV4).
 *
 * lock_days > 0: Apply S3 Object Lock in COMPLIANCE mode.
 *   Sets x-amz-object-lock-mode: COMPLIANCE
 *   Sets x-amz-object-lock-retain-until-date: <today + lock_days>
 *   These headers are included in the SigV4 signed-headers list.
 *   The bucket must have Object Lock enabled at creation time.
 *   If not, AWS returns 400 InvalidRequest; a clear error is printed.
 *
 * lock_days = 0: no lock (default, backward-compatible).
 *
 * Returns 0 on success, -1 on any failure (prints error to stderr). */
int s3_upload(const S3Creds *creds, const char *bucket, const char *key,
              const char *local_path, int lock_days);

/* Check whether s3://bucket/key exists (HEAD request).
 * Returns 1 = exists, 0 = not found (404), -1 = error. */
int s3_exists(const S3Creds *creds, const char *bucket, const char *key);

/* -------------------------------------------------------------------------
 * S3 object metadata (returned by s3_list)
 * ------------------------------------------------------------------------- */

/* Maximum objects returned by a single s3_list call (across all pages) */
#define S3_LIST_MAX 10000

typedef struct {
    char key[1024];           /* object key (no leading slash)                */
    char last_modified[40];   /* ISO 8601 UTC, e.g. "2025-01-15T10:30:00.000Z" */
} S3Object;

/* -------------------------------------------------------------------------
 * Extended S3 operations (retention policy)
 * ------------------------------------------------------------------------- */

/* List objects in bucket with given key prefix.
 * out       — caller-allocated array of at least max_out S3Object entries.
 * max_out   — maximum entries to fill (recommend S3_LIST_MAX).
 * Handles ListObjectsV2 pagination automatically.
 * Returns number of objects found (0..max_out) or -1 on error. */
int s3_list(const S3Creds *creds, const char *bucket, const char *prefix,
            S3Object *out, int max_out);

/* Set Object Lock retention on an existing object (PutObjectRetention).
 * mode       — "COMPLIANCE" or "GOVERNANCE".
 * until_date — ISO 8601 UTC retain-until date, e.g. "2032-01-15T00:00:00Z".
 * Returns 0 on success, -1 on error. */
int s3_set_retention(const S3Creds *creds, const char *bucket, const char *key,
                     const char *mode, const char *until_date);

/* Delete s3://bucket/key (DELETE request).
 * Returns 0 on success, -1 on error. */
int s3_delete_object(const S3Creds *creds, const char *bucket, const char *key);

/* Check the Object Lock status of s3://bucket/key (HEAD request).
 * On success:
 *   If the object is locked:  mode_out = "COMPLIANCE" (or "GOVERNANCE"),
 *                             until_out = ISO 8601 retain-until date.
 *   If the object is unlocked: mode_out[0] = '\0', until_out[0] = '\0'.
 *   Returns 0.
 * On error (object not found, I/O failure, etc.): returns -1.
 *
 * mode_out  — caller-supplied buffer (recommend ≥ 32 bytes)
 * until_out — caller-supplied buffer (recommend ≥ 40 bytes) */
int s3_check_lock(const S3Creds *creds, const char *bucket, const char *key,
                  char *mode_out,  size_t mode_size,
                  char *until_out, size_t until_size);

#endif /* S3_H */
