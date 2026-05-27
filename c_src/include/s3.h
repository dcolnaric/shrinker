/*
 * s3.h — S3 direct read/write (Phase 5 Step 27)
 *
 * Public API for reading from and writing to Amazon S3 using libcurl
 * and AWS Signature Version 4.  All S3 operations go through:
 *
 *   1. s3_load_creds() — standard AWS credential chain
 *   2. s3_download()   — GET object to local temp file
 *   3. s3_upload()     — PUT local file to object
 *   4. s3_exists()     — HEAD to check existence before append
 *
 * main.c detects "s3://" prefixes, calls these helpers, and routes to
 * the existing local-file functions (compress_file, search_file, …).
 * The core logic is unchanged — S3 is a pure transport layer.
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
 * Returns 0 on success, -1 on any failure (prints error to stderr). */
int s3_upload(const S3Creds *creds, const char *bucket, const char *key,
              const char *local_path);

/* Check whether s3://bucket/key exists (HEAD request).
 * Returns 1 = exists, 0 = not found (404), -1 = error. */
int s3_exists(const S3Creds *creds, const char *bucket, const char *key);

#endif /* S3_H */
