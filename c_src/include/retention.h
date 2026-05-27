/*
 * retention.h — Retention policy YAML DSL (Phase 5 Step 29)
 *
 * Defines the in-memory representation of a retention.yaml config file
 * and the public API for parsing and applying retention policies.
 *
 * Config file format (retention.yaml):
 *
 *   streams:
 *     - name: admin_actions
 *       pattern: s3://bucket/archive/admin-*.logz
 *       retention_days: 2555
 *       lock: true
 *
 *     - name: debug_logs
 *       pattern: s3://bucket/archive/debug-*.logz
 *       retention_days: 90
 *       lock: false
 *
 * Each stream:
 *   name           Human-readable label (used in output / error messages)
 *   pattern        s3://bucket/key-glob — '*' is the only supported wildcard
 *   retention_days How many days since last-modified before an object expires
 *   lock           true → apply S3 Object Lock Compliance Mode on matching objects
 *                  false → objects are not locked; expired objects are deleted
 */

#ifndef RETENTION_H
#define RETENTION_H

/* Maximum streams per config file */
#define RETENTION_MAX_STREAMS 64

typedef struct {
    char name[256];       /* stream label                               */
    char pattern[1024];   /* s3://bucket/glob — must start with s3://   */
    int  retention_days;  /* must be > 0                                */
    int  lock;            /* 1 = apply COMPLIANCE lock; 0 = no lock     */
} RetentionStream;

typedef struct {
    RetentionStream streams[RETENTION_MAX_STREAMS];
    int             num_streams;
} RetentionConfig;

/*
 * retention_parse_yaml — parse a retention.yaml file into cfg.
 *
 * Returns 0 on success.  On error, prints a message to stderr with the
 * offending line number (for YAML syntax errors) or field name (for
 * validation errors), and returns -1.
 *
 * Validates:
 *   - every stream has a non-empty name, pattern, and retention_days > 0
 *   - pattern starts with "s3://"
 */
int retention_parse_yaml(const char *path, RetentionConfig *cfg);

/*
 * retention_apply — apply the retention policy described in cfg.
 *
 * For each stream:
 *   1. Lists S3 objects whose key matches the stream's glob pattern.
 *   2. For each matching object:
 *      a. Checks current Object Lock status via HEAD (s3_check_lock).
 *      b. If lock=true and object not locked → s3_set_retention (COMPLIANCE).
 *      c. If retention_days elapsed since last-modified and no active lock
 *         → s3_delete_object.
 *      d. Otherwise prints current status.
 *
 * dry_run = 1 → print WOULD actions without making any S3 changes.
 * region_override may be NULL (uses credential-chain region).
 *
 * Output lines:
 *   "OK:           s3://bucket/key (locked COMPLIANCE, N days remaining)"
 *   "OK:           s3://bucket/key (unlocked, N days until expiry)"
 *   "WOULD LOCK:   s3://bucket/key (retain until YYYY-MM-DD)"
 *   "WOULD DELETE: s3://bucket/key"
 *   "LOCK:         s3://bucket/key (retain until YYYY-MM-DD)"
 *   "DELETE:       s3://bucket/key"
 *
 * Returns 0 if all objects were processed without error, 1 if any S3
 * operation failed (the run continues for remaining objects).
 */
int retention_apply(const RetentionConfig *cfg,
                    const char *region_override,
                    int dry_run);

#endif /* RETENTION_H */
