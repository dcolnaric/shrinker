/*
 * main.c — Shrinker C CLI (Phase 5 Steps 27–28 — S3 + Object Lock)
 *
 * Provides a complete command-line interface that mirrors src/cli.py exactly.
 * S3 paths (s3://bucket/key) are transparently handled: the binary downloads
 * to / uploads from a temp file and calls the existing local-file functions.
 *
 *   shrinker --help | --version
 *   shrinker compress   <input>      <output>          [--format …] [--region …]
 *                                                      [--lock DAYS]
 *   shrinker append     <input>      <archive.logz>    [--format …] [--region …]
 *                                                      [--lock DAYS]
 *   shrinker search     <file.logz>  [query]           [--from …] [--to …]
 *                                    [--user …] [--ip …] [--action …] [--level …]
 *                                    [--region …]
 *   shrinker decompress <file.logz>  --output <file>   [--region …]
 *   shrinker verify     <file.logz>                    [--region …]
 *   shrinker export     <file.logz>  [--from …] [--to …] [--format …] [--region …]
 *   shrinker verify-lock s3://bucket/key               [--region …]
 *
 * S3 URL format:  s3://bucket/path/to/object.logz
 *
 * Exit codes:
 *   compress / decompress / export / search / append   0 = ok,       1 = error
 *   verify                                             0 = verified, 1 = tampered,
 *                                                      2 = error
 *   verify-lock                                        0 = ok,       1 = error
 *   bad arguments / unknown command                    2
 */

#define _FILE_OFFSET_BITS 64   /* 64-bit file offsets on all platforms */
#define _POSIX_C_SOURCE 200809L /* mkstemp, strdup */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>            /* mkstemp, unlink, close */
#include "shrinker.h"
#include "s3.h"

/* -------------------------------------------------------------------------
 * Version string
 * ------------------------------------------------------------------------- */

#define VERSION_STRING "shrinker 0.2.1 (Phase 5 — S3 + Object Lock)"

/* -------------------------------------------------------------------------
 * Help strings
 * ------------------------------------------------------------------------- */

static void help_root(void)
{
    printf("usage: shrinker <command> [options]\n"
           "\n"
           "Compress audit log files 10x and search without decompression.\n"
           "Designed for compliance archival (SOC 2, PCI-DSS, HIPAA, SOX).\n"
           "\n"
           "commands:\n"
           "  compress     Compress a log file to .logz format\n"
           "  append       Append new entries to an existing archive\n"
           "  search       Search a .logz file for matching lines\n"
           "  decompress   Decompress a .logz file back to original bytes\n"
           "  verify       Verify the SHA-256 hash chain of a .logz file\n"
           "  export       Export log records to CSV or JSONL\n"
           "  verify-lock  Check S3 Object Lock status of a .logz object\n"
           "\n"
           "global options:\n"
           "  --help       Show this help message\n"
           "  --version    Print version and exit\n"
           "\n"
           "S3 support:\n"
           "  All <file> and <output> arguments accept s3://bucket/key paths.\n"
           "  Credentials: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars,\n"
           "  ~/.aws/credentials, or EC2/ECS IAM role (standard chain).\n"
           "  Region: AWS_DEFAULT_REGION / AWS_REGION, ~/.aws/config, or us-east-1.\n"
           "  Override region per command with --region <region>.\n"
           "\n"
           "Object Lock (WORM compliance):\n"
           "  Use --lock DAYS with compress or append to apply S3 Object Lock\n"
           "  in Compliance mode.  Requires a bucket created with Object Lock\n"
           "  enabled.  Examples: 2555 = 7 years (SOX), 365 = 1 year (SOC 2).\n"
           "\n"
           "Run 'shrinker <command> --help' for command-specific help.\n");
}

static void help_compress(void)
{
    printf("usage: shrinker compress <input> <output> [options]\n"
           "\n"
           "Compress a log file to .logz format with seekable 64 KB chunks,\n"
           "bloom filters for fast search, and a SHA-256 hash chain.\n"
           "<output> may be a local path or s3://bucket/key.\n"
           "\n"
           "arguments:\n"
           "  input           Input log file path\n"
           "  output          Output .logz file path (local or s3://bucket/key)\n"
           "\n"
           "options:\n"
           "  --format FORMAT  Override auto-detected log format.\n"
           "                   Choices: json, syslog, plaintext\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --lock DAYS      Set S3 Object Lock retention in Compliance Mode.\n"
           "                   Requires an S3 output path and a bucket with\n"
           "                   Object Lock enabled.  DAYS must be > 0.\n"
           "                   Examples: 2555 (SOX 7y), 365 (SOC 2 1y)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker compress server.log server.logz\n"
           "  shrinker compress server.log s3://my-bucket/logs/server.logz\n"
           "  shrinker compress server.log s3://my-bucket/logs/server.logz --lock 2555\n"
           "  shrinker compress server.log server.logz --format json\n");
}

static void help_search(void)
{
    printf("usage: shrinker search <file> [query] [options]\n"
           "\n"
           "Search a .logz file for lines matching query without full decompression.\n"
           "Uses bloom filters and the timestamp index to skip irrelevant chunks.\n"
           "query is optional — omit it for field-filter-only search.\n"
           "<file> may be a local path or s3://bucket/key.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path (local or s3://bucket/key)\n"
           "  query           Search query string (optional)\n"
           "\n"
           "options:\n"
           "  --from DATE      Start of time range (YYYY-MM-DD)\n"
           "  --to   DATE      End   of time range (YYYY-MM-DD)\n"
           "  --user VALUE     Filter by user/user_id/username field (JSON logs only)\n"
           "  --ip   VALUE     Filter by ip/ip_address field         (JSON logs only)\n"
           "  --action VALUE   Filter by action field                (JSON logs only)\n"
           "  --level  VALUE   Filter by level/severity field        (JSON logs only)\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker search server.logz \"payment failed\"\n"
           "  shrinker search s3://my-bucket/logs/server.logz \"500\" --from 2025-01-01\n"
           "  shrinker search server.logz --user admin --level ERROR\n");
}

static void help_decompress(void)
{
    printf("usage: shrinker decompress <file> --output <output>\n"
           "\n"
           "Decompress a .logz file back to the original bytes (bit-exact round-trip).\n"
           "<file> may be a local path or s3://bucket/key.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path (local or s3://bucket/key)\n"
           "\n"
           "options:\n"
           "  --output FILE    Write decompressed output to FILE (required)\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker decompress archive.logz --output restored.log\n"
           "  shrinker decompress s3://my-bucket/archive.logz --output restored.log\n");
}

static void help_verify(void)
{
    printf("usage: shrinker verify <file> [options]\n"
           "\n"
           "Verify the SHA-256 hash chain of a .logz file.\n"
           "Prints VERIFIED or TAMPERED to stdout.\n"
           "<file> may be a local path or s3://bucket/key.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path (local or s3://bucket/key)\n"
           "\n"
           "options:\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --help           Show this help message\n"
           "\n"
           "exit codes:\n"
           "  0  VERIFIED  — hash chain is intact\n"
           "  1  TAMPERED  — hash mismatch or decompression failure\n"
           "  2  ERROR     — usage error or I/O failure\n"
           "\n"
           "examples:\n"
           "  shrinker verify archive.logz\n"
           "  shrinker verify s3://my-bucket/archive.logz\n");
}

static void help_export(void)
{
    printf("usage: shrinker export <file> [options]\n"
           "\n"
           "Export log records to CSV or JSONL without full decompression.\n"
           "Applies the same chunk-level time-range skip as 'search'.\n"
           "Output is written to stdout; redirect to a file with >.\n"
           "<file> may be a local path or s3://bucket/key.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path (local or s3://bucket/key)\n"
           "\n"
           "options:\n"
           "  --from DATE      Start of time range (YYYY-MM-DD)\n"
           "  --to   DATE      End   of time range (YYYY-MM-DD)\n"
           "  --format FORMAT  Output format: csv (default) or json (JSONL)\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker export archive.logz > audit.csv\n"
           "  shrinker export s3://my-bucket/archive.logz --format json > audit.jsonl\n");
}

static void help_append(void)
{
    printf("usage: shrinker append <input> <archive.logz> [options]\n"
           "\n"
           "Append new log entries to an existing archive.\n"
           "Creates a new archive if the file does not exist.\n"
           "<archive.logz> may be a local path or s3://bucket/key.\n"
           "\n"
           "The hash chain is extended from the last chunk of the existing\n"
           "archive, so the result passes 'verify' with full chain continuity.\n"
           "New chunks use the existing archive's dictionary and format byte.\n"
           "\n"
           "arguments:\n"
           "  input           Input log file path\n"
           "  archive.logz    Target .logz archive (created if absent)\n"
           "\n"
           "options:\n"
           "  --format FORMAT  Override auto-detected format when creating a\n"
           "                   new archive.  Ignored for existing archives.\n"
           "                   Choices: json, syslog, plaintext\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --lock DAYS      Set S3 Object Lock retention in Compliance Mode.\n"
           "                   Requires an S3 archive path and a bucket with\n"
           "                   Object Lock enabled.  DAYS must be > 0.\n"
           "                   Examples: 2555 (SOX 7y), 365 (SOC 2 1y)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker append server.log archive.logz\n"
           "  shrinker append /var/log/app.log s3://my-bucket/archive.logz\n"
           "  shrinker append /var/log/app.log s3://my-bucket/archive.logz --lock 365\n");
}

static void help_verify_lock(void)
{
    printf("usage: shrinker verify-lock <s3://bucket/key> [options]\n"
           "\n"
           "Check the S3 Object Lock status of a .logz archive.\n"
           "Prints whether the object is locked in Compliance mode and\n"
           "the retain-until date.\n"
           "\n"
           "arguments:\n"
           "  s3://bucket/key  S3 URL of the .logz object to check\n"
           "\n"
           "options:\n"
           "  --region REGION  AWS region for S3 (overrides env/config)\n"
           "  --help           Show this help message\n"
           "\n"
           "exit codes:\n"
           "  0  OK     — lock status retrieved successfully\n"
           "  1  ERROR  — S3 request failed or object not found\n"
           "\n"
           "examples:\n"
           "  shrinker verify-lock s3://my-bucket/logs/server.logz\n"
           "  shrinker verify-lock s3://my-bucket/logs/server.logz --region eu-west-1\n");
}

/* -------------------------------------------------------------------------
 * Small helpers
 * ------------------------------------------------------------------------- */

static int is_help(const char *arg)
{
    return (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0);
}

static int has_help(int argc, char *argv[], int from)
{
    for (int i = from; i < argc; i++)
        if (is_help(argv[i])) return 1;
    return 0;
}

/* -------------------------------------------------------------------------
 * S3 routing helpers
 *
 * s3_to_tmp():  download an S3 URL to a fresh temp file.
 *               Fills tmpfile[] (must be char[64]) with the path.
 *               Returns 0 on success, -1 on failure.
 *               Caller must unlink(tmpfile) when done.
 *
 * tmp_to_s3():  upload a local file to an S3 URL.
 *               lock_days > 0 enables S3 Object Lock Compliance Mode.
 *               Returns 0 on success, -1 on failure.
 * ------------------------------------------------------------------------- */

static int s3_to_tmp(const char *s3_url, const char *region_override,
                     char tmpfile[64])
{
    tmpfile[0] = '\0';

    S3Url s3u;
    if (s3_parse_url(s3_url, &s3u) != 0) {
        fprintf(stderr, "s3: invalid URL: %s\n", s3_url);
        return -1;
    }
    S3Creds creds;
    if (s3_load_creds(&creds) != 0) return -1;
    if (region_override)
        strncpy(creds.region, region_override, sizeof(creds.region) - 1);

    strcpy(tmpfile, "/tmp/shrinker_XXXXXX");
    int fd = mkstemp(tmpfile);
    if (fd < 0) {
        perror("s3: mkstemp");
        tmpfile[0] = '\0';
        return -1;
    }
    close(fd);   /* s3_download opens it independently */

    fprintf(stderr, "Downloading s3://%s/%s ...\n", s3u.bucket, s3u.key);
    if (s3_download(&creds, s3u.bucket, s3u.key, tmpfile) != 0) {
        unlink(tmpfile);
        tmpfile[0] = '\0';
        return -1;
    }
    return 0;
}

static int tmp_to_s3(const char *local_path, const char *s3_url,
                     const char *region_override, int lock_days)
{
    S3Url s3u;
    if (s3_parse_url(s3_url, &s3u) != 0) {
        fprintf(stderr, "s3: invalid URL: %s\n", s3_url);
        return -1;
    }
    S3Creds creds;
    if (s3_load_creds(&creds) != 0) return -1;
    if (region_override)
        strncpy(creds.region, region_override, sizeof(creds.region) - 1);

    fprintf(stderr, "Uploading to s3://%s/%s ...\n", s3u.bucket, s3u.key);
    return s3_upload(&creds, s3u.bucket, s3u.key, local_path, lock_days);
}

/* -------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(int argc, char *argv[])
{
    /* ------------------------------------------------------------------
     * Global flags: --version, --help, no arguments
     * ------------------------------------------------------------------ */
    if (argc >= 2 && strcmp(argv[1], "--version") == 0) {
        printf("%s\n", VERSION_STRING);
        return 0;
    }

    if (argc < 2 || strcmp(argv[1], "--help") == 0 ||
        strcmp(argv[1], "-h") == 0) {
        help_root();
        return 0;
    }

    /* ------------------------------------------------------------------
     * compress
     *   shrinker compress <input> <output> [--format F] [--region R]
     *                                      [--lock DAYS]
     *
     *   If <output> is s3://…: compress to a temp file, upload, delete.
     *   --lock requires an S3 output path.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "compress") == 0) {
        if (has_help(argc, argv, 2)) { help_compress(); return 0; }

        if (argc < 4) {
            fprintf(stderr,
                    "compress: missing required arguments <input> <output>\n\n");
            help_compress();
            return 2;
        }

        const char *input           = argv[2];
        const char *output          = argv[3];
        int         format_override = -1;
        const char *region_override = NULL;
        int         lock_days       = 0;

        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--format") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "compress: --format requires an argument\n");
                    return 2;
                }
                const char *fmt = argv[++i];
                if      (strcmp(fmt, "json")      == 0) format_override = FORMAT_JSON;
                else if (strcmp(fmt, "syslog")    == 0) format_override = FORMAT_SYSLOG;
                else if (strcmp(fmt, "plaintext") == 0) format_override = FORMAT_PLAINTEXT;
                else {
                    fprintf(stderr,
                        "compress: invalid format '%s' — choose json, syslog, "
                        "or plaintext\n", fmt);
                    return 2;
                }
            } else if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "compress: --region requires an argument\n");
                    return 2;
                }
                region_override = argv[++i];
            } else if (strcmp(argv[i], "--lock") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "compress: --lock requires an argument\n");
                    return 2;
                }
                lock_days = atoi(argv[++i]);
                if (lock_days <= 0) {
                    fprintf(stderr,
                        "compress: --lock DAYS must be a positive integer "
                        "(e.g. 365 for SOC 2, 2555 for SOX 7y)\n");
                    return 2;
                }
            } else {
                fprintf(stderr, "compress: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        /* --lock is only meaningful with an S3 output */
        if (lock_days > 0 && !s3_is_url(output)) {
            fprintf(stderr,
                "compress: --lock requires an S3 output path (s3://...)\n");
            return 2;
        }

        if (s3_is_url(output)) {
            /* compress → temp, then upload (with optional Object Lock) */
            char tmpfile[64];
            strcpy(tmpfile, "/tmp/shrinker_XXXXXX");
            int fd = mkstemp(tmpfile);
            if (fd < 0) { perror("compress: mkstemp"); return 1; }
            close(fd);

            int rc = compress_file(input, tmpfile, format_override);
            if (rc == 0) {
                if (tmp_to_s3(tmpfile, output, region_override, lock_days) != 0)
                    rc = 1;
            }
            unlink(tmpfile);
            return (rc == 0) ? 0 : 1;
        }

        int rc = compress_file(input, output, format_override);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * search
     *   shrinker search <file> [query] [--from D] [--to D]
     *                          [--user V] [--ip V] [--action V] [--level V]
     *                          [--region R]
     *
     *   If <file> is s3://…: download to temp, search, delete.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "search") == 0) {
        if (has_help(argc, argv, 2)) { help_search(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "search: missing required argument <file>\n\n");
            help_search();
            return 2;
        }

        const char *file         = argv[2];
        const char *query        = "";
        int         opt_start    = 3;
        /* argv[3] is the query if it doesn't start with "--" */
        if (argc >= 4 && !(argv[3][0] == '-' && argv[3][1] == '-')) {
            query     = argv[3];
            opt_start = 4;
        }

        const char *from_date    = NULL;
        const char *to_date      = NULL;
        const char *field_user   = NULL;
        const char *field_ip     = NULL;
        const char *field_action = NULL;
        const char *field_level  = NULL;
        const char *region_override = NULL;

        for (int i = opt_start; i < argc; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --from requires an argument\n"); return 2; }
                from_date = argv[++i];
            } else if (strcmp(argv[i], "--to") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --to requires an argument\n"); return 2; }
                to_date = argv[++i];
            } else if (strcmp(argv[i], "--user") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --user requires an argument\n"); return 2; }
                field_user = argv[++i];
            } else if (strcmp(argv[i], "--ip") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --ip requires an argument\n"); return 2; }
                field_ip = argv[++i];
            } else if (strcmp(argv[i], "--action") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --action requires an argument\n"); return 2; }
                field_action = argv[++i];
            } else if (strcmp(argv[i], "--level") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --level requires an argument\n"); return 2; }
                field_level = argv[++i];
            } else if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "search: --region requires an argument\n"); return 2; }
                region_override = argv[++i];
            } else {
                fprintf(stderr, "search: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        char tmpfile[64] = "";
        const char *effective_file = file;

        if (s3_is_url(file)) {
            if (s3_to_tmp(file, region_override, tmpfile) != 0) return 1;
            effective_file = tmpfile;
        }

        int rc = search_file(effective_file, query, from_date, to_date,
                             field_user, field_ip, field_action, field_level);
        if (tmpfile[0]) unlink(tmpfile);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * decompress
     *   shrinker decompress <file> --output <output> [--region R]
     *
     *   If <file> is s3://…: download to temp, decompress, delete.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "decompress") == 0) {
        if (has_help(argc, argv, 2)) { help_decompress(); return 0; }

        if (argc < 3) {
            fprintf(stderr,
                    "decompress: missing required argument <file>\n\n");
            help_decompress();
            return 2;
        }

        const char *input           = argv[2];
        const char *output          = NULL;
        const char *region_override = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--output") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr,
                            "decompress: --output requires an argument\n");
                    return 2;
                }
                output = argv[++i];
            } else if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr,
                            "decompress: --region requires an argument\n");
                    return 2;
                }
                region_override = argv[++i];
            } else {
                fprintf(stderr, "decompress: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        if (!output) {
            fprintf(stderr, "decompress: --output <file> is required\n\n");
            help_decompress();
            return 2;
        }

        char tmpfile[64] = "";
        const char *effective_input = input;

        if (s3_is_url(input)) {
            if (s3_to_tmp(input, region_override, tmpfile) != 0) return 1;
            effective_input = tmpfile;
        }

        int rc = decompress_file(effective_input, output);
        if (tmpfile[0]) unlink(tmpfile);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * verify
     *   shrinker verify <file> [--region R]
     *
     *   If <file> is s3://…: download to temp, verify, delete.
     *   Returns 0=verified, 1=tampered, 2=error.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "verify") == 0) {
        if (has_help(argc, argv, 2)) { help_verify(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "verify: missing required argument <file>\n\n");
            help_verify();
            return 2;
        }

        const char *file            = argv[2];
        const char *region_override = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "verify: --region requires an argument\n");
                    return 2;
                }
                region_override = argv[++i];
            } else {
                fprintf(stderr, "verify: unexpected argument '%s'\n", argv[i]);
                return 2;
            }
        }

        char tmpfile[64] = "";
        const char *effective_file = file;

        if (s3_is_url(file)) {
            if (s3_to_tmp(file, region_override, tmpfile) != 0) return 2;
            effective_file = tmpfile;
        }

        int rc = verify_file(effective_file);   /* 0=verified, 1=tampered, 2=error */
        if (tmpfile[0]) unlink(tmpfile);
        return rc;
    }

    /* ------------------------------------------------------------------
     * export
     *   shrinker export <file> [--from D] [--to D] [--format F] [--region R]
     *
     *   If <file> is s3://…: download to temp, export (stdout), delete.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "export") == 0) {
        if (has_help(argc, argv, 2)) { help_export(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "export: missing required argument <file>\n\n");
            help_export();
            return 2;
        }

        const char *file            = argv[2];
        const char *from_date       = NULL;
        const char *to_date         = NULL;
        const char *format          = "csv";
        const char *region_override = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--from") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "export: --from requires an argument\n"); return 2; }
                from_date = argv[++i];
            } else if (strcmp(argv[i], "--to") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "export: --to requires an argument\n"); return 2; }
                to_date = argv[++i];
            } else if (strcmp(argv[i], "--format") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "export: --format requires an argument\n"); return 2; }
                format = argv[++i];
                if (strcmp(format, "csv") != 0 && strcmp(format, "json") != 0) {
                    fprintf(stderr,
                        "export: invalid format '%s' — choose csv or json\n",
                        format);
                    return 2;
                }
            } else if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) { fprintf(stderr, "export: --region requires an argument\n"); return 2; }
                region_override = argv[++i];
            } else {
                fprintf(stderr, "export: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        char tmpfile[64] = "";
        const char *effective_file = file;

        if (s3_is_url(file)) {
            if (s3_to_tmp(file, region_override, tmpfile) != 0) return 1;
            effective_file = tmpfile;
        }

        int rc = export_file(effective_file, from_date, to_date, format);
        if (tmpfile[0]) unlink(tmpfile);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * append
     *   shrinker append <input> <archive.logz> [--format F] [--region R]
     *                                          [--lock DAYS]
     *
     *   If <archive> is s3://…:
     *     • Check if the object exists.
     *     • If it exists: download to temp.
     *     • Run append_file(input, temp, format_override).
     *     • Upload temp back to S3 (with optional Object Lock).
     *     • Delete temp.
     *   --lock requires an S3 archive path.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "append") == 0) {
        if (has_help(argc, argv, 2)) { help_append(); return 0; }

        if (argc < 4) {
            fprintf(stderr,
                    "append: missing required arguments <input> "
                    "<archive.logz>\n\n");
            help_append();
            return 2;
        }

        const char *input           = argv[2];
        const char *archive         = argv[3];
        int         format_override = -1;
        const char *region_override = NULL;
        int         lock_days       = 0;

        for (int i = 4; i < argc; i++) {
            if (strcmp(argv[i], "--format") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "append: --format requires an argument\n");
                    return 2;
                }
                const char *fmt = argv[++i];
                if      (strcmp(fmt, "json")      == 0) format_override = FORMAT_JSON;
                else if (strcmp(fmt, "syslog")    == 0) format_override = FORMAT_SYSLOG;
                else if (strcmp(fmt, "plaintext") == 0) format_override = FORMAT_PLAINTEXT;
                else {
                    fprintf(stderr,
                        "append: invalid format '%s' — choose json, syslog, "
                        "or plaintext\n", fmt);
                    return 2;
                }
            } else if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "append: --region requires an argument\n");
                    return 2;
                }
                region_override = argv[++i];
            } else if (strcmp(argv[i], "--lock") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "append: --lock requires an argument\n");
                    return 2;
                }
                lock_days = atoi(argv[++i]);
                if (lock_days <= 0) {
                    fprintf(stderr,
                        "append: --lock DAYS must be a positive integer "
                        "(e.g. 365 for SOC 2, 2555 for SOX 7y)\n");
                    return 2;
                }
            } else {
                fprintf(stderr, "append: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        /* --lock is only meaningful with an S3 archive */
        if (lock_days > 0 && !s3_is_url(archive)) {
            fprintf(stderr,
                "append: --lock requires an S3 archive path (s3://...)\n");
            return 2;
        }

        if (s3_is_url(archive)) {
            /* Load credentials once (used for exists + download + upload) */
            S3Url s3u;
            if (s3_parse_url(archive, &s3u) != 0) {
                fprintf(stderr, "append: invalid S3 URL: %s\n", archive);
                return 1;
            }
            S3Creds creds;
            if (s3_load_creds(&creds) != 0) return 1;
            if (region_override)
                strncpy(creds.region, region_override,
                        sizeof(creds.region) - 1);

            /* create temp file name */
            char tmpfile[64];
            strcpy(tmpfile, "/tmp/shrinker_XXXXXX");
            int fd = mkstemp(tmpfile);
            if (fd < 0) { perror("append: mkstemp"); return 1; }
            close(fd);

            /* does the S3 object exist already? */
            int exists = s3_exists(&creds, s3u.bucket, s3u.key);
            if (exists == -1) { unlink(tmpfile); return 1; }

            if (exists == 1) {
                /* download existing archive into the temp file */
                fprintf(stderr, "Downloading s3://%s/%s ...\n",
                        s3u.bucket, s3u.key);
                if (s3_download(&creds, s3u.bucket, s3u.key, tmpfile) != 0) {
                    unlink(tmpfile);
                    return 1;
                }
            } else {
                /* no object yet — remove the empty mkstemp file so
                 * append_file() treats it as "create new archive" */
                unlink(tmpfile);
            }

            /* append locally (creates archive if tmpfile absent) */
            int rc = append_file(input, tmpfile, format_override);
            if (rc == 0) {
                /* upload the updated (or freshly created) archive,
                 * applying Object Lock if requested */
                fprintf(stderr, "Uploading to s3://%s/%s ...\n",
                        s3u.bucket, s3u.key);
                if (s3_upload(&creds, s3u.bucket, s3u.key, tmpfile,
                              lock_days) != 0)
                    rc = 1;
            }
            unlink(tmpfile);
            return (rc == 0) ? 0 : 1;
        }

        int rc = append_file(input, archive, format_override);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * verify-lock
     *   shrinker verify-lock <s3://bucket/key> [--region R]
     *
     *   Issues a HEAD request to S3 and inspects the Object Lock response
     *   headers.  Prints the lock status and retain-until date.
     *   Returns 0 on success, 1 on error.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "verify-lock") == 0) {
        if (has_help(argc, argv, 2)) { help_verify_lock(); return 0; }

        if (argc < 3) {
            fprintf(stderr,
                    "verify-lock: missing required argument "
                    "<s3://bucket/key>\n\n");
            help_verify_lock();
            return 2;
        }

        const char *url             = argv[2];
        const char *region_override = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--region") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr,
                            "verify-lock: --region requires an argument\n");
                    return 2;
                }
                region_override = argv[++i];
            } else {
                fprintf(stderr, "verify-lock: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        if (!s3_is_url(url)) {
            fprintf(stderr,
                "verify-lock: argument must be an S3 URL (s3://bucket/key)\n");
            return 2;
        }

        S3Url s3u;
        if (s3_parse_url(url, &s3u) != 0) {
            fprintf(stderr, "verify-lock: invalid S3 URL: %s\n", url);
            return 1;
        }

        S3Creds creds;
        if (s3_load_creds(&creds) != 0) return 1;
        if (region_override)
            strncpy(creds.region, region_override, sizeof(creds.region) - 1);

        char mode[32]  = "";
        char until[40] = "";

        if (s3_check_lock(&creds, s3u.bucket, s3u.key, mode, sizeof(mode),
                          until, sizeof(until)) != 0) {
            /* error already printed by s3_check_lock */
            return 1;
        }

        if (mode[0] != '\0') {
            /* Trim ISO 8601 timestamp to date part for readability:
             * "2032-05-27T00:00:00Z" → "2032-05-27" */
            char date[11] = "";
            if (strlen(until) >= 10) {
                strncpy(date, until, 10);
                date[10] = '\0';
            } else {
                strncpy(date, until, sizeof(date) - 1);
            }
            printf("LOCKED — %s mode, retain until %s\n", mode, date);
        } else {
            printf("NOT LOCKED — no Object Lock on this object\n");
        }

        return 0;
    }

    /* ------------------------------------------------------------------
     * Unknown subcommand
     * ------------------------------------------------------------------ */
    fprintf(stderr,
            "shrinker: unknown command '%s'\n\n"
            "valid commands: compress, append, search, decompress, verify, "
            "export, verify-lock\n"
            "Run 'shrinker --help' for usage.\n",
            argv[1]);
    return 2;
}
