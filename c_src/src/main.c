/*
 * main.c — Shrinker C CLI (Phase 3 Step 17 — production-quality CLI)
 *
 * Provides a complete command-line interface that mirrors src/cli.py exactly:
 *
 *   shrinker --help | --version
 *   shrinker compress   <input> <output> [--format json|syslog|plaintext]
 *   shrinker search     <file>  <query>  [--from DATE] [--to DATE]
 *                                        [--user X] [--ip X] [--action X] [--level X]
 *   shrinker decompress <file>  --output <output>
 *   shrinker verify     <file>
 *   shrinker export     <file>  [--from DATE] [--to DATE] [--format csv|json]
 *
 * Exit codes:
 *   compress / decompress / export / search   0 = success,  1 = error
 *   verify                                    0 = verified, 1 = tampered, 2 = error
 *   bad arguments / unknown command           2
 */

#define _FILE_OFFSET_BITS 64   /* 64-bit file offsets on all platforms */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shrinker.h"

/* -------------------------------------------------------------------------
 * Version string
 * ------------------------------------------------------------------------- */

#define VERSION_STRING "shrinker 0.1.0 (Phase 3 Python-compatible C core)"

/* -------------------------------------------------------------------------
 * Help strings — one per subcommand plus a top-level summary.
 * Printed to stdout so users can pipe them through less/grep.
 * ------------------------------------------------------------------------- */

static void help_root(void)
{
    printf("usage: shrinker <command> [options]\n"
           "\n"
           "Compress audit log files 10x and search without decompression.\n"
           "Designed for compliance archival (SOC 2, PCI-DSS, HIPAA, SOX).\n"
           "\n"
           "commands:\n"
           "  compress    Compress a log file to .logz format\n"
           "  append      Append new entries to an existing archive\n"
           "  search      Search a .logz file for matching lines\n"
           "  decompress  Decompress a .logz file back to original bytes\n"
           "  verify      Verify the SHA-256 hash chain of a .logz file\n"
           "  export      Export log records to CSV or JSONL\n"
           "\n"
           "global options:\n"
           "  --help       Show this help message\n"
           "  --version    Print version and exit\n"
           "\n"
           "Run 'shrinker <command> --help' for command-specific help.\n");
}

static void help_compress(void)
{
    printf("usage: shrinker compress <input> <output> [options]\n"
           "\n"
           "Compress a log file to .logz format with seekable 64 KB chunks,\n"
           "bloom filters for fast search, and a SHA-256 hash chain.\n"
           "\n"
           "arguments:\n"
           "  input           Input log file path\n"
           "  output          Output .logz file path\n"
           "\n"
           "options:\n"
           "  --format FORMAT  Override auto-detected log format.\n"
           "                   Choices: json, syslog, plaintext\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker compress server.log server.logz\n"
           "  shrinker compress server.log server.logz --format json\n");
}

static void help_search(void)
{
    printf("usage: shrinker search <file> [query] [options]\n"
           "\n"
           "Search a .logz file for lines matching query without full decompression.\n"
           "Uses bloom filters and the timestamp index to skip irrelevant chunks.\n"
           "query is optional — omit it for field-filter-only search.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path\n"
           "  query           Search query string (optional)\n"
           "\n"
           "options:\n"
           "  --from DATE      Start of time range (YYYY-MM-DD)\n"
           "  --to   DATE      End   of time range (YYYY-MM-DD)\n"
           "  --user VALUE     Filter by user/user_id/username field (JSON logs only)\n"
           "  --ip   VALUE     Filter by ip/ip_address field         (JSON logs only)\n"
           "  --action VALUE   Filter by action field                (JSON logs only)\n"
           "  --level  VALUE   Filter by level/severity field        (JSON logs only)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker search server.logz \"payment failed\"\n"
           "  shrinker search server.logz \"500\" --from 2025-01-01 --to 2025-01-31\n"
           "  shrinker search server.logz \"delete\" --user admin --level ERROR\n"
           "  shrinker search server.logz --user admin --action delete\n");
}

static void help_decompress(void)
{
    printf("usage: shrinker decompress <file> --output <output>\n"
           "\n"
           "Decompress a .logz file back to the original bytes (bit-exact round-trip).\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path\n"
           "\n"
           "options:\n"
           "  --output FILE    Write decompressed output to FILE (required)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker decompress archive.logz --output restored.log\n");
}

static void help_verify(void)
{
    printf("usage: shrinker verify <file>\n"
           "\n"
           "Verify the SHA-256 hash chain of a .logz file.\n"
           "Prints VERIFIED or TAMPERED to stdout.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path\n"
           "\n"
           "options:\n"
           "  --help           Show this help message\n"
           "\n"
           "exit codes:\n"
           "  0  VERIFIED  — hash chain is intact\n"
           "  1  TAMPERED  — hash mismatch or decompression failure\n"
           "  2  ERROR     — usage error or I/O failure\n"
           "\n"
           "examples:\n"
           "  shrinker verify archive.logz\n");
}

static void help_export(void)
{
    printf("usage: shrinker export <file> [options]\n"
           "\n"
           "Export log records to CSV or JSONL without full decompression.\n"
           "Applies the same chunk-level time-range skip as 'search'.\n"
           "Output is written to stdout; redirect to a file with >.\n"
           "\n"
           "arguments:\n"
           "  file            Input .logz file path\n"
           "\n"
           "options:\n"
           "  --from DATE      Start of time range (YYYY-MM-DD)\n"
           "  --to   DATE      End   of time range (YYYY-MM-DD)\n"
           "  --format FORMAT  Output format: csv (default) or json (JSONL)\n"
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker export archive.logz > audit.csv\n"
           "  shrinker export archive.logz --from 2025-01-01 --to 2025-12-31 > audit.csv\n"
           "  shrinker export archive.logz --format json > audit.jsonl\n");
}

static void help_append(void)
{
    printf("usage: shrinker append <input> <archive.logz> [options]\n"
           "\n"
           "Append new log entries to an existing archive.\n"
           "Creates a new archive if the file does not exist.\n"
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
           "  --help           Show this help message\n"
           "\n"
           "examples:\n"
           "  shrinker append server.log archive.logz\n"
           "  shrinker append /var/log/app.log archive.logz\n");
}

/* -------------------------------------------------------------------------
 * Helpers
 * ------------------------------------------------------------------------- */

/* Return 1 if argv[i] is --help or -h. */
static int is_help(const char *arg)
{
    return (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0);
}

/* Scan argv[from..argc-1] for a --help/-h flag. */
static int has_help(int argc, char *argv[], int from)
{
    for (int i = from; i < argc; i++)
        if (is_help(argv[i])) return 1;
    return 0;
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

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        help_root();
        return 0;
    }

    /* ------------------------------------------------------------------
     * compress
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "compress") == 0) {
        if (has_help(argc, argv, 2)) { help_compress(); return 0; }

        if (argc < 4) {
            fprintf(stderr, "compress: missing required arguments <input> <output>\n\n");
            help_compress();
            return 2;
        }

        const char *input  = argv[2];
        const char *output = argv[3];
        int format_override = -1;   /* -1 = auto-detect */

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
                        "compress: invalid format '%s' — choose json, syslog, or plaintext\n",
                        fmt);
                    return 2;
                }
            } else {
                fprintf(stderr, "compress: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        int rc = compress_file(input, output, format_override);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * search
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "search") == 0) {
        if (has_help(argc, argv, 2)) { help_search(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "search: missing required argument <file>\n\n");
            help_search();
            return 2;
        }

        const char *file         = argv[2];
        /* query is optional: omit it to do a field-filter-only search.
         * Detect whether argv[3] is the query or the first option flag:
         * known flags all start with "--"; anything else is the query. */
        const char *query        = "";
        int opt_start = 3;
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
            } else {
                fprintf(stderr, "search: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        int rc = search_file(file, query, from_date, to_date,
                             field_user, field_ip, field_action, field_level);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * decompress
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "decompress") == 0) {
        if (has_help(argc, argv, 2)) { help_decompress(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "decompress: missing required argument <file>\n\n");
            help_decompress();
            return 2;
        }

        const char *input  = argv[2];
        const char *output = NULL;

        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "--output") == 0) {
                if (i + 1 >= argc) {
                    fprintf(stderr, "decompress: --output requires an argument\n");
                    return 2;
                }
                output = argv[++i];
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

        int rc = decompress_file(input, output);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * verify
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "verify") == 0) {
        if (has_help(argc, argv, 2)) { help_verify(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "verify: missing required argument <file>\n\n");
            help_verify();
            return 2;
        }

        /* Extra arguments after <file> are an error */
        if (argc > 3) {
            fprintf(stderr, "verify: unexpected argument '%s'\n", argv[3]);
            return 2;
        }

        return verify_file(argv[2]);  /* 0=verified, 1=tampered, 2=error */
    }

    /* ------------------------------------------------------------------
     * export
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "export") == 0) {
        if (has_help(argc, argv, 2)) { help_export(); return 0; }

        if (argc < 3) {
            fprintf(stderr, "export: missing required argument <file>\n\n");
            help_export();
            return 2;
        }

        const char *file      = argv[2];
        const char *from_date = NULL;
        const char *to_date   = NULL;
        const char *format    = "csv";   /* default */

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
            } else {
                fprintf(stderr, "export: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        int rc = export_file(file, from_date, to_date, format);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * append
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "append") == 0) {
        if (has_help(argc, argv, 2)) { help_append(); return 0; }

        if (argc < 4) {
            fprintf(stderr,
                    "append: missing required arguments <input> <archive.logz>\n\n");
            help_append();
            return 2;
        }

        const char *input   = argv[2];
        const char *archive = argv[3];
        int format_override = -1;   /* -1 = auto-detect (create-new only) */

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
                        "append: invalid format '%s' — choose json, syslog, or plaintext\n",
                        fmt);
                    return 2;
                }
            } else {
                fprintf(stderr, "append: unknown option '%s'\n", argv[i]);
                return 2;
            }
        }

        int rc = append_file(input, archive, format_override);
        return (rc == 0) ? 0 : 1;
    }

    /* ------------------------------------------------------------------
     * Unknown subcommand
     * ------------------------------------------------------------------ */
    fprintf(stderr, "shrinker: unknown command '%s'\n\n"
                    "valid commands: compress, append, search, decompress, verify, export\n"
                    "Run 'shrinker --help' for usage.\n",
            argv[1]);
    return 2;
}
