import argparse
import sys

import compress
import decompress
import export
import search
from verify import verify

EXAMPLES = """
examples:
  shrinker compress server.log server.logz
  shrinker compress server.log server.logz --format json
  shrinker search server.logz "payment failed"
  shrinker search server.logz "500"
  shrinker decompress archive.logz --output restored.log
  shrinker decompress archive.logz > restored.log
  shrinker verify archive.logz
  shrinker export archive.logz --from 2025-01-01 --to 2025-01-31 > audit.csv
  shrinker export archive.logz --format json > audit.jsonl
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog='shrinker',
        description='Compress log files to .logz format and search without full decompression.',
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command')

    c = sub.add_parser('compress', help='Compress a log file to .logz format')
    c.add_argument('input', help='Input log file path')
    c.add_argument('output', help='Output .logz file path')
    c.add_argument('--format', choices=['json', 'syslog', 'plaintext'], help='Override auto-detected log format')

    s = sub.add_parser('search', help='Search a .logz file for matching lines')
    s.add_argument('file', help='Input .logz file path')
    s.add_argument('query', nargs='?', default='',
                   help='Search query string (omit for field-filter-only search)')
    s.add_argument('--from', dest='from_date', metavar='DATE',
                   help='Start of time range (ISO date, e.g. 2025-01-01)')
    s.add_argument('--to', dest='to_date', metavar='DATE',
                   help='End of time range (ISO date, e.g. 2025-01-31)')
    s.add_argument('--user', metavar='VALUE',
                   help='Filter by user/user_id/username field value (JSON logs only)')
    s.add_argument('--ip', metavar='VALUE',
                   help='Filter by ip/ip_address field value (JSON logs only)')
    s.add_argument('--action', metavar='VALUE',
                   help='Filter by action field value (JSON logs only)')
    s.add_argument('--level', metavar='VALUE',
                   help='Filter by level/severity field value (JSON logs only)')

    d = sub.add_parser('decompress', help='Decompress a .logz file back to original bytes')
    d.add_argument('file', help='Input .logz file path')
    d.add_argument('--output', metavar='filename', help='Write output to file instead of stdout')

    v = sub.add_parser('verify', help='Verify the SHA-256 hash chain of a .logz file')
    v.add_argument('input', help='Input .logz file path')

    e = sub.add_parser('export', help='Export log records to CSV or JSONL without full decompression')
    e.add_argument('input', help='Input .logz file path')
    e.add_argument('--from', dest='from_date', metavar='DATE',
                   help='Start of time range (ISO date, e.g. 2025-01-01)')
    e.add_argument('--to', dest='to_date', metavar='DATE',
                   help='End of time range (ISO date, e.g. 2025-01-31)')
    e.add_argument('--format', dest='format', choices=['csv', 'json'], default='csv',
                   help='Output format: csv (default) or json (JSONL)')

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)
    if args.command == 'compress':
        compress.run(args)
    elif args.command == 'search':
        search.run(args)
    elif args.command == 'decompress':
        decompress.run(args)
    elif args.command == 'verify':
        rc = verify(args.input)
        sys.exit(rc)
    elif args.command == 'export':
        export.run(args)


if __name__ == '__main__':
    main()
