import argparse
import sys

import compress
import decompress
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
    s.add_argument('query', help='Search query string')
    s.add_argument('--from', dest='from_date', metavar='DATE',
                   help='Start of time range (ISO date, e.g. 2025-01-01)')
    s.add_argument('--to', dest='to_date', metavar='DATE',
                   help='End of time range (ISO date, e.g. 2025-01-31)')

    d = sub.add_parser('decompress', help='Decompress a .logz file back to original bytes')
    d.add_argument('file', help='Input .logz file path')
    d.add_argument('--output', metavar='filename', help='Write output to file instead of stdout')

    v = sub.add_parser('verify', help='Verify the SHA-256 hash chain of a .logz file')
    v.add_argument('input', help='Input .logz file path')

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


if __name__ == '__main__':
    main()
