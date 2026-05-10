import re

BLOOM_BYTES = 1024
BLOOM_BITS = BLOOM_BYTES * 8  # 8192

# Delimiters that bound meaningful tokens in JSON, syslog, and plaintext
_TOKEN_RE = re.compile(rb'[ ":\n\r\t,{}\[\]]+')


def _djb2(data: bytes) -> int:
    h = 5381
    for b in data:
        h = ((h << 5) + h + b) & 0xFFFFFFFF
    return h


def _fnv1a(data: bytes) -> int:
    h = 0x811c9dc5
    for b in data:
        h = ((h ^ b) * 0x01000193) & 0xFFFFFFFF
    return h


def _sdbm(data: bytes) -> int:
    h = 0
    for b in data:
        h = (b + (h << 6) + (h << 16) - h) & 0xFFFFFFFF
    return h


def build(raw: bytes) -> bytes:
    bf = bytearray(BLOOM_BYTES)
    for token in _TOKEN_RE.split(raw):
        if not token:
            continue
        for h in (_djb2(token), _fnv1a(token), _sdbm(token)):
            bit = h % BLOOM_BITS
            bf[bit >> 3] |= 1 << (bit & 7)
    return bytes(bf)


def _check_token(bf: bytes, token: bytes) -> bool:
    for h in (_djb2(token), _fnv1a(token), _sdbm(token)):
        bit = h % BLOOM_BITS
        if not (bf[bit >> 3] & (1 << (bit & 7))):
            return False
    return True


def query_present(bf: bytes, query_bytes: bytes) -> bool:
    tokens = [t for t in _TOKEN_RE.split(query_bytes) if t]
    if not tokens:
        tokens = [query_bytes]
    return all(_check_token(bf, t) for t in tokens)
