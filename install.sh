#!/bin/sh
# install.sh — download and install the latest Shrinker release.
#
# One-liner usage:
#   curl  -fsSL https://raw.githubusercontent.com/dcolnaric/shrinker/main/install.sh | sh
#   wget  -qO-  https://raw.githubusercontent.com/dcolnaric/shrinker/main/install.sh | sh
#
# Supported platforms: Linux x86_64, Linux aarch64/arm64
# Dependencies: curl or wget, sha256sum (coreutils / busybox), awk, sed, grep

set -e

REPO="dcolnaric/shrinker"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"

# ── helpers ───────────────────────────────────────────────────────────────────

say() { printf '%s\n' "$*"; }

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# ── detect download tool (curl preferred, wget fallback) ──────────────────────

if command -v curl >/dev/null 2>&1; then
  # -f: fail on HTTP errors, -s: silent, -S: show errors, -L: follow redirects
  download() { curl -fsSL -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
  download() { wget -q -O "$2" "$1"; }
else
  die "Neither curl nor wget found. Install one and retry."
fi

# ── detect OS ─────────────────────────────────────────────────────────────────

OS=$(uname -s)
case "$OS" in
  Linux) ;;
  *) die "Unsupported OS: $OS  (only Linux is supported for now)" ;;
esac

# ── detect architecture ───────────────────────────────────────────────────────

ARCH=$(uname -m)
case "$ARCH" in
  x86_64)        ARCH_LABEL="x86_64" ;;
  aarch64|arm64) ARCH_LABEL="arm64"  ;;
  *) die "Unsupported architecture: $ARCH  (supported: x86_64, aarch64/arm64)" ;;
esac

BINARY_NAME="shrinker-linux-${ARCH_LABEL}"
CHECKSUMS_NAME="shrinker-checksums.txt"

# ── temp workspace — cleaned up unconditionally on exit ───────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT INT TERM

# ── fetch release metadata ────────────────────────────────────────────────────

say "Fetching latest release info..."
download "$API_URL" "$WORK/release.json" \
  || die "Failed to fetch release metadata from $API_URL"

# Parse tag_name from JSON without jq.
# GitHub formats this as:  "tag_name": "v0.1.0"  — one key per line.
VERSION=$(grep '"tag_name"' "$WORK/release.json" | head -1 \
  | sed 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
[ -n "$VERSION" ] || die "Could not parse version from release metadata"
say "  Latest release: $VERSION"

# Extract browser_download_url for each asset.
# GitHub puts each URL on its own line:
#   "browser_download_url": "https://.../shrinker-linux-x86_64"
# We match the line that ends with /<asset-name>" to avoid partial matches.
BINARY_URL=$(grep '"browser_download_url"' "$WORK/release.json" \
  | grep "/${BINARY_NAME}\"" | head -1 \
  | sed 's/.*"\(https[^"]*\)".*/\1/')
CHECKSUMS_URL=$(grep '"browser_download_url"' "$WORK/release.json" \
  | grep "/${CHECKSUMS_NAME}\"" | head -1 \
  | sed 's/.*"\(https[^"]*\)".*/\1/')

[ -n "$BINARY_URL"    ] || die "Download URL not found for $BINARY_NAME in release $VERSION"
[ -n "$CHECKSUMS_URL" ] || die "Download URL not found for $CHECKSUMS_NAME in release $VERSION"

# ── download binary and checksum file ────────────────────────────────────────

say "Downloading $BINARY_NAME..."
download "$BINARY_URL" "$WORK/$BINARY_NAME" \
  || die "Failed to download $BINARY_NAME"

say "Downloading $CHECKSUMS_NAME..."
download "$CHECKSUMS_URL" "$WORK/$CHECKSUMS_NAME" \
  || die "Failed to download $CHECKSUMS_NAME"

# ── verify SHA-256 checksum ───────────────────────────────────────────────────

say "Verifying SHA-256 checksum..."

EXPECTED=$(grep "$BINARY_NAME" "$WORK/$CHECKSUMS_NAME" | awk '{print $1}')
[ -n "$EXPECTED" ] || die "No checksum entry found for $BINARY_NAME in $CHECKSUMS_NAME"

ACTUAL=$(sha256sum "$WORK/$BINARY_NAME" | awk '{print $1}')

if [ "$EXPECTED" != "$ACTUAL" ]; then
  die "Checksum mismatch for $BINARY_NAME
  expected: $EXPECTED
  actual:   $ACTUAL"
fi
say "  Checksum OK"

# ── choose install directory ──────────────────────────────────────────────────

INSTALL_DIR="/usr/local/bin"
if [ ! -w "$INSTALL_DIR" ]; then
  INSTALL_DIR="$HOME/.local/bin"
  mkdir -p "$INSTALL_DIR"
fi
INSTALL_PATH="$INSTALL_DIR/shrinker"

# ── install ───────────────────────────────────────────────────────────────────

cp "$WORK/$BINARY_NAME" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

say ""
say "Shrinker $VERSION installed to $INSTALL_PATH"

# Warn if the install directory is not currently in PATH.
case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    say ""
    say "  Note: $INSTALL_DIR is not in your PATH."
    say "  Add it with:  export PATH=\"\$PATH:$INSTALL_DIR\""
    ;;
esac

# ── confirm installation ──────────────────────────────────────────────────────

say ""
"$INSTALL_PATH" --version
