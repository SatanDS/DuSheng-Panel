#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if ! printf '%s' "$VERSION" | grep -Eq '^v[0-9A-Za-z][0-9A-Za-z._-]*$'; then
  echo "Usage: $0 <version>, for example: $0 v0.1.5" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEPLOY_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DOWNLOAD_ROOT="${DUSHENG_DOWNLOADS_DIR:-$DEPLOY_DIR/downloads}"
SOURCE_ROOT="${DUSHENG_RELEASE_SOURCE_ROOT:-https://github.com/SatanDS/DuSheng-Panel/releases/download}"
RELEASE_BASE="${SOURCE_ROOT%/}/$VERSION"
DEST_DIR="${DOWNLOAD_ROOT%/}/$VERSION"
ASSETS=(
  dusheng-agent-linux-amd64.tar.gz
  dusheng-agent-linux-arm64.tar.gz
)

require_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Required command not found: $1" >&2
    exit 1
  fi
}

download_file() {
  local name="$1"
  local dest="$2"
  echo "Downloading $RELEASE_BASE/$name"
  curl --fail --show-error --location --http1.1 \
    --retry 5 --retry-all-errors --retry-delay 3 \
    --connect-timeout 15 --max-time 1800 \
    --continue-at - --output "$dest" "$RELEASE_BASE/$name"
}

verify_dir() {
  local dir="$1"
  local asset expected actual
  for asset in "${ASSETS[@]}"; do
    expected="$(awk -v name="$asset" '$2 == name { print $1; exit }' "$dir/checksums.txt")"
    if ! printf '%s' "$expected" | grep -Eq '^[0-9a-fA-F]{64}$'; then
      echo "No valid SHA256 checksum found for $asset" >&2
      return 1
    fi
    actual="$(sha256sum "$dir/$asset" | awk '{ print $1 }')"
    if [ "${actual,,}" != "${expected,,}" ]; then
      echo "SHA256 verification failed for $asset" >&2
      return 1
    fi
    echo "Verified $asset"
  done
}

require_command curl
require_command sha256sum
require_command awk
mkdir -p "$DOWNLOAD_ROOT"

if [ -d "$DEST_DIR" ]; then
  echo "$DEST_DIR already exists; verifying existing assets."
  verify_dir "$DEST_DIR"
  echo "Agent release $VERSION is already ready."
  exit 0
fi

tmp="$(mktemp -d "${DOWNLOAD_ROOT%/}/.sync-${VERSION}.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

download_file checksums.txt "$tmp/checksums.txt"
for asset in "${ASSETS[@]}"; do
  download_file "$asset" "$tmp/$asset"
done
verify_dir "$tmp"
chmod 0755 "$tmp"
chmod 0644 "$tmp"/*
mv "$tmp" "$DEST_DIR"
trap - EXIT

echo "Agent release $VERSION is available in $DEST_DIR"
echo "Set DUSHENG_AGENT_RELEASE_BASE to:"
echo "  https://your-panel.example/downloads/$VERSION"
