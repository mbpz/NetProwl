#!/bin/bash
# post-build-macos.sh
# Ad-hoc sign and clear quarantine for macOS .app bundle
# Usage: ./scripts/post-build-macos.sh <path-to.app>

set -e

if [ -z "$1" ]; then
  echo "Usage: $0 <path-to.app>"
  exit 1
fi

APP_PATH="$1"

if [ ! -d "$APP_PATH" ]; then
  echo "Error: $APP_PATH is not a valid .app bundle"
  exit 1
fi

echo "[*] Signing: $APP_PATH"
codesign --force --deep --sign - "$APP_PATH"

echo "[*] Clearing quarantine xattr..."
xattr -rd com.apple.quarantine "$APP_PATH"

echo "[+] Done: $APP_PATH"
echo ""
echo "To create tarball for Homebrew:"
echo "  tar -czvf NetProwl-{version}-macos-arm64.tar.gz -C \$(dirname \"$APP_PATH\") \$(basename \"$APP_PATH\")"
