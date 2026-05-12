# NetProwl Homebrew Tap

## Install

```bash
brew install mbpz/tap/netprowl
```

## For Official Homebrew Cask

The official cask is maintained in [Homebrew/homebrew-cask](https://github.com/Homebrew/homebrew-cask).

Updates are automated via `.github/workflows/bump-homebrew.yml` which creates PRs to the official repository when a new release is published.

## Development

To build locally:

```bash
# Build the macOS app
cd netprowl-pc && npm install && npm run tauri build -- --target aarch64-apple-darwin

# Sign and package
./scripts/post-build-macos.sh src-tauri/target/aarch64-apple-darwin/release/bundle/macos/NetProwl.app

# Create tarball
tar -czvf NetProwl-{version}-macos-arm64.tar.gz -C src-tauri/target/aarch64-apple-darwin/release/bundle/macos NetProwl.app
```
