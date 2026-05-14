# NetProwl PC

Network reconnaissance tool — PC client built with Tauri + React.

## macOS Installation

### Homebrew (recommended)

```bash
brew install --cask mbpz/tap/netprowl
```

> Installs `NetProwl.app` to `/Applications`. No Gatekeeper popup, no manual signing.

### Manual Install

Download from [GitHub Releases](https://github.com/mbpz/NetProwl/releases):

```bash
# ARM (Apple Silicon)
tar -xzf NetProwl-arm64.tar.gz
sudo mv NetProwl.app /Applications/

# Intel
tar -xzf NetProwl-x64.tar.gz
sudo mv NetProwl.app /Applications/
```

## Build from Source

```bash
cd netprowl-pc
npm install
npm run tauri dev        # dev mode
npm run tauri build      # production build
```

### macOS Build Requirements

- Rust (stable)
- Node.js 20+
- macOS 11+ (Big Sur or later)

### Signing & Notarization

The CI pipeline automatically:
1. Ad-hoc signs the `.app` bundle
2. Clears `com.apple.quarantine` xattr

This allows the app to run on Apple Silicon Macs without Gatekeeper blocking it.

For local signing:

```bash
./scripts/post-build-macos.sh path/to/NetProwl.app
```

## Development

```bash
# Install external tools
./install.sh

# Run dev server
npm run tauri dev
```
test1778634639
test1778635925
// trigger fresh CI
test
# ci trigger
ci test
