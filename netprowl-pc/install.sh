#!/bin/bash
set -euo pipefail

# ── NetProwl External Tool Installer ──
# Detects missing dependencies and installs them with platform-appropriate methods.
# Tools: masscan, nmap, rustscan, nuclei, ffuf, feroxbuster

echo "[*] NetProwl Tool Installer v1.0"
echo ""

OS="$(uname -s)"
ARCH="$(uname -m)"
INSTALLED=0
SKIPPED=0
FAILED=0

info()  { echo "[*] $*"; }
ok()    { echo "[+] $*"; INSTALLED=$((INSTALLED + 1)); }
skip()  { echo "[~] $*"; SKIPPED=$((SKIPPED + 1)); }
fail()  { echo "[-] $*"; FAILED=$((FAILED + 1)); }

# ── Dependency checks ──
ensure_go() {
    if command -v go &>/dev/null; then
        GO_VER="$(go version | awk '{print $3" "$4}')"
        ok "Go found: $GO_VER"
    else
        case "$OS" in
            Darwin)
                info "Go not found. Installing via Homebrew..."
                brew install go 2>/dev/null && ok "Go installed" || fail "Go installation failed"
                ;;
            Linux)
                if command -v apt-get &>/dev/null; then
                    info "Installing Go via apt..."
                    sudo apt-get install -y golang-go 2>/dev/null && ok "Go installed" || fail "Go not available, install manually: https://go.dev/dl/"
                elif command -v dnf &>/dev/null; then
                    sudo dnf install -y golang 2>/dev/null && ok "Go installed" || fail "Go not available"
                else
                    fail "Go not found. Install from https://go.dev/dl/"
                fi
                ;;
        esac
    fi
}

ensure_rust() {
    if command -v cargo &>/dev/null; then
        RUST_VER="$(rustc --version 2>/dev/null || echo 'unknown')"
        ok "Rust found: $RUST_VER"
    else
        info "Rust/Cargo not found. Installing via rustup..."
        if curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y 2>/dev/null; then
            . "$HOME/.cargo/env" 2>/dev/null || true
            ok "Rust installed"
        else
            fail "Rust installation failed. Install manually: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
        fi
    fi
}

# ── Tool installer ──
install_tool() {
    local cmd="$1"
    local install_fn="$2"
    local description="$3"

    if command -v "$cmd" &>/dev/null; then
        local ver
        ver="$($cmd --version 2>/dev/null || $cmd -version 2>/dev/null || echo 'installed')"
        skip "$description: already installed ($ver)"
        return 0
    fi

    info "Installing $description..."
    if $install_fn; then
        if command -v "$cmd" &>/dev/null; then
            ok "$description installed"
        else
            ok "$description installed (may need to reload shell: source ~/.bashrc or source ~/.zshrc)"
        fi
    else
        fail "$description installation failed"
        return 1
    fi
}

# ── Platform-specific tool installation ──
install_tools() {
    case "$OS" in
        Darwin)
            # masscan + nmap via Homebrew
            if command -v brew &>/dev/null; then
                install_tool masscan \
                    "brew install masscan 2>/dev/null" \
                    "masscan" || true
                install_tool nmap \
                    "brew install nmap 2>/dev/null" \
                    "nmap" || true
            else
                fail "Homebrew not found. Install: /bin/bash -c \"\$(curl -fsSL https://brew.sh/install.sh)\""
                return 1
            fi

            # rustscan + feroxbuster via Cargo (requires ensure_rust)
            install_tool rustscan \
                "cargo install rustscan 2>/dev/null" \
                "rustscan" || true
            install_tool feroxbuster \
                "cargo install feroxbuster 2>/dev/null" \
                "feroxbuster" || true

            # nuclei + ffuf via Go (requires ensure_go)
            install_tool nuclei \
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null" \
                "nuclei" || true
            install_tool ffuf \
                "go install github.com/ffuf/ffuf/v2@latest 2>/dev/null" \
                "ffuf" || true
            ;;

        Linux)
            if command -v apt-get &>/dev/null; then
                info "Updating apt cache..."
                sudo apt-get update -qq 2>/dev/null || true

                install_tool masscan \
                    "sudo apt-get install -y masscan 2>/dev/null" \
                    "masscan" || true
                install_tool nmap \
                    "sudo apt-get install -y nmap 2>/dev/null" \
                    "nmap" || true
            elif command -v dnf &>/dev/null; then
                install_tool masscan \
                    "sudo dnf install -y masscan 2>/dev/null" \
                    "masscan" || true
                install_tool nmap \
                    "sudo dnf install -y nmap 2>/dev/null" \
                    "nmap" || true
            elif command -v pacman &>/dev/null; then
                install_tool masscan \
                    "sudo pacman -Sy --noconfirm masscan 2>/dev/null" \
                    "masscan" || true
                install_tool nmap \
                    "sudo pacman -Sy --noconfirm nmap 2>/dev/null" \
                    "nmap" || true
            else
                fail "Unsupported Linux package manager. Install masscan + nmap manually."
            fi

            # rustscan + feroxbuster via Cargo
            install_tool rustscan \
                "cargo install rustscan 2>/dev/null" \
                "rustscan" || true
            install_tool feroxbuster \
                "cargo install feroxbuster 2>/dev/null" \
                "feroxbuster" || true

            # nuclei + ffuf via Go
            install_tool nuclei \
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null" \
                "nuclei" || true
            install_tool ffuf \
                "go install github.com/ffuf/ffuf/v2@latest 2>/dev/null" \
                "ffuf" || true
            ;;

        *)
            fail "Unsupported OS: $OS"
            return 1
            ;;
    esac
}

# ── Wordlist setup ──
setup_wordlists() {
    info "Checking wordlist paths..."
    local paths=(
        "/usr/share/wordlists/dirb"
        "/usr/share/wordlists"
        "/usr/local/share/wordlists/dirb"
        "/opt/wordlists/dirb"
    )

    for p in "${paths[@]}"; do
        if [ -d "$p" ]; then
            ok "Wordlist directory found: $p"
            return 0
        fi
    done

    # Create default wordlist directory
    local default_dir="/usr/local/share/wordlists/dirb"
    info "Creating default wordlist directory: $default_dir"
    if sudo mkdir -p "$default_dir" 2>/dev/null; then
        # Download a basic wordlist
        local wordlist="$default_dir/common.txt"
        info "Downloading basic wordlist..."
        if curl -sSf -o "$wordlist" "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" 2>/dev/null; then
            ok "Basic wordlist downloaded to $wordlist"
        else
            # Fallback: create a minimal wordlist
            printf '/\n/admin\n/login\n/api\n/backup\n/config\n/.env\n/wp-admin\n/phpmyadmin\n/robots.txt\n' | sudo tee "$wordlist" >/dev/null 2>&1
            ok "Created minimal wordlist at $wordlist"
        fi
    else
        skip "Cannot create wordlist directory (need sudo)"
    fi
}

# ── Main ──
echo "OS: $OS ($ARCH)"
echo ""

# Install runtime dependencies if missing
ensure_rust
ensure_go

echo ""
echo "--- Installing security tools ---"
install_tools

echo ""
echo "--- Setting up wordlists ---"
setup_wordlists

echo ""
echo "=== Summary ==="
echo "  Installed: $INSTALLED"
echo "  Already present: $SKIPPED"
echo "  Failed: $FAILED"
echo ""

if [ "$FAILED" -gt 0 ]; then
    echo "Some tools failed to install. You can install them manually:"
    echo "  masscan:  https://github.com/robertdavidgraham/masscan"
    echo "  nmap:     https://nmap.org/download"
    echo "  rustscan: cargo install rustscan"
    echo "  nuclei:   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    echo "  ffuf:     go install github.com/ffuf/ffuf/v2@latest"
    echo "  feroxbuster: cargo install feroxbuster"
    echo ""
fi

echo "[*] Done."
