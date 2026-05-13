#!/bin/bash
set -euo pipefail
echo "[*] NetProwl Tool Installer"
OS="$(uname -s)"
if [ "$OS" != "Linux" ] && [ "$OS" != "Darwin" ]; then echo "[-] Unsupported OS: $OS"; exit 1; fi
install_tool() {
    local cmd=$1
    local install_cmd=$2
    if which "$cmd" > /dev/null 2>&1; then
        echo "[+] $cmd: $(which $cmd)"
    else
        echo "[*] Installing $cmd..."
        if eval "$install_cmd" 2>&1; then
            echo "[+] $cmd installed successfully"
        else
            echo "[-] Failed to install $cmd - is it in your PATH?"
        fi
    fi
}
if [ "$OS" = "Linux" ]; then
    sudo apt update
    install_tool masscan "sudo apt install masscan -y"
    install_tool nmap "sudo apt install nmap -y"
    install_tool nuclei "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    install_tool ffuf "go install github.com/ffuf/ffuf/v2@latest"
    install_tool feroxbuster "cargo install feroxbuster"
    install_tool rustscan "cargo install rustscan"
else
    brew install masscan nmap
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install github.com/ffuf/ffuf/v2@latest
    cargo install feroxbuster
    cargo install rustscan
fi
echo "[+] Done."