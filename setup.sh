#!/usr/bin/env bash
# ShadowIoT setup script
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv_dir="${repo_dir}/.venv"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 is not installed. Please install Python 3 and retry."
  exit 1
fi

if [[ ! -d "$venv_dir" ]]; then
  echo "[*] Creating virtual environment at ${venv_dir}..."
  if ! python3 -m venv "$venv_dir"; then
    echo "[!] Failed to create virtual environment. Install python3-venv and retry."
    exit 1
  fi
fi

py="${venv_dir}/bin/python"

echo "[*] Installing Python dependencies (zeroconf, scapy) into the virtual environment..."
"$py" -m pip install --upgrade pip
"$py" -m pip install zeroconf scapy

echo "[*] Setting execute permissions..."
chmod +x "${repo_dir}/shadowiot.sh" "${repo_dir}/scanner.py" "${repo_dir}/setup.sh"

echo "[+] Setup complete. Run ./shadowiot.sh to launch ShadowIoT (automatically uses .venv)."
