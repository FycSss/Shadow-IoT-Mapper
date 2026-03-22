#!/usr/bin/env bash
set -e

# Create and activate a Python virtual environment and install dependencies
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[!] python3 is not installed. Please install Python 3 and retry."
  exit 1
fi

venv_dir="${PROJECT_ROOT}/.venv"

if [[ ! -d "$venv_dir" ]]; then
  echo "[*] Creating virtual environment at ${venv_dir}..."
  if ! python3 -m venv "$venv_dir"; then
    echo "[!] Failed to create virtual environment. Install python3-venv and retry."
    exit 1
  fi
fi

py="${venv_dir}/bin/python"

echo "[*] Installing Python dependencies (zeroconf, scapy) into the virtual environment..."
"$py" -m pip install --upgrade pip zeroconf scapy

echo "[+] Virtual environment ready at ${venv_dir}"
