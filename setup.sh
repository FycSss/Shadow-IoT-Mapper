#!/usr/bin/env bash
# ShadowIoT setup script
set -e

echo "[*] Installing Python dependencies (zeroconf, scapy)..."
if command -v pip3 >/dev/null 2>&1; then
  pip3 install --quiet --upgrade pip
  pip3 install --quiet zeroconf scapy
elif command -v pip >/dev/null 2>&1; then
  pip install --quiet --upgrade pip
  pip install --quiet zeroconf scapy
else
  echo "[!] pip is not installed. Please install pip or Python 3."
  exit 1
fi

echo "[*] Setting execute permissions..."
chmod +x shadowiot.sh scanner.py

echo "[+] Setup complete. Run ./shadowiot.sh to launch ShadowIoT."
