#!/usr/bin/env bash
# ShadowIoT setup script
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

if [[ ! -x "${PROJECT_ROOT}/setup_venv.sh" ]]; then
  chmod +x "${PROJECT_ROOT}/setup_venv.sh"
fi
./setup_venv.sh

echo "[*] Setting execute permissions..."
chmod +x "${PROJECT_ROOT}/shadowiot.sh" "${PROJECT_ROOT}/scanner.py" "${PROJECT_ROOT}/setup.sh"

echo "[+] Setup complete. Run ./shadowiot.sh to launch ShadowIoT (automatically uses .venv)."
