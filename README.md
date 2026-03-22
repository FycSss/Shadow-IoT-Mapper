# Shadow-IoT-Mapper

ShadowIoT is a red-team flavored network mapper for quick discovery of IoT devices.

## Setup (after download)

1) Prereqs: Python 3 with the `venv` module (`sudo apt install python3 python3-venv` on Debian/Kali/Ubuntu).
2) Make the scripts executable (first time only):
```bash
chmod +x setup.sh shadowiot.sh scanner.py
```
3) Install deps into a local `.venv` so it works even on locked-down systems (e.g., Kali with PEP 668):
```bash
./setup.sh
```
The launcher automatically uses this virtual environment.

## Usage

```bash
./shadowiot.sh
```

Menu options:

- Scan Network (mDNS/UPnP)
- Identify Vulnerable Printers
- Credential Audit (Check Default Passwords)
- Export Network Map (JSON)
