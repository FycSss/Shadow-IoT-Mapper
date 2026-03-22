# Shadow-IoT-Mapper

ShadowIoT is a red-team flavored network mapper for quick discovery of IoT devices.

## Setup

```bash
./setup.sh
```

The setup script creates a local `.venv` and installs dependencies there so it works on environments that block system-wide `pip` installs (e.g., Kali with PEP 668). The launcher automatically uses this virtual environment.

## Usage

```bash
./shadowiot.sh
```

Menu options:

- Scan Network (mDNS/UPnP)
- Identify Vulnerable Printers
- Credential Audit (Check Default Passwords)
- Export Network Map (JSON)
