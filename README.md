# Shadow-IoT-Mapper

ShadowIoT is a red-team flavored network mapper for quick discovery of IoT devices.

## Setup

On Kali/WSL/Linux, use a virtual environment to avoid system Python restrictions:

```bash
cd Shadow-IoT-Mapper
./setup.sh
```

This will:

- Create `.venv` in the project
- Install `zeroconf` and `scapy` into the virtual environment

To manually activate the environment later:

```bash
source .venv/bin/activate
```

## Running Shadow IoT Mapper

After setup:

```bash
cd Shadow-IoT-Mapper
source .venv/bin/activate
./shadowiot.sh
```

`shadowiot.sh` will automatically use `.venv` even if you skip manual activation, but activating ensures any follow-on Python commands also use the virtual environment.
It locates the bundled `.venv/bin/python` at runtime, so manual activation is optional for running the tool itself.

Menu options:

- Scan Network (mDNS/UPnP)
- Identify Vulnerable Printers
- Credential Audit (Check Default Passwords)
- Export Network Map (JSON)
