# Shadow IoT Mapper

ShadowIoT is a Kali-friendly asset mapper that blends **passive LAN observation** with **safe active enrichment** to build an IoT device inventory. It ships as a single Python CLI (`shadowiot`) with JSON-first outputs and optional CSV exports.

> ⚠️ **Use only on networks you are authorized to assess.** Active scanning can disrupt fragile IoT gear. Default settings are intentionally conservative and rate-limited.

## Quickstart (≈3 minutes)

```bash
# 1) Install (pipx preferred)
python -m pip install --upgrade pip
pipx install .
# or: python -m pip install .

# 2) Environment check
shadowiot doctor

# 3) Passive observe (needs sudo for sniffing)
sudo shadowiot passive --iface eth0 --duration 25 --out passive.json

# 4) Active enrichment (safe TCP connects)
shadowiot active --cidr 192.168.1.0/24 --ports 22,80,443 --out active.json

# 5) Merge to inventory (JSON or CSV)
shadowiot merge --passive passive.json --active active.json --out inventory.json
shadowiot merge --passive passive.json --active active.json --out inventory.csv --format csv
```

## What it does

- **Passive**: Listens for ARP (required) plus optional mDNS/SSDP chatter. Builds devices with evidence and timestamps without sending probes.
- **Active**: Lightweight TCP connect host discovery + banner grabs on a small, configurable port set (default: `22,80,443,8080,8443`) with built-in rate limiting.
- **Merge**: Dedupe by MAC/IP, roll up hostnames/services/evidence, and attach a confidence score. Outputs JSON or CSV inventories.
- **Doctor**: Platform, privilege, and dependency checks with actionable guidance (e.g., sudo needed for sniffing).

### Device model

```json
{
  "mac": "aa:bb:cc:dd:ee:ff",
  "ips": ["192.168.1.42"],
  "hostnames": ["cam.local"],
  "vendor": "Example Corp",
  "services": [{"port": 80, "protocol": "tcp", "banner": "Server: lighttpd"}],
  "first_seen": "2026-03-22T18:00:00Z",
  "last_seen": "2026-03-22T18:05:00Z",
  "evidence": [{"source": "arp", "detail": "ARP 192.168.1.42 is-at aa:bb:cc:dd:ee:ff"}],
  "confidence": 0.8
}
```

## Commands

- `shadowiot doctor` — readiness checks (OS, privileges, dependencies). Use `--json` for machine-readable output.
- `shadowiot passive --iface <iface> [--duration 20] [--no-mdns] [--no-ssdp] [--out FILE] [--format json|csv]`
  - No probes are sent. Requires sudo/CAP_NET_RAW for sniffing.
- `shadowiot active --cidr <cidr> [--ports 22,80,443] [--timeout 1.0] [--rate-limit 0.05] [--out FILE] [--format json|csv]`
  - Uses TCP connect (not raw packets) for safe host discovery and banner grabs.
- `shadowiot merge --passive passive.json --active active.json --out inventory.json [--format json|csv]`
  - Dedupe by MAC/IP, compute confidence, and emit a consolidated inventory.

## Safe modes & defaults

- Passive mode only listens. Active mode is TCP connect only and rate-limited (50ms between attempts).
- CIDR range guard refuses scans larger than 4096 addresses; tune the range instead of blasting large networks.
- Banners are read passively after connect; no payloads are sent beyond the handshake.

## Development

```bash
python -m venv .venv && source .venv/bin/activate
python -m pip install -e .[dev]
python -m ruff check .
python -m pytest
```

## Packaging / Docker

- Installable via `pipx install .` or `python -m pip install .`.
- A minimal Dockerfile is included for quick, isolated runs; build with `docker build -t shadowiot .` and run with `--net=host` for sniffing inside Linux hosts.

## License

MIT. See [LICENSE](LICENSE).
