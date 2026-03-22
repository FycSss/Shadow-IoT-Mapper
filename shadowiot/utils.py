from __future__ import annotations

import csv
import ipaddress
import json
import socket
import time
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from .models import Device

try:
    from manuf import manuf
except Exception:  # pragma: no cover - optional dependency guard
    manuf = None


def normalize_mac(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    stripped = mac.replace("-", ":").replace(".", "")
    if len(stripped) == 12:
        stripped = ":".join(stripped[i : i + 2] for i in range(0, 12, 2))
    return stripped.lower()


def lookup_vendor(mac: Optional[str]) -> Optional[str]:
    if not mac:
        return None
    mac = normalize_mac(mac)
    if manuf:
        try:
            parser = manuf.MacParser()
            vendor = parser.get_manuf(mac)
            return vendor
        except Exception:
            return None
    return None


def parse_ports(ports: str) -> List[int]:
    cleaned = ports.replace(" ", "")
    if not cleaned:
        return []
    parsed = []
    for part in cleaned.split(","):
        if "-" in part:
            start, end = part.split("-", 1)
            parsed.extend(range(int(start), int(end) + 1))
        else:
            parsed.append(int(part))
    return sorted(set(port for port in parsed if 0 < port < 65536))


def save_output(payload, fmt: str = "json", out_path: Optional[str] = None) -> str:
    fmt = fmt.lower()
    if fmt not in {"json", "csv"}:
        raise ValueError("format must be json or csv")

    if fmt == "json":
        serialized = json.dumps(payload, indent=2)
    else:
        serialized = devices_to_csv(payload.get("devices", []))

    if out_path:
        path = Path(out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        mode = "w"
        encoding = "utf-8"
        with path.open(mode, encoding=encoding, newline="") as fp:
            fp.write(serialized)
    return serialized


def devices_to_csv(devices: Iterable[Dict]) -> str:
    fieldnames = [
        "mac",
        "ips",
        "hostnames",
        "vendor",
        "services",
        "first_seen",
        "last_seen",
        "confidence",
        "evidence",
    ]
    rows = []
    for dev in devices:
        rows.append(
            {
                "mac": dev.get("mac") or "",
                "ips": ";".join(dev.get("ips", [])),
                "hostnames": ";".join(dev.get("hostnames", [])),
                "vendor": dev.get("vendor") or "",
                "services": ";".join(
                    f"{svc.get('protocol','tcp')}/{svc.get('port')}:{svc.get('banner','')}"
                    for svc in dev.get("services", [])
                ),
                "first_seen": dev.get("first_seen", ""),
                "last_seen": dev.get("last_seen", ""),
                "confidence": dev.get("confidence", ""),
                "evidence": ";".join(
                    f"{ev.get('source')}|{ev.get('detail')}" for ev in dev.get("evidence", [])
                ),
            }
        )
    from io import StringIO

    buffer = StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)
    return buffer.getvalue()


def load_inventory(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as fp:
        data = json.load(fp)
    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError("Input must be a JSON object with a 'devices' list")
    return data


def merge_devices(primary: Device, update: Device):
    if update.mac and not primary.mac:
        primary.mac = normalize_mac(update.mac)
    elif update.mac:
        primary.mac = normalize_mac(primary.mac)
    for ip in update.ips:
        if ip not in primary.ips:
            primary.ips.append(ip)
    for host in update.hostnames:
        if host not in primary.hostnames:
            primary.hostnames.append(host)
    if not primary.vendor and update.vendor:
        primary.vendor = update.vendor
    existing_ports = {(svc.port, svc.protocol) for svc in primary.services}
    for svc in update.services:
        key = (svc.port, svc.protocol)
        if key not in existing_ports:
            primary.services.append(svc)
            existing_ports.add(key)
    primary.evidence.extend(update.evidence)
    primary.confidence = min(1.0, max(primary.confidence, update.confidence))
    primary.touch()


def rate_limited_connect(
    host: str, port: int, timeout: float, rate_limit: float
) -> Tuple[bool, Optional[str]]:
    time.sleep(rate_limit)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            result = sock.connect_ex((host, port))
            if result == 0:
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(128)
                    banner_text = banner.decode(errors="ignore").strip()
                except Exception:
                    banner_text = ""
                return True, banner_text
            if result in (111, 61, 10061):  # connection refused on linux/mac/windows
                return False, ""
            return False, None
        except OSError:
            return False, None


def network_hosts(cidr: str, max_hosts: int = 4096) -> List[str]:
    network = ipaddress.ip_network(cidr, strict=False)
    if network.num_addresses > max_hosts:
        raise ValueError(f"Refusing to scan {network.num_addresses} addresses; reduce the range.")
    hosts = [str(h) for h in network.hosts()]
    if not hosts:
        hosts = [str(network.network_address)]
    return hosts
