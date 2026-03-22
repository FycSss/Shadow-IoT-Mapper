from __future__ import annotations

import socket
from typing import Dict, List

from .models import Device, Evidence, Service, now_iso
from .utils import network_hosts, rate_limited_connect


def scan_active(
    cidr: str,
    ports: List[int],
    timeout: float = 1.0,
    rate_limit: float = 0.05,
) -> Dict:
    hosts = network_hosts(cidr)
    devices: List[Device] = []
    for host in hosts:
        device = Device(ips=[host], confidence=0.2)
        try:
            hostname = socket.getfqdn(host)
            if hostname and hostname != host and hostname not in device.hostnames:
                device.hostnames.append(hostname)
        except Exception:
            pass
        alive = False
        for port in ports:
            is_open, banner = rate_limited_connect(
                host,
                port,
                timeout=timeout,
                rate_limit=rate_limit,
            )
            if is_open:
                alive = True
                device.services.append(Service(port=port, banner=banner or None))
                device.evidence.append(
                    Evidence(
                        source="active-scan",
                        detail=f"tcp/{port} open (banner={banner or 'n/a'})",
                    )
                )
                device.confidence = min(1.0, device.confidence + 0.35)
            elif banner == "":
                alive = True
                device.evidence.append(
                    Evidence(
                        source="active-scan",
                        detail=f"{host}:{port} refused connection",
                    )
                )
                device.confidence = min(1.0, device.confidence + 0.1)
        if alive:
            devices.append(device)
    payload = {
        "generated_at": now_iso(),
        "mode": "active",
        "cidr": cidr,
        "ports": ports,
        "devices": [dev.to_dict() for dev in devices],
    }
    return payload
