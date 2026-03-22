from __future__ import annotations

from typing import Dict

from .models import Device, Evidence, Service, now_iso
from .utils import load_inventory, lookup_vendor, merge_devices, normalize_mac, save_output


def _device_from_dict(data: Dict) -> Device:
    dev = Device(
        mac=normalize_mac(data.get("mac")),
        ips=list(data.get("ips", [])),
        hostnames=list(data.get("hostnames", [])),
        vendor=data.get("vendor"),
        confidence=float(data.get("confidence", 0.2)),
    )
    dev.first_seen = data.get("first_seen", dev.first_seen)
    dev.last_seen = data.get("last_seen", dev.last_seen)
    dev.services = [
        Service(
            port=s.get("port"),
            protocol=s.get("protocol", "tcp"),
            banner=s.get("banner"),
        )
        for s in data.get("services", [])
        if s.get("port") is not None
    ]
    dev.evidence = [
        Evidence(
            source=e.get("source"),
            detail=e.get("detail"),
            timestamp=e.get("timestamp"),
        )
        for e in data.get("evidence", [])
        if e.get("source")
    ]
    return dev


def _score_device(device: Device):
    score = 0.2
    if device.mac:
        score += 0.3
    if device.services:
        score += 0.2
    if len(device.ips) > 1:
        score += 0.1
    if device.hostnames:
        score += 0.1
    device.confidence = min(1.0, max(device.confidence, score))
    if not device.vendor:
        device.vendor = lookup_vendor(device.mac)


def merge_inventories(
    passive_path: str,
    active_path: str,
    fmt: str = "json",
    out: str | None = None,
) -> Dict:
    passive = load_inventory(passive_path)
    active = load_inventory(active_path)
    combined: Dict[str, Device] = {}

    def upsert(dev: Device):
        key = dev.mac or (dev.ips[0] if dev.ips else f"unknown-{len(combined)+1}")
        if key in combined:
            merge_devices(combined[key], dev)
        else:
            combined[key] = dev

    for record in passive.get("devices", []):
        upsert(_device_from_dict(record))
    for record in active.get("devices", []):
        upsert(_device_from_dict(record))

    for dev in combined.values():
        _score_device(dev)

    payload = {
        "generated_at": now_iso(),
        "mode": "merged",
        "sources": {"passive": passive_path, "active": active_path},
        "devices": [dev.to_dict() for dev in combined.values()],
    }
    if out:
        save_output(payload, fmt=fmt, out_path=out)
    return payload
