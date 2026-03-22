from __future__ import annotations

from typing import Dict, Optional

from scapy.all import ARP, DNS, IP, UDP, Ether, Raw, sniff  # type: ignore

from .models import Device, Evidence, now_iso
from .utils import lookup_vendor, normalize_mac


def _get_or_create(devices: Dict[str, Device], mac: Optional[str], ip: Optional[str]) -> Device:
    key = normalize_mac(mac) or ip
    if not key:
        key = f"unknown-{len(devices)+1}"
    if key not in devices:
        devices[key] = Device(mac=normalize_mac(mac), ips=[ip] if ip else [])
    dev = devices[key]
    if mac and not dev.mac:
        dev.mac = normalize_mac(mac)
    if ip and ip not in dev.ips:
        dev.ips.append(ip)
    return dev


def _add_evidence(device: Device, source: str, detail: str, confidence: float):
    device.evidence.append(Evidence(source=source, detail=detail))
    device.confidence = min(1.0, device.confidence + confidence)
    device.touch()


def _handle_arp(packet, devices: Dict[str, Device]):
    arp = packet.getlayer(ARP)
    if not arp:
        return
    mac = getattr(arp, "hwsrc", None)
    ip = getattr(arp, "psrc", None)
    dev = _get_or_create(devices, mac, ip)
    detail = f"ARP {arp.psrc} is-at {arp.hwsrc}"
    dev.vendor = dev.vendor or lookup_vendor(dev.mac)
    _add_evidence(dev, "arp", detail, confidence=0.3)


def _handle_mdns(packet, devices: Dict[str, Device]):
    dns = packet.getlayer(DNS)
    if not dns:
        return
    ip_layer = packet.getlayer(IP)
    ip_src = getattr(ip_layer, "src", None) if ip_layer else None
    mac = packet.getlayer(Ether).src if packet.haslayer(Ether) else None
    dev = _get_or_create(devices, mac, ip_src)
    qname = (
        dns.qd.qname.decode(errors="ignore")
        if dns.qd and getattr(dns.qd, "qname", None)
        else ""
    )
    hostname = qname.rstrip(".local.") if qname else ""
    if hostname and hostname not in dev.hostnames:
        dev.hostnames.append(hostname)
    detail = f"mDNS query {qname}" if qname else "mDNS traffic observed"
    dev.vendor = dev.vendor or lookup_vendor(dev.mac)
    _add_evidence(dev, "mdns", detail, confidence=0.2)


def _handle_ssdp(packet, devices: Dict[str, Device]):
    raw = packet.getlayer(Raw)
    ip_layer = packet.getlayer(IP)
    ip_src = getattr(ip_layer, "src", None) if ip_layer else None
    mac = packet.getlayer(Ether).src if packet.haslayer(Ether) else None
    dev = _get_or_create(devices, mac, ip_src)
    payload = raw.load.decode(errors="ignore") if raw and getattr(raw, "load", None) else ""
    server_line = next(
        (line for line in payload.split("\r\n") if line.lower().startswith("server")), ""
    )
    detail = server_line or "SSDP/UPnP advertisement observed"
    dev.vendor = dev.vendor or lookup_vendor(dev.mac)
    _add_evidence(dev, "ssdp", detail, confidence=0.1)


def collect_passive(
    iface: str,
    duration: int = 20,
    include_mdns: bool = True,
    include_ssdp: bool = True,
) -> Dict:
    bpf_parts = ["arp"]
    if include_mdns:
        bpf_parts.append("udp port 5353")
    if include_ssdp:
        bpf_parts.append("udp port 1900")
    bpf_filter = " or ".join(bpf_parts)
    devices: Dict[str, Device] = {}
    try:
        packets = sniff(
            iface=iface, timeout=duration, filter=bpf_filter, store=True
        )  # pragma: no cover - relies on system
    except PermissionError as exc:  # pragma: no cover - environment dependent
        raise PermissionError(
            f"Permission denied while sniffing on {iface}. Try running with sudo. ({exc})"
        ) from exc
    except OSError as exc:  # pragma: no cover - environment dependent
        raise OSError(f"Unable to sniff on interface {iface}: {exc}") from exc
    for pkt in packets:
        if pkt.haslayer(ARP):
            _handle_arp(pkt, devices)
        if include_mdns and pkt.haslayer(DNS):
            _handle_mdns(pkt, devices)
        if include_ssdp and pkt.haslayer(UDP) and getattr(pkt[UDP], "dport", None) == 1900:
            _handle_ssdp(pkt, devices)
    payload = {
        "generated_at": now_iso(),
        "mode": "passive",
        "iface": iface,
        "devices": [dev.to_dict() for dev in devices.values()],
    }
    return payload
