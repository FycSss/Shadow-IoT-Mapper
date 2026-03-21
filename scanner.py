#!/usr/bin/env python3
"""
ShadowIoT Scanner - backend logic invoked by shadowiot.sh
"""
import argparse
import ipaddress
import json
import socket
import sys
import time
from datetime import datetime, timezone

from zeroconf import ServiceBrowser, Zeroconf

try:
    from scapy.all import (
        ARP,
        IP,
        TCP,
        UDP,
        Raw,
        arping,
        conf,
        send,
        sniff,
        sr,
    )
except Exception as exc:  # pragma: no cover - runtime dependency guard
    print(f"[!] Unable to import scapy: {exc}")
    sys.exit(1)


class Colors:
    GREEN = "\033[1;32m"
    RED = "\033[1;31m"
    BLUE = "\033[1;34m"
    RESET = "\033[0m"


def log_discovery(message: str):
    print(f"{Colors.GREEN}[+] {message}{Colors.RESET}")


def log_vuln(message: str):
    print(f"{Colors.RED}[!] {message}{Colors.RESET}")


def log_info(message: str):
    print(f"{Colors.BLUE}[*] {message}{Colors.RESET}")


MDNS_SERVICE_INFO_TIMEOUT_MS = 2000
SYN_ACK_FLAGS = 0x12  # SYN+ACK response (0x02 | 0x10)


def expand_targets(target: str):
    try:
        network = ipaddress.ip_network(target, strict=False)
        hosts = list(network.hosts())
        if not hosts:
            hosts = [network.network_address]
        return [str(host) for host in hosts]
    except ValueError:
        return [target]


def mdns_scan(timeout: int = 6):
    zeroconf = Zeroconf()
    services = []
    seen_services = set()

    class BrowserListener:
        def add_service(self, zc, service_type, name):
            if (service_type, name) in seen_services:
                return
            info = zc.get_service_info(
                service_type, name, timeout=MDNS_SERVICE_INFO_TIMEOUT_MS  # milliseconds (2s)
            )
            if info:
                addr = "unknown"
                if info.addresses:
                    try:
                        if len(info.addresses[0]) == 4:
                            addr = socket.inet_ntop(socket.AF_INET, info.addresses[0])
                        elif len(info.addresses[0]) == 16:
                            addr = socket.inet_ntop(socket.AF_INET6, info.addresses[0])
                    except OSError:
                        addr = "unknown"
                seen_services.add((service_type, name))
                record = {
                    "name": name,
                    "type": service_type,
                    "address": addr,
                    "port": info.port,
                }
                services.append(record)
                log_discovery(f"mDNS: {name} @ {addr}:{info.port} ({service_type})")

        # Zeroconf ServiceBrowser invokes update_service on PTR changes; seen_services prevents duplicates so updates follow the add path.
        update_service = add_service

        def remove_service(self, *args, **kwargs):
            return None

    log_info("Starting mDNS discovery...")
    browser = ServiceBrowser(zeroconf, "_services._dns-sd._udp.local.", BrowserListener())
    time.sleep(timeout)
    zeroconf.close()
    return services


def upnp_scan(timeout: int = 4):
    def parse_header_value(line: str) -> str:
        return line.split(":", 1)[1].strip() if ":" in line else ""

    ssdp_payload = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST:239.255.255.250:1900",
            "ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1",
            "MAN:\"ssdp:discover\"",
            "MX:2",
            "",
            "",
        ]
    )
    responses = []
    log_info("Broadcasting SSDP/UPnP probe...")
    try:
        send(
            IP(dst="239.255.255.250") / UDP(sport=1900, dport=1900) / Raw(load=ssdp_payload),
            verbose=0,
        )
        sniffed = sniff(filter="udp and port 1900", timeout=timeout)
        for packet in sniffed:
            if packet.haslayer(IP):
                src = packet[IP].src
            else:
                src = "unknown"
            raw = bytes(packet[Raw].load).decode(errors="ignore") if packet.haslayer(Raw) else ""
            server_line = next(
                (line for line in raw.splitlines() if line.lower().startswith("server")), ""
            )
            location_line = next(
                (line for line in raw.splitlines() if line.lower().startswith("location")), ""
            )
            server_value = parse_header_value(server_line)
            location_value = parse_header_value(location_line)
            record = {
                "source": src,
                "server": server_value,
                "location": location_value,
            }
            responses.append(record)
            log_discovery(f"UPnP: {src} {record['server']}".strip())
    except PermissionError:
        log_info("Insufficient privileges to sniff UPnP responses. Run as root for full results.")
    except Exception as exc:
        log_info(f"UPnP discovery warning: {exc}")
    return responses


def printer_scan(target: str, ports=None):
    if ports is None:
        ports = [515, 631, 9100]
    hosts = expand_targets(target)
    log_info(f"Scanning {len(hosts)} host(s) for printer services...")
    answered, _ = sr(IP(dst=hosts) / TCP(dport=ports, flags="S"), timeout=3, verbose=0)
    findings = []
    for sent, received in answered:
        tcp = received.getlayer(TCP)
        if tcp and (tcp.flags & SYN_ACK_FLAGS) == SYN_ACK_FLAGS:  # SYN+ACK confirms the port accepted the handshake (not RST)
            record = {"host": received[IP].src, "port": tcp.sport}
            findings.append(record)
            desc = f"Printer service open on {record['host']}:{record['port']}"
            log_vuln(desc if record["port"] == 9100 else f"{desc} (LPD/IPP)")
    if not findings:
        log_info("No exposed printer services detected.")
    return findings


def credential_audit(target: str, ports=None):
    if ports is None:
        ports = [22, 23, 80, 443, 554]
    hosts = expand_targets(target)
    log_info(f"Auditing management ports across {len(hosts)} host(s)...")
    answered, _ = sr(IP(dst=hosts) / TCP(dport=ports, flags="S"), timeout=3, verbose=0)
    issues = []
    for _, received in answered:
        tcp = received.getlayer(TCP)
        if tcp and (tcp.flags & SYN_ACK_FLAGS) == SYN_ACK_FLAGS:  # SYN+ACK indicates the management port is listening
            host = received[IP].src
            port = tcp.sport
            issues.append({"host": host, "port": port})
            log_vuln(f"Potential default credentials on {host}:{port} (service exposed)")
    if not issues:
        log_info("No exposed management services found.")
    return issues


def export_network_map(target: str, output_path: str = "network_map.json"):
    log_info(f"Enumerating live hosts on {target} via ARP...")
    try:
        answered, _ = arping(target, timeout=3, verbose=0)
    except PermissionError:
        log_info("Insufficient privileges for ARP scan. Run as root for full results.")
        answered = []
    hosts = [
        {"ip": rcv.psrc, "mac": rcv.hwsrc}
        for _, rcv in answered
        if rcv.haslayer(ARP)
    ]
    if not hosts:
        log_info("No hosts responded to ARP probe.")
    else:
        for host in hosts:
            log_discovery(f"Host: {host['ip']} ({host['mac']})")
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "hosts": hosts,
    }
    with open(output_path, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)
    log_info(f"Network map exported to {output_path}")
    return payload


def parse_args():
    parser = argparse.ArgumentParser(
        description="ShadowIoT scanner backend (mDNS/UPnP, printers, credential audit, export)"
    )
    parser.add_argument(
        "--mode",
        required=True,
        choices=["mdns-upnp", "printers", "creds", "export"],
        help="Scan mode to execute",
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP or CIDR range (e.g., 192.168.1.0/24)",
    )
    return parser.parse_args()


def main():
    conf.verb = 0  # Silence scapy chatter
    args = parse_args()
    if args.mode == "mdns-upnp":
        mdns_scan()
        upnp_scan()
    elif args.mode == "printers":
        printer_scan(args.target)
    elif args.mode == "creds":
        credential_audit(args.target)
    elif args.mode == "export":
        export_network_map(args.target)
    else:  # pragma: no cover - argparse handles choices
        log_info("Unknown mode selected.")


if __name__ == "__main__":
    main()
