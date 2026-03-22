import argparse
import json
import sys
from typing import List

from .active import scan_active
from .doctor import run_doctor
from .merge import merge_inventories
from .passive import collect_passive
from .utils import parse_ports, save_output

DEFAULT_PORTS = [22, 80, 443, 8080, 8443]


def _add_common_output_args(parser: argparse.ArgumentParser):
    parser.add_argument("--out", help="Optional output file path (JSON or CSV).")
    parser.add_argument(
        "--format",
        dest="format",
        choices=["json", "csv"],
        default="json",
        help="Output format (json default).",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shadowiot",
        description="ShadowIoT Mapper - passive LAN discovery and safe active enrichment.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="Check environment readiness.")
    doctor.add_argument("--json", action="store_true", help="Output doctor results as JSON.")

    passive = subparsers.add_parser("passive", help="Passive discovery (no probes).")
    passive.add_argument("--iface", required=True, help="Interface to sniff (e.g., eth0).")
    passive.add_argument(
        "--duration",
        type=int,
        default=20,
        help="Sniff duration in seconds (default: 20).",
    )
    passive.add_argument("--no-mdns", action="store_true", help="Disable mDNS observations.")
    passive.add_argument("--no-ssdp", action="store_true", help="Disable SSDP observations.")
    _add_common_output_args(passive)

    active = subparsers.add_parser("active", help="Active enrichment (safe TCP connects).")
    active.add_argument("--cidr", required=True, help="Target CIDR (e.g., 192.168.1.0/24).")
    active.add_argument(
        "--ports",
        default=",".join(str(p) for p in DEFAULT_PORTS),
        help=f"Comma-separated ports (default: {','.join(str(p) for p in DEFAULT_PORTS)}).",
    )
    active.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Per-connection timeout (seconds).",
    )
    active.add_argument(
        "--rate-limit",
        type=float,
        default=0.05,
        help="Delay between connection attempts in seconds (default: 0.05).",
    )
    _add_common_output_args(active)

    merge = subparsers.add_parser("merge", help="Merge passive and active inventories.")
    merge.add_argument("--passive", required=True, help="Path to passive JSON results.")
    merge.add_argument("--active", required=True, help="Path to active JSON results.")
    merge.add_argument("--out", required=True, help="Output path for merged inventory.")
    merge.add_argument(
        "--format",
        dest="format",
        choices=["json", "csv"],
        default="json",
        help="Output format (json default).",
    )
    return parser


def handle_doctor(args) -> int:
    findings = run_doctor()
    ok = all(f.ok for f in findings)
    if args.json:
        payload = {"ok": ok, "findings": [f.__dict__ for f in findings]}
        print(json.dumps(payload, indent=2))
    else:
        for finding in findings:
            prefix = "[+]" if finding.ok else "[!]"
            print(f"{prefix} {finding.message}")
    return 0 if ok else 1


def handle_passive(args) -> int:
    payload = collect_passive(
        iface=args.iface,
        duration=args.duration,
        include_mdns=not args.no_mdns,
        include_ssdp=not args.no_ssdp,
    )
    serialized = save_output(payload, fmt=args.format, out_path=args.out)
    print(serialized)
    return 0


def handle_active(args) -> int:
    ports: List[int] = parse_ports(args.ports)
    payload = scan_active(
        cidr=args.cidr,
        ports=ports or DEFAULT_PORTS,
        timeout=args.timeout,
        rate_limit=args.rate_limit,
    )
    serialized = save_output(payload, fmt=args.format, out_path=args.out)
    print(serialized)
    return 0


def handle_merge(args) -> int:
    payload = merge_inventories(
        passive_path=args.passive,
        active_path=args.active,
        fmt=args.format,
        out=args.out,
    )
    if args.format == "json":
        print(json.dumps(payload, indent=2))
    else:
        print(f"[+] Merged inventory written to {args.out}")
    return 0


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "doctor":
            return handle_doctor(args)
        if args.command == "passive":
            return handle_passive(args)
        if args.command == "active":
            return handle_active(args)
        if args.command == "merge":
            return handle_merge(args)
    except Exception as exc:  # pragma: no cover - cli surface
        print(f"[!] {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
