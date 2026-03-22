from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass
from typing import List


@dataclass
class DoctorFinding:
    ok: bool
    message: str


def _check_platform() -> DoctorFinding:
    system = platform.system()
    if system != "Linux":
        return DoctorFinding(
            ok=False,
            message=f"Non-Linux platform detected ({system}). Kali/Debian are recommended.",
        )
    return DoctorFinding(ok=True, message="Linux platform detected.")


def _check_privileges() -> DoctorFinding:
    geteuid = getattr(os, "geteuid", None)
    if geteuid and geteuid() != 0:
        return DoctorFinding(
            ok=False,
            message=(
                "Not running as root; packet capture may fail. "
                "Re-run with sudo for passive/ARP capture."
            ),
        )
    return DoctorFinding(ok=True, message="Sufficient privileges for packet capture.")


def _check_dependencies() -> List[DoctorFinding]:
    findings = []
    try:
        import scapy  # noqa: F401

        findings.append(DoctorFinding(ok=True, message="scapy available."))
    except Exception as exc:
        findings.append(
            DoctorFinding(
                ok=False,
                message=(
                    "scapy import failed: "
                    f"{exc}. Install via 'pip install shadow-iot-mapper' or run setup.sh."
                ),
            )
        )
    try:
        import zeroconf  # noqa: F401

        findings.append(DoctorFinding(ok=True, message="zeroconf available."))
    except Exception as exc:
        findings.append(
            DoctorFinding(
                ok=False,
                message=(
                    "zeroconf import failed: "
                    f"{exc}. Install via 'pip install shadow-iot-mapper'."
                ),
            )
        )
    if not shutil.which("tcpdump") and not shutil.which("tshark"):
        findings.append(
            DoctorFinding(
                ok=False,
                message=(
                    "Optional: tcpdump/tshark not found. "
                    "Passive troubleshooting will be easier with them installed."
                ),
            )
        )
    else:
        findings.append(
            DoctorFinding(ok=True, message="Packet inspection tools present (tcpdump/tshark).")
        )
    return findings


def run_doctor() -> List[DoctorFinding]:
    checks: List[DoctorFinding] = [
        _check_platform(),
        _check_privileges(),
    ]
    checks.extend(_check_dependencies())
    return checks
