from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Evidence:
    source: str
    detail: str
    timestamp: str = field(default_factory=now_iso)


@dataclass
class Service:
    port: int
    protocol: str = "tcp"
    banner: Optional[str] = None


@dataclass
class Device:
    mac: Optional[str] = None
    ips: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    vendor: Optional[str] = None
    services: List[Service] = field(default_factory=list)
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    evidence: List[Evidence] = field(default_factory=list)
    confidence: float = 0.2

    def touch(self):
        self.last_seen = now_iso()

    def to_dict(self):
        return {
            "mac": self.mac,
            "ips": self.ips,
            "hostnames": self.hostnames,
            "vendor": self.vendor,
            "services": [service.__dict__ for service in self.services],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "evidence": [e.__dict__ for e in self.evidence],
            "confidence": round(self.confidence, 2),
        }
