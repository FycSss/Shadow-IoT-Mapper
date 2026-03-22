import json
from pathlib import Path

from shadowiot.merge import merge_inventories


def test_merge_inventories_dedup(tmp_path: Path):
    passive_data = {
        "devices": [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ips": ["192.168.1.10"],
                "hostnames": ["cam.local"],
                "vendor": "TestVendor",
                "services": [{"port": 80, "protocol": "tcp", "banner": "http"}],
                "evidence": [{"source": "arp", "detail": "seen"}],
                "confidence": 0.6,
            }
        ]
    }
    active_data = {
        "devices": [
            {
                "mac": "aa:bb:cc:dd:ee:ff",
                "ips": ["192.168.1.10"],
                "hostnames": [],
                "services": [{"port": 22, "protocol": "tcp", "banner": ""}],
                "evidence": [{"source": "active-scan", "detail": "open"}],
                "confidence": 0.4,
            }
        ]
    }
    passive_path = tmp_path / "passive.json"
    active_path = tmp_path / "active.json"
    passive_path.write_text(json.dumps(passive_data))
    active_path.write_text(json.dumps(active_data))

    merged = merge_inventories(str(passive_path), str(active_path))
    assert merged["devices"][0]["mac"] == "aa:bb:cc:dd:ee:ff"
    ports = {svc["port"] for svc in merged["devices"][0]["services"]}
    assert ports == {80, 22}
