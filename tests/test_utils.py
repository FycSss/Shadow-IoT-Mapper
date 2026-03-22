from shadowiot import utils


def test_parse_ports_range_and_list():
    ports = utils.parse_ports("22,80-81,443")
    assert ports == [22, 80, 81, 443]


def test_devices_to_csv_serializes():
    devices = [
        {
            "mac": "aa:bb:cc:dd:ee:ff",
            "ips": ["192.168.1.10"],
            "hostnames": ["cam.local"],
            "vendor": "TestVendor",
            "services": [{"port": 80, "protocol": "tcp", "banner": "http"}],
            "first_seen": "now",
            "last_seen": "now",
            "confidence": 0.8,
            "evidence": [{"source": "arp", "detail": "test"}],
        }
    ]
    csv_output = utils.devices_to_csv(devices)
    assert "aa:bb:cc:dd:ee:ff" in csv_output
    assert "services" in csv_output.splitlines()[0]
