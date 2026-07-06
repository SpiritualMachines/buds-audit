"""Unit tests for core.fingerprint matching logic."""

import pytest

from core.fingerprint import (
    AIROHA_COMPANY_ID,
    fingerprint_device,
    has_airoha_manufacturer_id,
    match_known_device,
    normalize_prefix,
)
from core.models import BtDevice


@pytest.fixture
def known_devices() -> list[dict]:
    return [
        {
            "brand": "Sony",
            "model": "WF-1000XM3",
            "address_prefix": "AC:7B:A1",
            "airoha_soc": "AB1562",
            "cves": ["CVE-2025-20700", "CVE-2025-20701", "CVE-2025-20702"],
            "patched_firmware": None,
            "notes": "TWS earbuds; confirmed affected by ERNW advisory",
        }
    ]


def make_device(
    address: str, manufacturer_data: dict[int, bytes] | None = None
) -> BtDevice:
    return BtDevice(
        address=address,
        name=None,
        rssi=None,
        transport="le",
        manufacturer_data=manufacturer_data or {},
    )


def test_normalize_prefix_uppercases_first_three_octets():
    assert normalize_prefix("ac:7b:a1:11:22:33") == "AC:7B:A1"


def test_has_airoha_manufacturer_id_true_when_present():
    assert has_airoha_manufacturer_id({AIROHA_COMPANY_ID: b"\x01"}) is True


def test_has_airoha_manufacturer_id_false_when_absent():
    assert has_airoha_manufacturer_id({0x004C: b"\x01"}) is False


def test_match_known_device_matches_case_insensitive(known_devices):
    device = make_device("ac:7b:a1:99:88:77")
    match = match_known_device(device, known_devices)
    assert match is not None
    assert match["brand"] == "Sony"


def test_match_known_device_returns_none_when_no_match(known_devices):
    device = make_device("00:11:22:33:44:55")
    assert match_known_device(device, known_devices) is None


def test_fingerprint_device_sets_profile_and_soc_on_match(known_devices):
    device = make_device("AC:7B:A1:00:00:01", {AIROHA_COMPANY_ID: b"\x01"})
    fingerprint_device(device, known_devices)
    assert device.matched_profile == known_devices[0]
    assert device.airoha_soc == "AB1562"


def test_fingerprint_device_marks_unconfirmed_when_id_present_no_match(known_devices):
    device = make_device("00:11:22:33:44:55", {AIROHA_COMPANY_ID: b"\x01"})
    fingerprint_device(device, known_devices)
    assert device.matched_profile is None
    assert device.airoha_soc is not None
    assert "unconfirmed" in device.airoha_soc


def test_fingerprint_device_leaves_none_when_no_signal(known_devices):
    device = make_device("00:11:22:33:44:55")
    fingerprint_device(device, known_devices)
    assert device.matched_profile is None
    assert device.airoha_soc is None
