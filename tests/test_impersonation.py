"""Unit tests for impersonation/duplicate-identity correlation logic."""

import asyncio

import pytest
from bleak.exc import BleakError

from core.impersonation import (
    AdvertisementSample,
    _identity_key,
    _windows_overlap,
    collect_advertisements,
    detect_duplicate_identities,
)
from core.scanner import ScanError


class _FailingScanner:
    """Stands in for BleakScanner to simulate an unavailable adapter
    without needing real hardware - mirrors a live-confirmed failure mode
    (see tests/test_scanner.py)."""

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        raise BleakError("adapter not available")

    async def __aexit__(self, *exc_info):
        return False


def test_collect_advertisements_wraps_bleak_error_as_scan_error(monkeypatch):
    monkeypatch.setattr("core.impersonation.BleakScanner", _FailingScanner)

    with pytest.raises(ScanError):
        asyncio.run(collect_advertisements(1.0))


def _sample(
    address, name="Sony WF-1000XM3", mfg=((0x05D6, b"\x01"),), rssi=-50, ts=0.0
):
    return AdvertisementSample(
        address=address, name=name, manufacturer_data=mfg, rssi=rssi, timestamp=ts
    )


def test_identity_key_none_when_name_missing():
    assert _identity_key(_sample("AA:AA:AA:AA:AA:AA", name=None)) is None
    assert _identity_key(_sample("AA:AA:AA:AA:AA:AA", name="")) is None


def test_identity_key_matches_on_name_and_manufacturer_data():
    a = _sample("AA:AA:AA:AA:AA:AA")
    b = _sample("BB:BB:BB:BB:BB:BB")
    assert _identity_key(a) == _identity_key(b)


def test_windows_overlap_true_when_ranges_intersect():
    assert _windows_overlap((0.0, 5.0), (3.0, 8.0), tolerance=0.0)


def test_windows_overlap_true_within_tolerance_when_adjacent():
    assert _windows_overlap((0.0, 5.0), (6.0, 10.0), tolerance=2.0)


def test_windows_overlap_false_when_far_apart():
    assert not _windows_overlap((0.0, 5.0), (30.0, 40.0), tolerance=2.0)


def test_detect_duplicate_identities_no_flag_for_single_address():
    samples = [
        _sample("AA:AA:AA:AA:AA:AA", ts=0.0),
        _sample("AA:AA:AA:AA:AA:AA", ts=1.0),
    ]
    assert detect_duplicate_identities(samples) == []


def test_detect_duplicate_identities_ignores_nameless_samples():
    samples = [
        _sample("AA:AA:AA:AA:AA:AA", name=None, ts=0.0),
        _sample("BB:BB:BB:BB:BB:BB", name=None, ts=0.5),
    ]
    assert detect_duplicate_identities(samples) == []


def test_detect_duplicate_identities_flags_concurrent_duplicate():
    samples = [
        _sample("AA:AA:AA:AA:AA:AA", ts=0.0),
        _sample("AA:AA:AA:AA:AA:AA", ts=1.0),
        _sample("BB:BB:BB:BB:BB:BB", ts=0.5),
        _sample("BB:BB:BB:BB:BB:BB", ts=1.5),
    ]
    flags = detect_duplicate_identities(samples)

    assert len(flags) == 1
    assert flags[0].flag_id == "POSSIBLE_IMPERSONATION"
    assert flags[0].severity == "HIGH"
    assert set(flags[0].evidence["addresses"]) == {
        "AA:AA:AA:AA:AA:AA",
        "BB:BB:BB:BB:BB:BB",
    }


def test_detect_duplicate_identities_no_flag_when_sequential_address_rotation():
    # One address stops advertising well before the other starts - looks
    # like normal address rotation of a single device, not a second
    # simultaneous transmitter, so no flag.
    samples = [
        _sample("AA:AA:AA:AA:AA:AA", ts=0.0),
        _sample("AA:AA:AA:AA:AA:AA", ts=1.0),
        _sample("BB:BB:BB:BB:BB:BB", ts=30.0),
        _sample("BB:BB:BB:BB:BB:BB", ts=31.0),
    ]
    assert detect_duplicate_identities(samples, tolerance=2.0) == []


def test_detect_duplicate_identities_different_identities_not_grouped():
    samples = [
        _sample("AA:AA:AA:AA:AA:AA", name="Sony WF-1000XM3", ts=0.0),
        _sample("BB:BB:BB:BB:BB:BB", name="Bose QC35", ts=0.0),
    ]
    assert detect_duplicate_identities(samples) == []
