"""Unit tests for the pure-logic parts of the GATT unauthenticated-access probe.

Connection/read/notify behaviour in core/gatt.py needs a live BLE peripheral
and isn't covered here - only the flag-construction logic.
"""

from core.gatt import _make_flag


def test_make_flag_read_access():
    flag = _make_flag(
        "0000180a-0000-1000-8000-00805f9b34fb",
        "00002a29-0000-1000-8000-00805f9b34fb",
        "read",
        ["read"],
    )

    assert flag.flag_id == "GATT_UNAUTHENTICATED_ACCESS"
    assert flag.severity == "MEDIUM"
    assert flag.cve == "CVE-2025-20700"
    assert flag.evidence["access"] == "read"
    assert flag.evidence["service_uuid"] == "0000180a-0000-1000-8000-00805f9b34fb"
    assert (
        flag.evidence["characteristic_uuid"] == "00002a29-0000-1000-8000-00805f9b34fb"
    )


def test_make_flag_notify_access_records_properties():
    flag = _make_flag(
        "0000180a-0000-1000-8000-00805f9b34fb",
        "00002a29-0000-1000-8000-00805f9b34fb",
        "notify",
        ["notify", "indicate"],
    )

    assert flag.evidence["access"] == "notify"
    assert flag.evidence["properties"] == ["notify", "indicate"]
