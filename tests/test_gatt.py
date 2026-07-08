"""Unit tests for the pure-logic parts of the GATT unauthenticated-access probe.

Connection/read/notify behaviour in core/gatt.py needs a live BLE peripheral
and isn't covered here - only the flag-construction logic.
"""

from bleak.exc import BleakDBusError, BleakError

from core.gatt import _is_security_required_error, _make_flag


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


def test_make_flag_omits_value_hex_when_no_value_given():
    flag = _make_flag(
        "0000180a-0000-1000-8000-00805f9b34fb",
        "00002a29-0000-1000-8000-00805f9b34fb",
        "notify",
        ["notify"],
    )

    assert "value_hex" not in flag.evidence


def test_make_flag_records_value_hex_when_value_given():
    flag = _make_flag(
        "0000180a-0000-1000-8000-00805f9b34fb",
        "00002a29-0000-1000-8000-00805f9b34fb",
        "read",
        ["read"],
        value=b"\x01\x02\xaa",
    )

    assert flag.evidence["value_hex"] == "0102aa"


def test_is_security_required_error_true_for_insufficient_encryption():
    # Raw, un-expanded detail text, matching what BlueZ actually sends -
    # BleakDBusError expands "0x0f" into "(Insufficient Encryption)" itself.
    exc = BleakDBusError("org.bluez.Error.Failed", ["ATT error: 0x0f"])

    assert _is_security_required_error(exc) is True


def test_is_security_required_error_true_for_insufficient_authentication():
    exc = BleakDBusError("org.bluez.Error.Failed", ["ATT error: 0x05"])

    assert _is_security_required_error(exc) is True


def test_is_security_required_error_false_for_unrelated_error():
    exc = BleakError("device not found")

    assert _is_security_required_error(exc) is False


def test_is_security_required_error_false_for_timeout():
    assert _is_security_required_error(TimeoutError("timed out")) is False
