"""Unit tests for baseline building and drift comparison logic."""

from core.baseline import build_baseline, compute_drift


def test_build_baseline_hex_encodes_manufacturer_data():
    baseline = build_baseline(
        name="Sony WF-1000XM3",
        manufacturer_data={0x05D6: b"\x01\x02"},
        gatt_table=["svc/char"],
        firmware_version="build-1",
        bonding_state={"paired": False, "trusted": False, "bonded": False},
    )

    assert baseline["manufacturer_data"] == {"1494": "0102"}
    assert baseline["gatt_table"] == ["svc/char"]
    assert baseline["firmware_version"] == "build-1"


def _baseline(**overrides) -> dict:
    base = {
        "name": "Sony WF-1000XM3",
        "manufacturer_data": {"1494": "0102"},
        "gatt_table": ["svc/char1", "svc/char2"],
        "firmware_version": "build-1",
        "bonding_state": {"paired": False, "trusted": False, "bonded": False},
    }
    base.update(overrides)
    return base


def test_compute_drift_no_flags_when_identical():
    baseline = _baseline()
    current = _baseline()

    assert compute_drift(baseline, current) == []


def test_compute_drift_identity_drift_on_name_change():
    baseline = _baseline()
    current = _baseline(name="Different Name")

    flags = compute_drift(baseline, current)

    assert len(flags) == 1
    assert flags[0].flag_id == "IDENTITY_DRIFT"
    assert flags[0].severity == "HIGH"


def test_compute_drift_identity_drift_on_manufacturer_data_change():
    baseline = _baseline()
    current = _baseline(manufacturer_data={"1494": "ffff"})

    flags = compute_drift(baseline, current)

    assert any(flag.flag_id == "IDENTITY_DRIFT" for flag in flags)


def test_compute_drift_no_flag_when_baseline_manufacturer_data_missing():
    # A single scan window doesn't reliably catch manufacturer-specific
    # data every time - an empty capture on either side must not be
    # treated as a conflicting value. Reproduces a real false positive
    # found live: --baseline caught an empty capture, a later --check-drift
    # caught real data, and nothing had actually changed.
    baseline = _baseline(manufacturer_data={})
    current = _baseline(manufacturer_data={"1494": "0102"})

    assert compute_drift(baseline, current) == []


def test_compute_drift_no_flag_when_current_manufacturer_data_missing():
    baseline = _baseline(manufacturer_data={"1494": "0102"})
    current = _baseline(manufacturer_data={})

    assert compute_drift(baseline, current) == []


def test_compute_drift_gatt_table_drift():
    baseline = _baseline()
    current = _baseline(gatt_table=["svc/char1"])

    flags = compute_drift(baseline, current)

    assert len(flags) == 1
    assert flags[0].flag_id == "GATT_TABLE_DRIFT"
    assert flags[0].severity == "MEDIUM"


def test_compute_drift_firmware_change_flagged_either_direction():
    baseline = _baseline(firmware_version="build-2")
    current = _baseline(firmware_version="build-1")

    flags = compute_drift(baseline, current)

    assert len(flags) == 1
    assert flags[0].flag_id == "FIRMWARE_DOWNGRADE"


def test_compute_drift_no_firmware_flag_when_either_side_unavailable():
    baseline = _baseline(firmware_version=None)
    current = _baseline(firmware_version="build-1")

    assert compute_drift(baseline, current) == []


def test_compute_drift_bond_state_drift():
    baseline = _baseline()
    current = _baseline(bonding_state={"paired": True, "trusted": True, "bonded": True})

    flags = compute_drift(baseline, current)

    assert len(flags) == 1
    assert flags[0].flag_id == "BOND_STATE_DRIFT"
    assert flags[0].severity == "HIGH"


def test_compute_drift_multiple_flags_can_fire_together():
    baseline = _baseline()
    current = _baseline(name="Different Name", gatt_table=["svc/char1"])

    flags = compute_drift(baseline, current)

    flag_ids = {flag.flag_id for flag in flags}
    assert flag_ids == {"IDENTITY_DRIFT", "GATT_TABLE_DRIFT"}
