"""Baseline capture and drift detection (compromise-assessment heuristics).

A baseline is a snapshot of a device's identity, GATT table, firmware
version, and local bonding state, captured once via explicit user action
(never automatically) and stored in data/device_baselines.json. Later runs
compare a fresh snapshot against it. This can never be forensic proof of
compromise - only a heuristic signal that something changed since the user
last trusted this device. See ROADMAP.md's Compromise Assessment section.

Baselines never store key material (link keys, IRKs): manufacturer_data is
stored hex-encoded for JSON compatibility, and bonding_state is only the
Paired/Trusted/Bonded booleans from core.gatt.get_bonding_state, never key
content.

firmware_version comparison can only detect "changed", not "downgraded":
RACE buildversion strings are opaque vendor build identifiers, not semver
(see core/race.py), so there's no sound ordering to compute a real downgrade
from. Any unexpected change is flagged under FIRMWARE_DOWNGRADE regardless
of direction, since a device the user didn't reflash shouldn't show a
different build at all - that's the compromise-relevant signal, not
specifically which direction it moved.

manufacturer_data comparison only fires when both snapshots actually have
data to compare, for the same reason firmware_version only compares when
both sides are present: a single scan window doesn't reliably capture
manufacturer-specific data every time. Confirmed live against the project's
own Sony WF-1000XM3 - three consecutive scans a few minutes apart returned
identical manufacturer data, but an earlier --baseline capture had caught a
window with none at all, which produced a false IDENTITY_DRIFT (comparing
{} against real data) with nothing having actually changed. Treating an
empty capture as "not observed this run," not "confirmed absent," avoids
that false positive while still catching a genuine conflict (both sides
present and different).
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import RuleFlag


def load_baselines(path: Path) -> dict:
    if not path.exists():
        return {}
    with path.open() as f:
        return json.load(f)


def save_baselines(path: Path, baselines: dict) -> None:
    with path.open("w") as f:
        json.dump(baselines, f, indent=2)


def build_baseline(
    name: str | None,
    manufacturer_data: dict[int, bytes],
    gatt_table: list[str],
    firmware_version: str | None,
    bonding_state: dict[str, bool],
) -> dict:
    return {
        "name": name,
        "manufacturer_data": {
            str(company_id): data.hex()
            for company_id, data in manufacturer_data.items()
        },
        "gatt_table": gatt_table,
        "firmware_version": firmware_version,
        "bonding_state": bonding_state,
    }


def compute_drift(baseline: dict, current: dict) -> list[RuleFlag]:
    flags: list[RuleFlag] = []

    baseline_mfg_data = baseline.get("manufacturer_data") or {}
    current_mfg_data = current.get("manufacturer_data") or {}
    mfg_data_conflicts = (
        bool(baseline_mfg_data)
        and bool(current_mfg_data)
        and baseline_mfg_data != current_mfg_data
    )

    if baseline.get("name") != current.get("name") or mfg_data_conflicts:
        flags.append(
            RuleFlag(
                flag_id="IDENTITY_DRIFT",
                severity="HIGH",
                description="Name or manufacturer data changed since the trusted baseline was captured",
                cve=None,
                evidence={
                    "baseline_name": baseline.get("name"),
                    "current_name": current.get("name"),
                    "baseline_manufacturer_data": baseline.get("manufacturer_data"),
                    "current_manufacturer_data": current.get("manufacturer_data"),
                },
            )
        )

    if baseline.get("gatt_table") != current.get("gatt_table"):
        flags.append(
            RuleFlag(
                flag_id="GATT_TABLE_DRIFT",
                severity="MEDIUM",
                description="GATT service/characteristic set differs from the trusted baseline",
                cve=None,
                evidence={
                    "baseline_gatt_table": baseline.get("gatt_table"),
                    "current_gatt_table": current.get("gatt_table"),
                },
            )
        )

    baseline_version = baseline.get("firmware_version")
    current_version = current.get("firmware_version")
    if (
        baseline_version is not None
        and current_version is not None
        and current_version != baseline_version
    ):
        flags.append(
            RuleFlag(
                flag_id="FIRMWARE_DOWNGRADE",
                severity="HIGH",
                description="Firmware build version differs from the trusted baseline",
                cve=None,
                evidence={
                    "baseline_firmware_version": baseline_version,
                    "current_firmware_version": current_version,
                },
            )
        )

    baseline_bonding = baseline.get("bonding_state", {})
    current_bonding = current.get("bonding_state", {})
    if baseline_bonding != current_bonding:
        flags.append(
            RuleFlag(
                flag_id="BOND_STATE_DRIFT",
                severity="HIGH",
                description="Local bonding record (paired/trusted/bonded) changed since the trusted baseline",
                cve=None,
                evidence={
                    "baseline_bonding_state": baseline_bonding,
                    "current_bonding_state": current_bonding,
                },
            )
        )

    return flags
