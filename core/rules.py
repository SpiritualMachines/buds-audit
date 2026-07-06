"""Rule engine: combines flags from all probes into one verdict per device.

Verdict priority (highest wins): SUSPECTED_COMPROMISE > VULNERABLE > PARTIAL >
PASS. See CLAUDE.md's Verdict mapping table for the canonical definition.
This resolves one gap in that table explicitly: a device absent from
data/affected_devices.json can still raise a live flag (e.g. an unpaired GATT
read succeeding against an unknown device) without any HIGH/CRITICAL
severity. That case is PARTIAL, not PASS - PASS requires both "not on the
known-affected list" and "no flags raised at all".

COMPROMISE_INDICATOR_FLAGS lists the drift flags from Phase 6
(core/baseline.py) and the impersonation flag from Phase 7
(core/impersonation.py).
"""

from __future__ import annotations

from core.models import AssessmentResult, BtDevice, RuleFlag

HIGH_SEVERITIES = {"HIGH", "CRITICAL"}

COMPROMISE_INDICATOR_FLAGS = {
    "IDENTITY_DRIFT",
    "GATT_TABLE_DRIFT",
    "FIRMWARE_DOWNGRADE",
    "BOND_STATE_DRIFT",
    "RECENT_UNEXPECTED_RESET",
    "POSSIBLE_IMPERSONATION",
}


def evaluate_verdict(device: BtDevice, flags: list[RuleFlag]) -> str:
    flag_ids = {flag.flag_id for flag in flags}

    if flag_ids & COMPROMISE_INDICATOR_FLAGS:
        return "SUSPECTED_COMPROMISE"

    if any(flag.severity in HIGH_SEVERITIES for flag in flags):
        return "VULNERABLE"

    if flags or device.matched_profile is not None:
        return "PARTIAL"

    return "PASS"


def assess_device(device: BtDevice, flags: list[RuleFlag]) -> AssessmentResult:
    return AssessmentResult(
        device=device, verdict=evaluate_verdict(device, flags), flags=flags
    )
