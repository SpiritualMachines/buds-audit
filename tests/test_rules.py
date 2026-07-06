"""Unit tests for the verdict engine's priority logic."""

from core.models import BtDevice, RuleFlag
from core.rules import evaluate_verdict


def _device(matched: bool) -> BtDevice:
    profile = {"brand": "Sony", "model": "WF-1000XM3"} if matched else None
    return BtDevice(
        address="AC:7B:A1:11:22:33",
        name=None,
        rssi=None,
        transport="le",
        matched_profile=profile,
    )


def _flag(flag_id: str, severity: str) -> RuleFlag:
    return RuleFlag(flag_id=flag_id, severity=severity, description="test", cve=None)


def test_pass_when_unmatched_and_no_flags():
    assert evaluate_verdict(_device(matched=False), []) == "PASS"


def test_partial_when_matched_but_no_flags():
    assert evaluate_verdict(_device(matched=True), []) == "PARTIAL"


def test_partial_when_unmatched_but_low_severity_flag_raised():
    flags = [_flag("GATT_UNAUTHENTICATED_ACCESS", "MEDIUM")]
    assert evaluate_verdict(_device(matched=False), flags) == "PARTIAL"


def test_vulnerable_when_high_severity_flag_raised():
    flags = [_flag("RACE_EXPOSED", "HIGH")]
    assert evaluate_verdict(_device(matched=True), flags) == "VULNERABLE"


def test_vulnerable_when_critical_severity_flag_raised():
    flags = [_flag("SOME_FLAG", "CRITICAL")]
    assert evaluate_verdict(_device(matched=False), flags) == "VULNERABLE"


def test_suspected_compromise_supersedes_vulnerable():
    flags = [_flag("RACE_EXPOSED", "HIGH"), _flag("IDENTITY_DRIFT", "HIGH")]
    assert evaluate_verdict(_device(matched=True), flags) == "SUSPECTED_COMPROMISE"


def test_suspected_compromise_even_without_high_severity_flags():
    flags = [_flag("POSSIBLE_IMPERSONATION", "HIGH")]
    assert evaluate_verdict(_device(matched=False), flags) == "SUSPECTED_COMPROMISE"
