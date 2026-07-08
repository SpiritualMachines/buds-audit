"""Unit tests for the pure-logic parts of assessment output formatting.

print_* functions are exercised via capsys where the shape of stdout matters
(grouping/ordering); REMEDIATION text content itself isn't asserted verbatim
since it's just static guidance, not logic.
"""

from core.models import AssessmentResult, BtDevice, RuleFlag
from core.report import _group_flags_by_severity, print_assessment_result


def _flag(flag_id: str, severity: str, **evidence) -> RuleFlag:
    return RuleFlag(
        flag_id=flag_id,
        severity=severity,
        description=f"{flag_id} description",
        cve="CVE-2025-20700",
        evidence=evidence,
    )


def test_group_flags_by_severity_orders_high_before_medium():
    flags = [
        _flag("GATT_UNAUTHENTICATED_ACCESS", "MEDIUM"),
        _flag("RACE_EXPOSED", "HIGH"),
    ]

    groups = _group_flags_by_severity(flags)

    assert [group[0].flag_id for group in groups] == [
        "RACE_EXPOSED",
        "GATT_UNAUTHENTICATED_ACCESS",
    ]


def test_group_flags_by_severity_groups_same_flag_id_together():
    flags = [
        _flag("GATT_UNAUTHENTICATED_ACCESS", "MEDIUM", access="read"),
        _flag("RACE_EXPOSED", "HIGH"),
        _flag("GATT_UNAUTHENTICATED_ACCESS", "MEDIUM", access="notify"),
    ]

    groups = _group_flags_by_severity(flags)

    gatt_group = next(
        g for g in groups if g[0].flag_id == "GATT_UNAUTHENTICATED_ACCESS"
    )
    assert len(gatt_group) == 2
    assert [flag.evidence["access"] for flag in gatt_group] == ["read", "notify"]


def test_group_flags_by_severity_unknown_severity_sorts_last():
    flags = [
        _flag("SOME_NEW_FLAG", "UNKNOWN"),
        _flag("RACE_EXPOSED", "HIGH"),
    ]

    groups = _group_flags_by_severity(flags)

    assert groups[0][0].flag_id == "RACE_EXPOSED"
    assert groups[-1][0].flag_id == "SOME_NEW_FLAG"


def test_print_assessment_result_collapses_repeated_gatt_findings(capsys):
    device = BtDevice(address="AA:BB:CC:DD:EE:FF", name=None, rssi=None, transport="le")
    flags = [
        _flag(
            "GATT_UNAUTHENTICATED_ACCESS",
            "MEDIUM",
            access="read",
            characteristic_uuid="char-1",
            service_uuid="svc-1",
            value_hex="0000",
        ),
        _flag(
            "GATT_UNAUTHENTICATED_ACCESS",
            "MEDIUM",
            access="notify",
            characteristic_uuid="char-2",
            service_uuid="svc-1",
        ),
        _flag("RACE_EXPOSED", "HIGH"),
    ]
    result = AssessmentResult(device=device, verdict="PARTIAL", flags=flags)

    print_assessment_result(result)

    output = capsys.readouterr().out
    assert (
        "3 finding(s): 1 RACE_EXPOSED (HIGH), 2 GATT_UNAUTHENTICATED_ACCESS (MEDIUM)"
        in output
    )
    assert "- 2 instance(s)" in output
    assert "- read: char-1 (service svc-1), value=0000" in output
    assert "- notify: char-2 (service svc-1)" in output
    # RACE_EXPOSED (HIGH) must appear before the GATT group (MEDIUM) in output order.
    assert output.index("RACE_EXPOSED") < output.index("GATT_UNAUTHENTICATED_ACCESS")


def test_print_assessment_result_single_instance_shows_full_description(capsys):
    device = BtDevice(address="AA:BB:CC:DD:EE:FF", name=None, rssi=None, transport="le")
    flags = [_flag("RACE_EXPOSED", "HIGH")]
    result = AssessmentResult(device=device, verdict="PARTIAL", flags=flags)

    print_assessment_result(result)

    output = capsys.readouterr().out
    assert "RACE_EXPOSED description" in output
    assert "instance(s)" not in output
