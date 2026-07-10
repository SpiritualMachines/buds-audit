"""stdout formatting and JSON export for scan, probe, and assessment results."""

from __future__ import annotations

import textwrap

from core.models import AssessmentResult, BtDevice, RuleFlag

# Remediation guidance per flag_id.
REMEDIATION = {
    "GATT_UNAUTHENTICATED_ACCESS": (
        "Update to the latest firmware if a vendor patch exists. Until "
        "patched, avoid using or leaving the device paired in untrusted "
        "proximity to unknown BLE scanners."
    ),
    "RACE_EXPOSED": (
        "The RACE debug channel is reachable without pairing. Update "
        "firmware if a patch is available; there is no user-side mitigation "
        "beyond a vendor fix."
    ),
    "RACE_MEMORY_READ_CONFIRMED": (
        "The RACE debug channel returned real device flash content without "
        "pairing - confirmed arbitrary memory disclosure, not just channel "
        "reachability. Update firmware if a patch is available; there is no "
        "user-side mitigation beyond a vendor fix."
    ),
    "CLASSIC_PAIRING_BYPASS_UNPATCHED": (
        "Update to a patched firmware build if available. Treat Bluetooth "
        "Classic pairing prompts you did not initiate as a compromise "
        "indicator."
    ),
    "CLASSIC_PAIRING_BYPASS_UNKNOWN": (
        "Firmware build could not be verified. Check the vendor's advisory "
        "page for a patched release and treat the device as unpatched until "
        "confirmed."
    ),
    "IDENTITY_DRIFT": (
        "This device's name or manufacturer data changed since your last "
        "trusted baseline. If you didn't reconfigure or replace the device, "
        "treat this as possible impersonation or a spoofed replacement and "
        "re-verify its identity before pairing again."
    ),
    "GATT_TABLE_DRIFT": (
        "This device's GATT service/characteristic table changed since your "
        "last trusted baseline. This can follow a legitimate firmware "
        "update, but can also indicate a RACE-driven configuration write. "
        "Only re-baseline after confirming the change was expected."
    ),
    "FIRMWARE_DOWNGRADE": (
        "This device's firmware build differs from your last trusted "
        "baseline. If you didn't perform this update yourself, treat it as "
        "a possible rollback preceding a pairing-bypass attack."
    ),
    "BOND_STATE_DRIFT": (
        "This device's local bonding record (paired/trusted/bonded) changed "
        "without you re-pairing it yourself. Treat this as a possible "
        "silent pairing completion; consider removing and re-pairing the "
        "device after verifying its identity."
    ),
    "POSSIBLE_IMPERSONATION": (
        "A second address is broadcasting the same name and manufacturer "
        "data as a device already in range. Do not pair with either address "
        "until you can confirm which one is your real device - check it is "
        "physically present and in range, and treat any unexpected pairing "
        "request as a compromise indicator."
    ),
}

# Plain-language interpretation of the overall verdict, printed right under it
# so the bottom line ("what does this mean for me") reaches a non-expert
# before the technical findings do. This tool is meant to let the public
# check their own devices, not just security specialists - see core/rules.py
# for how each verdict is decided. Wording is deliberately neither alarmist
# nor falsely reassuring: it says what was observed and what to do, without
# implying an attack this tool did not actually confirm.
VERDICT_EXPLANATION = {
    "PASS": (
        "No issues found. This device is not on the known-affected list and "
        "did not respond to any of the unauthenticated checks this tool runs. "
        "Nothing further is needed."
    ),
    "PARTIAL": (
        "Some exposure worth knowing about, but no active attack was "
        "confirmed. Usually this means the device is a known-vulnerable model "
        "and/or answered requests it ideally should not have from an unpaired "
        "scanner like this one. The main defense is a manufacturer firmware "
        "update, if one exists. See the findings and their remediation notes "
        "below."
    ),
    "VULNERABLE": (
        "This device has a high-severity exposure a nearby attacker could "
        "realistically use. The most important step is to install any "
        "firmware update the manufacturer has released; if there is none, be "
        "cautious about using the device around untrusted people or unknown "
        "Bluetooth devices. See the findings below."
    ),
    "SUSPECTED_COMPROMISE": (
        "Something about this device changed in a way that can indicate "
        "tampering or impersonation since your last trusted scan. This does "
        "not prove an attack, but it is worth taking seriously - confirm the "
        "device is really yours and physically present before trusting it "
        "again. See the findings below."
    ),
}

# One-sentence plain-language gloss per flag_id, printed alongside the
# technical finding. Same tone rule as VERDICT_EXPLANATION above: describe
# what happened and why it matters in everyday terms, without overstating it.
PLAIN_LANGUAGE = {
    "GATT_UNAUTHENTICATED_ACCESS": (
        "This device handed data to this scanner without any pairing or "
        "approval. On its own that is an information exposure, not a takeover "
        "- but it is the kind of open access the Airoha attacks build on."
    ),
    "RACE_EXPOSED": (
        "A hidden manufacturer debug channel answered commands from an "
        "unpaired scanner. That channel is what these CVEs abuse - it should "
        "not be reachable without pairing."
    ),
    "RACE_MEMORY_READ_CONFIRMED": (
        "This scanner read raw memory off the device without pairing. That is "
        "direct proof of the memory-disclosure vulnerability, not just a "
        "reachable channel."
    ),
    "CLASSIC_PAIRING_BYPASS_UNPATCHED": (
        "This device's firmware is old enough to be vulnerable to a Bluetooth "
        "pairing bypass, where an attacker pairs with it without your "
        "approval."
    ),
    "CLASSIC_PAIRING_BYPASS_UNKNOWN": (
        "This is a known-affected model, but the tool could not read its "
        "firmware version to tell whether it has been patched. Treat it as "
        "unpatched until you can confirm otherwise."
    ),
    "IDENTITY_DRIFT": (
        "This device is advertising a different name or maker info than the "
        "last time you scanned it. If you did not change anything, it could "
        "be a different device posing as yours."
    ),
    "GATT_TABLE_DRIFT": (
        "The internal layout of this device changed since your last trusted "
        "scan. That can simply be a firmware update - or a sign something "
        "reconfigured it."
    ),
    "FIRMWARE_DOWNGRADE": (
        "This device's firmware version went backwards since your last scan. "
        "A downgrade can be a setup step for an attack."
    ),
    "BOND_STATE_DRIFT": (
        "This device's pairing record changed without you re-pairing it, "
        "which can indicate a silent, unauthorized pairing."
    ),
    "POSSIBLE_IMPERSONATION": (
        "Two devices in range are broadcasting the same identity. One may be "
        "impersonating your real device - do not pair until you know which is "
        "which."
    ),
}

_WRAP_WIDTH = 78


def _print_labeled(label: str, text: str, indent: str = "    ") -> None:
    """Print a labeled guidance paragraph wrapped with a hanging indent, so
    the distilled non-technical text (verdict interpretation, per-finding
    plain-language, remediation) stays readable in a terminal instead of
    soft-wrapping back to the left margin mid-sentence."""
    print(
        textwrap.fill(
            f"{label}{text}",
            width=_WRAP_WIDTH,
            initial_indent=indent,
            subsequent_indent=indent,
        )
    )


def print_scan_results(devices: list[BtDevice], flags_only: bool = False) -> None:
    matched_count = 0

    for device in devices:
        if device.matched_profile is not None:
            matched_count += 1
        elif flags_only:
            continue

        name = device.name or "unknown"
        rssi = device.rssi if device.rssi is not None else "n/a"
        chipset = device.airoha_soc or "none detected"

        print(
            f"[{device.transport.upper()}] {device.address}  "
            f"name={name}  rssi={rssi}  chipset={chipset}"
        )

        if device.matched_profile is not None:
            profile = device.matched_profile
            cves = ", ".join(profile.get("cves", []))
            print(
                f"    -> matches known-affected device: "
                f"{profile.get('brand')} {profile.get('model')} (CVEs: {cves})"
            )

    print()
    print(
        f"{len(devices)} device(s) scanned, {matched_count} matched known-affected profile(s)"
    )


def print_gatt_results(address: str, flags: list[RuleFlag]) -> None:
    print(f"GATT probe results for {address}")

    if not flags:
        print("  no unauthenticated access detected")
        return

    for flag in flags:
        evidence = flag.evidence
        print(
            f"  [{flag.severity}] {flag.flag_id} ({flag.cve}) - "
            f"unpaired {evidence.get('access')} succeeded on characteristic "
            f"{evidence.get('characteristic_uuid')} (service {evidence.get('service_uuid')})"
        )
        value_hex = evidence.get("value_hex")
        if value_hex:
            print(f"    value: {value_hex}")

    print()
    print(f"{len(flags)} unauthenticated-access finding(s)")


def print_race_results(
    address: str, service_found: bool, flags: list[RuleFlag]
) -> None:
    print(f"RACE probe results for {address}")

    if not service_found:
        print("  no known RACE service (Airoha/Sony GATT UUIDs) detected")
        return

    if not flags:
        print(
            "  RACE service present but did not respond to an unauthenticated command"
        )
        return

    for flag in flags:
        evidence = flag.evidence
        print(
            f"  [{flag.severity}] {flag.flag_id} ({flag.cve}) - "
            f"{evidence.get('vendor')} RACE channel responded unpaired "
            f"(service {evidence.get('service_uuid')})"
        )

    print()
    print(f"{len(flags)} RACE-reachability finding(s)")


def print_memory_read_results(
    address: str, service_found: bool, flags: list[RuleFlag], note: str | None = None
) -> None:
    print(f"RACE memory-read results for {address}")

    if not service_found:
        print("  no known RACE service (Airoha/Sony GATT UUIDs) detected")
        return

    if not flags:
        print(f"  no memory disclosed - {note or 'no further detail available'}")
        return

    for flag in flags:
        print(f"  [{flag.severity}] {flag.flag_id} ({flag.cve})")
        print(f"    {flag.description}")
        print(f"    sample (first 16 bytes): {flag.evidence.get('sample_hex')}")

    print()
    print(f"{len(flags)} memory-disclosure finding(s)")


def print_bd_address_results(
    address: str, service_found: bool, bd_address: str | None, note: str | None = None
) -> None:
    print(f"RACE BD-address query results for {address}")

    if not service_found:
        print("  no known RACE service (Airoha/Sony GATT UUIDs) detected")
        return

    if bd_address is None:
        print(f"  no BD address retrieved - {note or 'no further detail available'}")
        return

    print(f"  Classic (BR/EDR) BD address: {bd_address}")


def print_firmware_results(
    address: str, version: str | None, flags: list[RuleFlag]
) -> None:
    print(f"Firmware check results for {address}")
    print(f"  buildversion: {version if version is not None else 'unavailable'}")

    if not flags:
        print("  no pairing-bypass firmware flag raised")
        return

    for flag in flags:
        print(f"  [{flag.severity}] {flag.flag_id} ({flag.cve}) - {flag.description}")

    print()
    print(f"{len(flags)} pairing-bypass finding(s)")


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _group_flags_by_severity(flags: list[RuleFlag]) -> list[list[RuleFlag]]:
    """Group flags by flag_id (preserving each group's original relative
    order), then order the groups by descending severity so the most
    important findings surface first - a device with many near-identical
    MEDIUM GATT_UNAUTHENTICATED_ACCESS findings (one per exposed
    characteristic) and a single HIGH finding should show the HIGH finding
    first, not bury it at the bottom of a long repeated list."""
    groups: dict[str, list[RuleFlag]] = {}
    for flag in flags:
        groups.setdefault(flag.flag_id, []).append(flag)

    return sorted(
        groups.values(), key=lambda group: _SEVERITY_ORDER.get(group[0].severity, 99)
    )


def _print_flag_group(group: list[RuleFlag]) -> None:
    sample = group[0]
    count_label = f" - {len(group)} instance(s)" if len(group) > 1 else ""
    print(f"  [{sample.severity}] {sample.flag_id} ({sample.cve}){count_label}")

    plain = PLAIN_LANGUAGE.get(sample.flag_id)
    if plain:
        _print_labeled("In plain terms: ", plain)

    if len(group) == 1:
        print(f"    {sample.description}")
        value_hex = sample.evidence.get("value_hex") or sample.evidence.get(
            "sample_hex"
        )
        if value_hex:
            print(f"    value: {value_hex}")
    else:
        # Repeating the same boilerplate description/remediation once per
        # instance drowns out everything else on a device with many exposed
        # characteristics (seen live: 15+ near-identical
        # GATT_UNAUTHENTICATED_ACCESS blocks) - print the shared context
        # once (description implied by the header, remediation below), then
        # one compact line per instance instead.
        for flag in group:
            evidence = flag.evidence
            line = (
                f"    - {evidence.get('access', '?')}: "
                f"{evidence.get('characteristic_uuid', '?')} "
                f"(service {evidence.get('service_uuid', '?')})"
            )
            value_hex = evidence.get("value_hex")
            if value_hex:
                line += f", value={value_hex}"
            print(line)

    remediation = REMEDIATION.get(sample.flag_id)
    if remediation:
        _print_labeled("remediation: ", remediation)


def print_assessment_result(
    result: AssessmentResult,
    firmware_version: str | None = None,
    bd_address: str | None = None,
) -> None:
    device = result.device
    print(f"Assessment for {device.address} ({device.name or 'unknown'})")
    print(f"  verdict: {result.verdict}")

    if device.matched_profile is not None:
        profile = device.matched_profile
        print(f"  known-affected: {profile.get('brand')} {profile.get('model')}")

    if firmware_version is not None:
        print(f"  buildversion: {firmware_version}")

    if bd_address is not None:
        print(f"  BD address (Classic): {bd_address}")

    explanation = VERDICT_EXPLANATION.get(result.verdict)
    if explanation:
        print()
        _print_labeled("What this means: ", explanation, indent="  ")

    if not result.flags:
        print("  no findings")
        return

    groups = _group_flags_by_severity(result.flags)
    summary = ", ".join(
        f"{len(group)} {group[0].flag_id} ({group[0].severity})" for group in groups
    )
    print()
    print(f"  {len(result.flags)} finding(s): {summary}")

    for group in groups:
        print()
        _print_flag_group(group)


def print_impersonation_results(flags: list[RuleFlag]) -> None:
    if not flags:
        print("  no duplicate concurrent identities detected")
        return

    for flag in flags:
        print(f"  [{flag.severity}] {flag.flag_id} - {flag.description}")
        remediation = REMEDIATION.get(flag.flag_id)
        if remediation:
            print(f"    remediation: {remediation}")


def print_baseline_captured(address: str, baseline: dict) -> None:
    print(f"Baseline captured for {address}")
    print(f"  name: {baseline.get('name') or 'unknown'}")
    print(f"  gatt characteristics: {len(baseline.get('gatt_table', []))}")
    print(f"  firmware build: {baseline.get('firmware_version') or 'unavailable'}")
    print(f"  bonding state: {baseline.get('bonding_state')}")


def assessment_to_dict(
    result: AssessmentResult,
    firmware_version: str | None = None,
    bd_address: str | None = None,
) -> dict:
    device = result.device
    return {
        "address": device.address,
        "name": device.name,
        "transport": device.transport,
        "airoha_soc": device.airoha_soc,
        "matched_profile": device.matched_profile,
        "firmware_version": firmware_version,
        "bd_address": bd_address,
        "verdict": result.verdict,
        "verdict_explanation": VERDICT_EXPLANATION.get(result.verdict),
        "flags": [
            {
                "flag_id": flag.flag_id,
                "severity": flag.severity,
                "description": flag.description,
                "cve": flag.cve,
                "evidence": flag.evidence,
                "remediation": REMEDIATION.get(flag.flag_id),
                "plain_language": PLAIN_LANGUAGE.get(flag.flag_id),
            }
            for flag in result.flags
        ],
    }
