"""stdout formatting and JSON export for scan, probe, and assessment results."""

from __future__ import annotations

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


def print_assessment_result(
    result: AssessmentResult, firmware_version: str | None = None
) -> None:
    device = result.device
    print(f"Assessment for {device.address} ({device.name or 'unknown'})")
    print(f"  verdict: {result.verdict}")

    if device.matched_profile is not None:
        profile = device.matched_profile
        print(f"  known-affected: {profile.get('brand')} {profile.get('model')}")

    if firmware_version is not None:
        print(f"  buildversion: {firmware_version}")

    if not result.flags:
        print("  no findings")
        return

    print()
    for flag in result.flags:
        print(f"  [{flag.severity}] {flag.flag_id} ({flag.cve})")
        print(f"    {flag.description}")
        remediation = REMEDIATION.get(flag.flag_id)
        if remediation:
            print(f"    remediation: {remediation}")

    print()
    print(f"{len(result.flags)} finding(s)")


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
    result: AssessmentResult, firmware_version: str | None = None
) -> dict:
    device = result.device
    return {
        "address": device.address,
        "name": device.name,
        "transport": device.transport,
        "airoha_soc": device.airoha_soc,
        "matched_profile": device.matched_profile,
        "firmware_version": firmware_version,
        "verdict": result.verdict,
        "flags": [
            {
                "flag_id": flag.flag_id,
                "severity": flag.severity,
                "description": flag.description,
                "cve": flag.cve,
                "evidence": flag.evidence,
                "remediation": REMEDIATION.get(flag.flag_id),
            }
            for flag in result.flags
        ],
    }
