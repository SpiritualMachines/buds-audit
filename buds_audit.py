"""CLI entrypoint for the wireless earbud CVE assessment tool.

Orchestration only: argument parsing and wiring the async scan/fingerprint
calls together. Rule evaluation and reporting logic live in core/rules.py
and core/report.py so this file stays a thin driver.

core/gatt.py, core/race.py, core/impersonation.py, and core/scanner.py all
import bleak at module load time. Importing them here at the top would mean
`--help` itself needs bleak installed, which defeats the point of a help
menu - it should work from a bare `python3 buds_audit.py --help` with no venv,
no dependencies. Each is imported lazily, inside the function that actually
uses it, so only real Bluetooth operations require bleak to be importable.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from core.baseline import build_baseline, compute_drift, load_baselines, save_baselines
from core.fingerprint import (
    fingerprint_device,
    load_affected_devices,
    match_known_device,
)
from core.models import BtDevice, RuleFlag
from core.report import (
    assessment_to_dict,
    print_assessment_result,
    print_baseline_captured,
    print_firmware_results,
    print_gatt_results,
    print_impersonation_results,
    print_race_results,
    print_scan_results,
)
from core.rules import assess_device

AFFECTED_DEVICES_PATH = Path(__file__).parent / "data" / "affected_devices.json"
BASELINES_PATH = Path(__file__).parent / "data" / "device_baselines.json"
SCAN_TIMEOUT = 10.0


def build_parser() -> argparse.ArgumentParser:
    """Define the CLI surface. Each flag's `help` text is the source of
    truth for what it does - README.md's Usage section mirrors these in
    grouped, example-driven form for humans, but this is what `--help`
    actually shows."""
    parser = argparse.ArgumentParser(
        description="Wireless earbud CVE assessment tool (Airoha SDK chain)."
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Scan for nearby Bluetooth devices (BLE and Classic) and fingerprint them.",
    )
    parser.add_argument(
        "--target",
        metavar="ADDR",
        help="Restrict fingerprinting to a single device address, or the address for --gatt.",
    )
    parser.add_argument(
        "--gatt",
        action="store_true",
        help="Run an unauthenticated-access GATT probe against --target (CVE-2025-20700).",
    )
    parser.add_argument(
        "--race",
        action="store_true",
        help="Run a RACE-channel reachability probe against --target (CVE-2025-20702).",
    )
    parser.add_argument(
        "--firmware",
        action="store_true",
        help=(
            "Check firmware build version via RACE and cross-reference against "
            "known-patched builds for pairing-bypass assessment (CVE-2025-20701)."
        ),
    )
    parser.add_argument(
        "--assess",
        action="store_true",
        help=(
            "Run GATT, RACE, and firmware probes against --target together and "
            "produce one PASS/PARTIAL/VULNERABLE verdict."
        ),
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        help="With --assess, also write the assessment result to FILE as JSON.",
    )
    parser.add_argument(
        "--flags-only",
        action="store_true",
        help="With --scan, suppress devices with no known-affected catalog match.",
    )
    parser.add_argument(
        "--baseline",
        action="store_true",
        help=(
            "Capture (or overwrite) the trusted baseline for --target: "
            "identity, GATT table, firmware build, and bonding state."
        ),
    )
    parser.add_argument(
        "--check-drift",
        action="store_true",
        help="Compare --target against its stored baseline and flag any drift.",
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help=(
            "Continuously scan for advertisers broadcasting a duplicate "
            "identity (same name/manufacturer data, conflicting address) - "
            "impersonation/relay monitoring. Runs until interrupted (Ctrl+C)."
        ),
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Skip the ownership confirmation prompt before --gatt/--race/"
            "--firmware/--assess/--baseline/--check-drift. For scripted use "
            "only."
        ),
    )
    return parser


_OWNERSHIP_PROMPT = (
    "Confirm {target} is a device you own or have explicit authorisation "
    "to test [y/N]: "
)


def _confirm_authorized(target: str) -> bool:
    # Active probes connect to and send commands to the target; per this
    # project's scope, that must never happen against a device the operator
    # doesn't own or isn't authorised to test. A generic GATT/RACE probe has
    # no way to tell an earbud from a bystander's phone before connecting,
    # so the confirmation has to happen here, before any radio activity.
    # Plain blocking input() is fine here specifically because this runs
    # from main()'s synchronous flag-dispatch code, before asyncio.run()
    # starts a loop for the actual probe - see _async_input for why the
    # wizard can't do the same thing.
    response = input(_OWNERSHIP_PROMPT.format(target=target))
    return response.strip().lower() in ("y", "yes")


async def _async_input(prompt: str) -> str:
    """input() that doesn't block the asyncio event loop.

    bleak's BlueZ backend relies on the event loop continuously running to
    process D-Bus signals in real time, including PropertiesChanged for the
    adapter's own Powered state. Confirmed live: toggling Bluetooth off then
    back on while blocked on a plain input() call (e.g. the wizard sitting
    at its menu prompt) makes bleak permanently miss the "powered back on"
    signal - every scan after that keeps failing with "No powered Bluetooth
    adapters found" even though bluetoothctl itself correctly shows
    Powered: yes, and even long after the input() call returns. Running
    input() in a separate thread instead keeps the event loop free to
    process those signals while waiting on the user."""
    return await asyncio.to_thread(input, prompt)


async def _confirm_authorized_async(target: str) -> bool:
    """Wizard equivalent of _confirm_authorized - see _async_input for why
    the wizard can't use the plain blocking version."""
    response = await _async_input(_OWNERSHIP_PROMPT.format(target=target))
    return response.strip().lower() in ("y", "yes")


async def run_scan(target: str | None, flags_only: bool) -> None:
    """Passive discovery: scan, then fingerprint every result against the
    known-affected catalog. No ownership gate - this never connects to
    anything, it only listens to advertisements already broadcast publicly.
    `target` filters the printed results rather than restricting the scan
    itself, since BLE/Classic scanning can't be narrowed to one address up
    front."""
    from core.scanner import ScanError, scan_all

    try:
        devices = await scan_all(timeout=SCAN_TIMEOUT)
    except ScanError as exc:
        print(f"Scan failed: {exc}")
        return

    if target:
        devices = [d for d in devices if d.address.lower() == target.lower()]

    known_devices = load_affected_devices(AFFECTED_DEVICES_PATH)
    for device in devices:
        fingerprint_device(device, known_devices)

    print_scan_results(devices, flags_only=flags_only)


async def run_gatt(target: str) -> None:
    """Single-target CVE-2025-20700 probe. GattProbeError covers both
    "already paired" (finding would be meaningless) and any connection
    failure - printed as a skip, not a crash, since a device going out of
    range mid-probe is expected during live testing, not exceptional.
    no_pairing_agent guards the whole probe: a characteristic that requires
    encryption can otherwise make BlueZ silently route a real pairing
    prompt to the desktop's own agent - see core/agent.py."""
    from core.agent import AgentRegistrationError, no_pairing_agent
    from core.gatt import GattProbeError, probe_gatt

    try:
        async with no_pairing_agent():
            flags = await probe_gatt(target)
    except AgentRegistrationError as exc:
        print(f"GATT probe aborted: {exc}")
        return
    except GattProbeError as exc:
        print(f"GATT probe skipped: {exc}")
        return

    print_gatt_results(target, flags)


async def run_race(target: str) -> None:
    """Single-target CVE-2025-20702 probe. service_found and flags are
    reported separately (see print_race_results) rather than collapsed,
    since "no RACE service" and "RACE service present but unresponsive" are
    materially different findings, not the same result presented two ways.
    no_pairing_agent guards the whole probe - see run_gatt / core/agent.py."""
    from core.agent import AgentRegistrationError, no_pairing_agent
    from core.race import RaceProbeError, probe_race

    try:
        async with no_pairing_agent():
            service_found, flags = await probe_race(target)
    except AgentRegistrationError as exc:
        print(f"RACE probe aborted: {exc}")
        return
    except RaceProbeError as exc:
        print(f"RACE probe skipped: {exc}")
        return

    print_race_results(target, service_found, flags)


async def run_firmware(target: str) -> None:
    """Single-target CVE-2025-20701 probe (passive only - see ROADMAP.md's
    Hardware requirement note for why active pairing-bypass testing is out
    of scope here). matched_profile is looked up first so
    probe_firmware_version can cross-reference the retrieved build against
    that device's known-patched version, if the catalog has one.
    no_pairing_agent guards the whole probe - see run_gatt / core/agent.py."""
    from core.agent import AgentRegistrationError, no_pairing_agent
    from core.race import RaceProbeError, probe_firmware_version

    known_devices = load_affected_devices(AFFECTED_DEVICES_PATH)
    matched_profile = match_known_device(
        BtDevice(address=target, name=None, rssi=None, transport="le"), known_devices
    )

    try:
        async with no_pairing_agent():
            version, flags = await probe_firmware_version(target, matched_profile)
    except AgentRegistrationError as exc:
        print(f"Firmware check aborted: {exc}")
        return
    except RaceProbeError as exc:
        print(f"Firmware check skipped: {exc}")
        return

    print_firmware_results(target, version, flags)


async def run_assess(target: str, json_path: str | None) -> None:
    """Run all three probes against one target and roll the results into a
    single verdict. is_paired is checked once up front as a fast skip
    before running anything; each probe still catches its own
    GattProbeError/RaceProbeError independently afterwards rather than
    letting one failure abort the whole assessment, so e.g. a RACE
    connection timeout still leaves the GATT findings intact in the final
    verdict instead of losing them. All three probes share a single
    no_pairing_agent registration rather than one each, so the reject-all
    agent stays in place continuously across the whole assessment instead
    of leaving gaps between probes - see run_gatt / core/agent.py."""
    from core.agent import AgentRegistrationError, no_pairing_agent
    from core.gatt import GattProbeError, is_paired, probe_gatt
    from core.race import RaceProbeError, probe_firmware_version, probe_race

    if await is_paired(target):
        print(
            f"Assessment skipped: {target} is already paired; findings would be "
            "meaningless against an already-bonded device"
        )
        return

    known_devices = load_affected_devices(AFFECTED_DEVICES_PATH)
    matched_profile = match_known_device(
        BtDevice(address=target, name=None, rssi=None, transport="le"), known_devices
    )

    flags: list[RuleFlag] = []
    version: str | None = None

    try:
        async with no_pairing_agent():
            try:
                flags.extend(await probe_gatt(target))
            except GattProbeError as exc:
                print(f"GATT probe skipped: {exc}")

            try:
                _, race_flags = await probe_race(target)
                flags.extend(race_flags)
            except RaceProbeError as exc:
                print(f"RACE probe skipped: {exc}")

            try:
                version, firmware_flags = await probe_firmware_version(
                    target, matched_profile
                )
                flags.extend(firmware_flags)
            except RaceProbeError as exc:
                print(f"Firmware check skipped: {exc}")
    except AgentRegistrationError as exc:
        print(f"Assessment aborted: {exc}")
        return

    device = BtDevice(address=target, name=None, rssi=None, transport="le")
    device.matched_profile = matched_profile
    if matched_profile:
        device.airoha_soc = matched_profile.get("airoha_soc")

    result = assess_device(device, flags)

    print()
    print_assessment_result(result, firmware_version=version)

    if json_path:
        with open(json_path, "w") as f:
            json.dump(assessment_to_dict(result, firmware_version=version), f, indent=2)
        print(f"\nWrote assessment to {json_path}")


async def _capture_snapshot(target: str) -> dict:
    """Shared snapshot-building routine behind both --baseline and
    --check-drift, so the two can never drift apart in what they capture.
    matched_profile=None on the firmware call is deliberate: this only
    wants the raw build version for the snapshot, not a pairing-bypass
    verdict against a catalog entry - that evaluation belongs to
    --firmware/--assess, not baseline capture. no_pairing_agent guards the
    connecting calls (enumerate_gatt_table, probe_firmware_version) - see
    run_gatt / core/agent.py."""
    from core.agent import no_pairing_agent
    from core.gatt import enumerate_gatt_table, get_bonding_state
    from core.race import probe_firmware_version
    from core.scanner import scan_ble

    scanned = await scan_ble(timeout=SCAN_TIMEOUT)
    current = next((d for d in scanned if d.address.lower() == target.lower()), None)
    name = current.name if current else None
    manufacturer_data = current.manufacturer_data if current else {}

    async with no_pairing_agent():
        gatt_table = await enumerate_gatt_table(target)
        version, _ = await probe_firmware_version(target, matched_profile=None)

    bonding_state = await get_bonding_state(target)

    return build_baseline(name, manufacturer_data, gatt_table, version, bonding_state)


async def run_baseline(target: str) -> None:
    """Capture (or silently overwrite) the trusted baseline. No prompt on
    overwrite - re-running --baseline is how a user tells the tool "trust
    the device's current state," so overwriting is the expected behaviour,
    not a destructive surprise."""
    from core.agent import AgentRegistrationError
    from core.gatt import GattProbeError
    from core.race import RaceProbeError
    from core.scanner import ScanError

    try:
        baseline = await _capture_snapshot(target)
    except (GattProbeError, RaceProbeError, AgentRegistrationError, ScanError) as exc:
        print(f"Baseline capture skipped: {exc}")
        return

    baselines = load_baselines(BASELINES_PATH)
    baselines[target.upper()] = baseline
    save_baselines(BASELINES_PATH, baselines)

    print_baseline_captured(target, baseline)


async def run_check_drift(target: str) -> None:
    """Re-capture the same snapshot shape as --baseline and diff it.
    evaluate_verdict elevates any drift flag straight to
    SUSPECTED_COMPROMISE (see core/rules.py), superseding whatever the
    device's static VULNERABLE/PARTIAL status would otherwise be - drift
    is about "did something change," not "is this exploitable"."""
    from core.agent import AgentRegistrationError
    from core.gatt import GattProbeError
    from core.race import RaceProbeError
    from core.scanner import ScanError

    baselines = load_baselines(BASELINES_PATH)
    baseline = baselines.get(target.upper())
    if baseline is None:
        print(f"No baseline found for {target}. Capture one first with --baseline.")
        return

    try:
        current = await _capture_snapshot(target)
    except (GattProbeError, RaceProbeError, AgentRegistrationError, ScanError) as exc:
        print(f"Drift check skipped: {exc}")
        return

    flags = compute_drift(baseline, current)
    device = BtDevice(
        address=target, name=current.get("name"), rssi=None, transport="le"
    )
    result = assess_device(device, flags)

    print()
    print_assessment_result(result)


async def run_watch(window: float) -> None:
    """Loop indefinitely in fixed-length windows until interrupted. There's
    no other stop condition by design - this is a monitoring mode, not a
    one-shot check. Ctrl+C is handled by the caller (main()), not here:
    asyncio.run() converts SIGINT into a CancelledError raised inside the
    running coroutine first, only re-raising KeyboardInterrupt in the
    synchronous caller afterward - confirmed live (Python 3.14), a
    try/except KeyboardInterrupt inside this coroutine never actually
    catches it."""
    from core.impersonation import collect_advertisements, detect_duplicate_identities
    from core.scanner import ScanError

    print(
        f"Watching for duplicate concurrent identities ({window:.0f}s windows, Ctrl+C to stop)..."
    )
    while True:
        try:
            samples = await collect_advertisements(window)
        except ScanError as exc:
            print(f"Watch stopped: {exc}")
            return
        flags = detect_duplicate_identities(samples)
        print_impersonation_results(flags)


async def _prompt_choice(count: int) -> int | None:
    """Ask for one of `count` numbered options (1-indexed). Returns the
    chosen 0-indexed position, or None if the user backed out with 0.
    Async (uses _async_input) since this runs mid-wizard-session, unlike
    the flag-based interface's one-shot confirmation prompt."""
    while True:
        choice = (
            await _async_input(f"Which one? (1-{count}, or 0 to cancel): ")
        ).strip()
        if choice == "0":
            return None
        if choice.isdigit() and 1 <= int(choice) <= count:
            return int(choice) - 1
        print("Please enter a valid number.")


async def _wizard_pick_target() -> str | None:
    """Scan for nearby devices and let the user pick a known-affected match
    by number, so the wizard never requires already knowing a BLE address.
    Restricted to confirmed catalog matches, same as --scan --flags-only -
    keeps the wizard's picker simple rather than also surfacing "unconfirmed
    Airoha ID" hits that would need more explaining."""
    from core.scanner import ScanError, scan_all

    print(f"\nScanning for nearby devices ({int(SCAN_TIMEOUT)}s)...")
    try:
        devices = await scan_all(timeout=SCAN_TIMEOUT)
    except ScanError as exc:
        print(f"\nScan failed: {exc}")
        return None

    known_devices = load_affected_devices(AFFECTED_DEVICES_PATH)
    for device in devices:
        fingerprint_device(device, known_devices)

    matches = [d for d in devices if d.matched_profile is not None]

    if not matches:
        print(
            "\nNo known-affected devices found nearby. Make sure the "
            "earbuds are powered on and close by, then try again."
        )
        return None

    print(f"\nFound {len(matches)} known-affected device(s):")
    for i, device in enumerate(matches, start=1):
        profile = device.matched_profile
        print(
            f"  {i}) {profile.get('brand')} {profile.get('model')} - {device.address}"
        )

    if len(matches) == 1:
        return matches[0].address

    index = await _prompt_choice(len(matches))
    return None if index is None else matches[index].address


async def _wizard_pick_baseline() -> str | None:
    """List devices with a saved baseline and let the user pick one by
    number, so option 2 never requires already knowing a BLE address."""
    baselines = load_baselines(BASELINES_PATH)
    if not baselines:
        print("\nNo saved baseline yet. Choose option 1 first to create one.")
        return None

    entries = list(baselines.items())
    print("\nSaved baseline(s):")
    for i, (address, baseline) in enumerate(entries, start=1):
        print(f"  {i}) {baseline.get('name') or 'unknown'} - {address}")

    if len(entries) == 1:
        return entries[0][0]

    index = await _prompt_choice(len(entries))
    return None if index is None else entries[index][0]


async def _wizard_full_analysis() -> None:
    target = await _wizard_pick_target()
    if target is None:
        return

    if not await _confirm_authorized_async(target):
        print("Cancelled: ownership not confirmed.")
        return

    print("\nRunning the full vulnerability audit (GATT, RACE, firmware)...")
    await run_assess(target, json_path=None)

    print("\nSaving a baseline so future runs can detect changes...")
    await run_baseline(target)


async def _wizard_check_drift() -> None:
    target = await _wizard_pick_baseline()
    if target is None:
        return

    if not await _confirm_authorized_async(target):
        print("Cancelled: ownership not confirmed.")
        return

    await run_check_drift(target)


def _print_wizard_menu() -> None:
    print()
    print("buds-audit - interactive mode")
    print("1) Full analysis (scan, run the full CVE audit, and save a baseline)")
    print("2) Check current state against a saved baseline")
    print("3) Scan for spoofed/impersonating devices")
    print("4) Exit")


async def run_wizard() -> None:
    """No-args entry point: a numbered menu instead of requiring flags and
    an already-known BLE address, for anyone not already comfortable with a
    CLI. Each option is a thin wrapper around the same run_* functions the
    flag-based interface uses, so there's no separate logic path to keep in
    sync. A Ctrl+C during option 3's continuous watch exits the whole
    wizard rather than trying to recover mid-loop and return to this menu -
    same behaviour as --watch standalone, handled by the try/except around
    asyncio.run(run_wizard()) in main(). Uses _async_input rather than
    plain input() for the same reason every other wizard prompt does -
    see _async_input's docstring."""
    while True:
        _print_wizard_menu()
        choice = (await _async_input("Choose an option: ")).strip()

        if choice == "1":
            await _wizard_full_analysis()
        elif choice == "2":
            await _wizard_check_drift()
        elif choice == "3":
            print("\nListening for spoofed/duplicate devices. Press Ctrl+C to stop.")
            await run_watch(SCAN_TIMEOUT)
        elif choice == "4":
            return
        else:
            print("Please enter 1, 2, 3, or 4.")


def main() -> None:
    if len(sys.argv) == 1:
        try:
            asyncio.run(run_wizard())
        except (KeyboardInterrupt, EOFError):
            print("\nStopped.")
        return

    # Each active-probe branch below repeats the same three steps: require
    # --target, run the ownership-confirmation gate unless --yes, then
    # asyncio.run() the matching run_* function. Deliberately not factored
    # into a helper - it keeps each probe's requirements (target-required,
    # gated) visible at the call site, and a new probe flag should follow
    # the same three steps rather than a shared abstraction. --scan and
    # --watch skip the gate entirely since they never connect to anything.
    parser = build_parser()
    args = parser.parse_args()

    if args.gatt:
        if not args.target:
            parser.error("--gatt requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_gatt(args.target))
        return

    if args.race:
        if not args.target:
            parser.error("--race requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_race(args.target))
        return

    if args.firmware:
        if not args.target:
            parser.error("--firmware requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_firmware(args.target))
        return

    if args.assess:
        if not args.target:
            parser.error("--assess requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_assess(args.target, args.json))
        return

    if args.baseline:
        if not args.target:
            parser.error("--baseline requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_baseline(args.target))
        return

    if args.check_drift:
        if not args.target:
            parser.error("--check-drift requires --target ADDR")
        if not args.yes and not _confirm_authorized(args.target):
            print("Aborted: ownership not confirmed.")
            return
        asyncio.run(run_check_drift(args.target))
        return

    if args.watch:
        try:
            asyncio.run(run_watch(SCAN_TIMEOUT))
        except KeyboardInterrupt:
            print("\nStopped.")
        return

    if args.json:
        parser.error("--json requires --assess")

    if not args.scan:
        parser.print_help()
        return

    asyncio.run(run_scan(args.target, args.flags_only))


if __name__ == "__main__":
    main()
