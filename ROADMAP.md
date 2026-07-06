# buds-audit — Roadmap

Bluetooth earbud security assessment tool targeting the Airoha SDK vulnerability
chain (CVE-2025-20700 / 20701 / 20702). Modelled on the Janus USB assessment
approach: enumerate, probe, rule-check, report verdict per device.

Research basis: ERNW disclosure by Dennis Heinze and Frieder Steinmetz.
RACE toolkit published by ERNW as reference implementation: https://github.com/auracast-research/race-toolkit

### Prior Art and Gap

The ERNW RACE toolkit includes a `check` command covering all three CVEs. It is
not a replacement for this tool because:

- Requires a Bumble-compatible USB Bluetooth dongle (external hardware)
- Requires stopping the system Bluetooth daemon (`systemctl stop bluetooth`)
- Interactive wizard — not scriptable or report-friendly
- CVE-2025-20701 (Classic pairing bypass) is noted as unreliable even with the dongle
- FOTA support explicitly does not work on TWS earbuds — only over-ear headphones

This tool fills the gap: BLE-only checks via `bleak` through the OS stack (BlueZ),
no dongle required, non-interactive, clean per-device verdict output.

---

## Methodology

### Threat Model

The Airoha SDK shipped the RACE configuration protocol — originally a USB
developer tool — exposed unauthenticated over both BLE and Bluetooth Classic.
Combined with missing pairing enforcement, an attacker within Bluetooth range
can:

1. Enumerate GATT services without pairing (CVE-2025-20700)
2. Complete a Classic pairing handshake silently (CVE-2025-20701)
3. Read/write device RAM and flash via RACE (CVE-2025-20702)
4. Extract Bluetooth Link Keys from RAM dump
5. Impersonate the headphones to the victim's phone

This tool assesses exposure at each step without performing the full attack
chain. It is designed for owner-assessment and authorised testing only.

### Assessment Layers

| Layer | Method | CVE |
|-------|--------|-----|
| Fingerprint | BLE advertisement + manufacturer data parsing | — |
| GATT exposure | Enumerate services/characteristics, then attempt an unpaired read/notify-subscribe | CVE-2025-20700 |
| RACE reachability | Probe for RACE service UUID over BLE | CVE-2025-20702 |
| Pairing enforcement | Test Classic pairing consent enforcement | CVE-2025-20701 |
| Baseline drift | Compare current fingerprint/GATT table/firmware against a stored trusted baseline | compromise heuristic |
| Impersonation | Detect concurrent duplicate-identity advertisers during a scan window | compromise heuristic (Step 5) |

Passive fingerprinting is non-invasive. GATT exposure testing is not: BLE has
no over-the-air signal for "this characteristic requires pairing" — declared
properties (read/write/notify/etc.) only advertise capability. BlueZ only
reports encrypt-*/authorize permission flags for its own local GATT server,
never for a remote peripheral being discovered as a client. The only way to
know whether a characteristic actually enforces authentication is to attempt
the operation and see whether it succeeds or is rejected. So GATT assessment
does real (unpaired) reads and real notify-subscribe/unsubscribe cycles —
never a Write, since that risks changing device state and is deliberately
left to the RACE reachability probe below, which is scoped to reachability
only. Before and after each attempt, device bonding state is independently
verified via `bluetoothctl info <addr>` (not trusted from bleak's own state)
to confirm no silent pairing occurred during the probe.

RACE probing sends an unauthenticated connect + service discovery only — no
memory reads.

CVE-2025-20701 requires raw Bluetooth Classic HCI access, which means taking
exclusive control of the radio via Bumble — not possible through BlueZ without
a dedicated dongle. This check is out of scope for the no-dongle path. Devices
are flagged for CVE-2025-20701 based on firmware version data where available,
otherwise reported as untestable without external hardware.

### Affected Device Identification

Airoha chipsets are identified by:
- Bluetooth Company ID `0x05D6` (Airoha Technology Corp) in manufacturer data
- Known GATT service UUIDs from the RACE SDK
- A curated `data/affected_devices.json` keyed by device name / BT address prefix

Known affected brands: Sony, Bose, Jabra, JBL, Marshall, Beats (pre-patch),
and others using Airoha AB1562/AB1565/AB1568-series SoCs.

Confirmed affected (verified against a physical unit): Sony WF-1000XM3.

### Compromise Assessment: Vulnerable vs. Exploited

Vulnerability assessment (Phases 1-4) answers "can this device be attacked."
It cannot answer "has this device already been attacked" — that requires
evidence of what already happened, not just what's possible. True forensic
confirmation would mean reading device RAM/flash via RACE, which is the
attack itself (CVE-2025-20702) and stays out of scope (see Out of Scope).
This tool does not invasively read the earbuds to look for prior tampering.

Instead, compromise assessment is heuristic and drift-based: capture a
trusted baseline the first time a device is assessed, then flag deviations
on later runs that correlate with the known attack chain. This produces a
"suspected compromise" signal, not forensic proof.

Indicators tracked:

| Indicator | What it detects | Maps to |
|-----------|------------------|---------|
| Identity drift | Name/manufacturer data changed for a previously-baselined address | Step 5 impersonation, or a spoofed re-pair |
| GATT table drift | Service/characteristic set differs from the stored baseline | RACE-driven config write (CVE-2025-20702) |
| Firmware downgrade | Reported version is lower than the previously recorded one | Rollback preceding a pairing-bypass attack (CVE-2025-20701) |
| Bond state drift | Local BlueZ bonding record (Paired/Trusted/LinkKey presence) changed without a user-initiated re-pair | Silent pairing completion (CVE-2025-20701) |
| Duplicate concurrent identity | Two simultaneous advertisers with matching name/manufacturer data but conflicting address/RSSI | Active impersonation or relay (Step 5) |

Baselines and bond-state checks never store key material (LinkKey/IRK
values) — only presence/absence and metadata. The assessment tool must not
itself become a source of key leakage.

---

## Phase 1 — Discovery and Fingerprinting
**Target: 2026-07-XX**

- [x] BLE advertisement scanning via `bleak`
- [x] Parse manufacturer data: extract Company ID, model hints
- [x] Bluetooth Classic discovery via `hcitool scan` / BlueZ D-Bus
- [x] Match against `data/affected_devices.json` (known Airoha models + address prefixes)
- [x] Data models: `BtDevice`, `RuleFlag`, `AssessmentResult`
- [x] CLI entrypoint `buds_audit.py` with `--scan` and `--target ADDR` flags
- [x] Basic stdout output: address, name, manufacturer, chipset match verdict

## Phase 2 — GATT Enumeration (CVE-2025-20700)
**Target: 2026-07-XX**

- [x] Connect to target device over BLE without prior pairing
- [x] Enumerate all GATT services and characteristics
- [x] For each Read-capable characteristic, attempt an actual unpaired read
- [x] For each Notify/Indicate-capable characteristic, attempt subscribe then
      immediately unsubscribe (never Write — that's left to the RACE probe)
- [x] Verify bonding state via `bluetoothctl info <addr>` before and after
      each attempt, independent of bleak's own state, to confirm no silent
      pairing occurred
- [x] Skip probing entirely if the device is already paired when the probe
      starts — an "unauthenticated access" finding is meaningless against an
      already-bonded device
- [x] Flag `GATT_UNAUTHENTICATED_ACCESS` (service UUID, characteristic UUID,
      access type, property list) for each read/subscribe that succeeds
      without pairing
- [x] `--gatt` flag (requires `--target ADDR`) to run the probe against a
      specific address

## Phase 3 — RACE Protocol Reachability (CVE-2025-20702)
**Target: 2026-07-XX**

- [x] Implement minimal RACE client based on ERNW published protocol spec
- [x] Attempt unauthenticated RACE channel open over BLE
- [x] Do not perform memory reads — reachability probe only
- [x] Flag `RACE_EXPOSED` (HIGH) if channel opens without authentication challenge
- [x] Flag `RACE_NOT_REACHABLE` (PASS) if connection refused or service absent
- [x] Document RACE UUID and characteristic structure in `core/race.py`

## Phase 4 — Pairing Enforcement (CVE-2025-20701)
**Target: 2026-07-XX**

Active testing of CVE-2025-20701 requires raw HCI access via Bumble and a
dedicated Bluetooth dongle — not achievable through BlueZ. This phase covers
passive assessment only.

- [x] Check firmware version via RACE `buildversion` command (if device responds)
- [x] Cross-reference against known-patched firmware version table in `data/affected_devices.json`
- [x] Flag `CLASSIC_PAIRING_BYPASS_UNPATCHED` (HIGH) if firmware does not exactly
      match the known-patched build (RACE buildversion strings are opaque
      vendor build identifiers, not semver - ERNW's own toolkit only ever
      compares them by exact equality, never a "predates fix" ordering, and
      this tool follows the same approach)
- [x] Flag `CLASSIC_PAIRING_BYPASS_UNKNOWN` (MEDIUM) if firmware version unavailable
- [x] Document hardware requirement for active testing in README

## Phase 5 — Reporting and Polish
**Target: 2026-07-XX**

- [x] Per-device verdict: PASS / PARTIAL / VULNERABLE / SUSPECTED_COMPROMISE
      (`core/rules.py`)
- [x] CVE-tagged findings with severity, description, and remediation note
- [x] `--json FILE` export
- [x] `--flags-only` suppress clean devices
- [x] README with installation, usage, affected device list, and ethical use statement
- [x] `pytest tests/` coverage for fingerprint matching and GATT flag logic
- [x] `ruff` clean
- [x] Interactive ownership confirmation before any active probe
      (`--gatt`/`--race`/`--firmware`/`--assess`), with `--yes` to skip for
      scripted use. Added mid-Phase-5 after a live `--assess` smoke test
      against an unconfirmed nearby device triggered a real pairing prompt
      via its Fast Pair GATT service - a generic "probe every
      characteristic" approach can have real side effects on devices other
      than earbuds, not just an authorisation concern.

## Phase 6 — Baseline Capture and Drift Detection
**Target: 2026-07-XX**

- [x] `data/device_baselines.json` — local, per-address baseline store: name,
      manufacturer data (hex-encoded), GATT service/characteristic table,
      firmware version, host bonding-state booleans (never key material)
- [x] `--baseline` flag (with `--target ADDR`) — capture/overwrite the trusted
      baseline for a device; explicit user action only, never written
      automatically
- [x] `--check-drift` flag (with `--target ADDR`) — compare current scan
      against stored baseline
- [x] Flag `IDENTITY_DRIFT` (HIGH) — name/manufacturer data changed for a
      baselined address
- [x] Flag `GATT_TABLE_DRIFT` (MEDIUM) — service/characteristic set differs
      from baseline
- [x] Flag `FIRMWARE_DOWNGRADE` (HIGH) — any change from the baselined
      firmware build, not specifically a decrease: RACE buildversion strings
      are opaque vendor build identifiers with no sound ordering (same
      finding as Phase 4's exact-match resolution), so direction can't be
      determined - any unexpected change is itself the compromise-relevant
      signal
- [x] Flag `BOND_STATE_DRIFT` (HIGH) — local bonding record (Paired/Trusted/
      Bonded) changed without a user-initiated re-pair. Read via
      `bluetoothctl info <addr>` (BlueZ D-Bus properties), not
      `/var/lib/bluetooth` directly - that directory isn't readable without
      root on this system, which would have broken the project's "no root
      required" principle; presence/state only, never key material either way
- [ ] ~~Extend `core/race.py` with any read-only RACE status/uptime commands...
      flag `RECENT_UNEXPECTED_RESET`~~ — dropped: no such command exists
      anywhere in ERNW's race-toolkit reference source (checked
      `constants.py`, `packets.py`, `race_toolkit.py`), so there's nothing
      real to implement without inventing protocol behaviour
- [x] New verdict tier `SUSPECTED_COMPROMISE` — supersedes `VULNERABLE` when
      any drift flag fires (already wired into `core/rules.py` since Phase 5)

## Phase 7 — Impersonation / Relay Detection
**Target: 2026-07-06**

- [x] During a scan window, correlate all advertisers by name + manufacturer
      data (`core/impersonation.py:collect_advertisements` records every
      individual advertisement sighting, not collapsed to one-per-address
      like `scan_ble`, since reconstructing overlap requires every sample)
- [x] Detect concurrent duplicate identities with conflicting
      address/RSSI/timing (two physical sources presenting as one device) —
      grouped by (name, manufacturer_data) fingerprint, then flagged only
      when two distinct addresses' observation windows actually overlap in
      time. Plain non-overlapping sequential sightings of the same identity
      under two addresses are deliberately NOT flagged - that's expected
      behaviour for BLE address-privacy rotation (same finding as this
      project's own phone-unsuitability discovery in Phase 6), not
      impersonation
- [x] Flag `POSSIBLE_IMPERSONATION` (HIGH) — maps to threat model Step 5
      (impersonate the earbuds to the victim's phone)
- [x] `--watch` flag — continuous scan mode for impersonation monitoring,
      distinct from the one-shot assessment path. Passive-only (no GATT/RACE
      connection), so it does not go through the ownership-confirmation gate,
      same as `--scan`. Runs indefinitely in fixed-length windows until
      Ctrl+C - found live that the initial `try/except KeyboardInterrupt`
      inside the async loop never actually caught it (Python 3.14's
      `asyncio.run()` converts SIGINT into a `CancelledError` raised inside
      the coroutine first, only re-raising `KeyboardInterrupt` in the
      synchronous caller afterward), so the catch was moved to wrap
      `asyncio.run(run_watch(...))` in `main()` instead - verified against
      a real `SIGINT`
- [x] `--help`/`-h` work from a bare `python3 buds_audit.py --help` with no venv
      and no dependencies installed. `core/gatt.py`, `core/race.py`,
      `core/impersonation.py`, and `core/scanner.py` all import bleak at
      module load time, and `buds_audit.py` previously imported all of them at
      the top of the file - so before this fix, merely asking for `--help`
      required bleak to be importable, which defeats the point of a help
      menu. Each is now imported lazily inside the function that actually
      performs the Bluetooth operation.

---

## Out of Scope

- Full memory dump or Link Key extraction (crosses into active exploitation)
- Firmware injection via FOTA (destructive, out of scope for an assessment tool)
- Worm simulation
- Any testing against devices not owned or explicitly authorised by the user
- Forensic RAM/flash inspection for definitive compromise confirmation
  (would require performing the exploit itself); compromise assessment
  (Phases 6-7) is heuristic/drift-based only, never a memory read
