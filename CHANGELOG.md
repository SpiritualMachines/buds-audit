# Changelog

## 0.5.0

- Interactive wizard mode: running `buds_audit.py` with no flags at all now
  launches a numbered menu (full analysis + baseline, check drift, watch
  for spoofing) instead of printing help, for anyone not already
  comfortable with a CLI and BLE addresses. Device selection is done by
  picking from a scanned or previously-baselined list rather than typing a
  MAC address. Built as a thin layer over the existing `run_assess`/
  `run_baseline`/`run_check_drift`/`run_watch` functions and the same
  ownership-confirmation gate the flag-based interface already uses -
  no separate, less-careful logic path.
- The flag-based interface is unchanged and still the primary interface for
  scripted use; `--help`/`-h` and every existing flag behave exactly as
  before.
- Fixed `--scan`, `--watch`, and the wizard's device picker crashing with a
  raw traceback if the local Bluetooth adapter is off, missing, or
  rfkill-blocked - confirmed live by actually powering the adapter off:
  `BleakScanner` raises `BleakBluetoothNotAvailableError` in that case
  rather than returning no results, and nothing caught it. Active probes
  (`--gatt`/`--race`/`--firmware`/`--assess`/`--baseline`/`--check-drift`)
  already handled this correctly via their existing `BleakError` handling -
  also confirmed live - so only the scanning path needed the fix. New
  `ScanError` in `core/scanner.py` (reused by `core/impersonation.py` for
  `--watch`/wizard option 3) now turns this into the same kind of clean
  "skipped"/"failed" message as every other probe failure.
- Fixed the wizard permanently reporting "no powered Bluetooth adapters"
  after turning Bluetooth back on mid-session, even though `bluetoothctl`
  itself correctly showed it powered - confirmed live and root-caused, not
  just patched over. bleak's BlueZ backend needs the asyncio event loop
  continuously running to process D-Bus signals (including the adapter's
  own `Powered` property changing); the wizard's menu and confirmation
  prompts used plain blocking `input()` calls, which stall the entire event
  loop while waiting on the user, so a `PropertiesChanged` signal arriving
  during that wait was never processed and the stale "not powered" state
  stuck around for the rest of the session. Every wizard prompt now goes
  through `_async_input` (`input()` run in a separate thread via
  `asyncio.to_thread`) instead, keeping the event loop free to process
  D-Bus signals while waiting on the user. The flag-based interface never
  had this problem: its one ownership prompt runs before `asyncio.run()`
  starts a loop for the actual probe, not during one.
- Added an MIT `LICENSE` and an Acknowledgments section crediting Dennis
  Heinze and Frieder Steinmetz's ERNW research and race-toolkit, which the
  RACE protocol details in `core/race.py` were read from.

## 0.4.0

- Every active probe (`--gatt`/`--race`/`--firmware`/`--assess`/`--baseline`/
  `--check-drift`) now registers a temporary BlueZ agent (`core/agent.py`)
  that auto-rejects any pairing/authorization request for the duration of
  the probe, then hands control back. BlueZ can silently route a GATT
  characteristic's "insufficient authentication" response to whatever agent
  is currently the system default (the desktop's own, e.g. KDE's
  kded6/bluedevil) independent of anything this tool's Python code does -
  confirmed live as a real pairing prompt while auditing this project's own
  confirmed test device. Approving that prompt would both corrupt the
  "unauthenticated access" finding and leave a real bond behind, so the tool
  now closes the hole instead of relying on a human to notice and reject a
  prompt in time.
- Fixed a false `IDENTITY_DRIFT`/`SUSPECTED_COMPROMISE` on an unchanged
  device: `compute_drift` compared manufacturer_data with strict equality,
  but a single scan window doesn't reliably capture manufacturer-specific
  data every time - an earlier `--baseline` run caught an empty capture,
  a later `--check-drift` caught real data, and nothing had actually
  changed. Manufacturer_data now only counts as conflicting when both
  snapshots actually have data to compare, the same tolerance
  `firmware_version` comparison already used for the identical underlying
  reason. Found live against the project's own Sony WF-1000XM3.
- Fixed `--watch` printing an unhandled-exception traceback on Ctrl+C
  instead of exiting cleanly. On Python 3.14, `asyncio.run()` converts
  SIGINT into a `CancelledError` raised inside the running coroutine first,
  only re-raising `KeyboardInterrupt` in the synchronous caller afterward -
  a `try/except KeyboardInterrupt` inside the coroutine itself never
  actually caught it. The catch now lives around `asyncio.run(run_watch(...))`
  in `main()`, verified against a real `SIGINT`, not just re-read code.

## 0.3.0

- Impersonation/relay detection (`--watch`) for threat model Step 5
  (impersonating the earbuds to the victim's phone): continuously scans in
  fixed-length windows and flags `POSSIBLE_IMPERSONATION` (HIGH) when two
  distinct addresses broadcast the same name/manufacturer-data identity with
  overlapping observation windows.
- Detection deliberately requires concurrency (overlapping first-seen/
  last-seen windows), not just a shared identity across two addresses at
  some point during the scan - a device rotating its own BLE address over
  time would otherwise false-positive as impersonating itself.
- `--watch` is passive-only, like `--scan`: it never connects to a device,
  so it doesn't go through the ownership-confirmation gate.
- Fixed `--help`/`-h` failing with `ModuleNotFoundError: No module named
  'bleak'` when run outside the project's venv: `core/gatt.py`,
  `core/race.py`, `core/impersonation.py`, and `core/scanner.py` all import
  bleak at module load time, and `buds_audit.py` imported all of them
  unconditionally at the top of the file, so just asking for `--help`
  needed bleak installed. Those imports are now deferred to inside the
  function that performs the actual Bluetooth operation, so `--help`, `-h`,
  and no-args now work from a bare `python3 buds_audit.py` with no venv and no
  dependencies.

## 0.2.0

- Baseline capture (`--baseline`) and drift detection (`--check-drift`) for
  compromise assessment: snapshots identity, GATT table, RACE firmware
  build, and local bonding state (paired/trusted/bonded booleans only, never
  key material) into `data/device_baselines.json`, captured only via
  explicit user action.
- Drift flags `IDENTITY_DRIFT`, `GATT_TABLE_DRIFT`, `FIRMWARE_DOWNGRADE`,
  and `BOND_STATE_DRIFT`, feeding into the existing verdict engine as
  `SUSPECTED_COMPROMISE`, which supersedes every other verdict.
- Firmware-version drift is flagged on any change rather than a directional
  "downgrade": RACE buildversion strings have no sound ordering to compare
  (same finding as the Phase 4 pairing-bypass check).
- `RECENT_UNEXPECTED_RESET` from the original roadmap was dropped: no
  read-only RACE uptime/status command exists anywhere in ERNW's reference
  implementation, so there's nothing real to check.
- Fixed a real hang: `read_gatt_char`/`start_notify`/`write_gatt_char`/
  `stop_notify` have no timeout of their own, and a device that silently
  drops a request instead of returning an ATT error could stall `--gatt`
  and `--race` indefinitely. Every one is now wrapped with a bound. Found
  via live testing against a physical Sony WF-1000XM3.
- `--race` now distinguishes "no RACE service present" from "RACE service
  present but did not respond to an unauthenticated command" instead of
  reporting both identically - also found via live testing against real
  hardware, where the Sony RACE service was reachable and accepted a
  correctly-framed command but never returned a response.
- Corrected the seeded Sony WF-1000XM3 catalog entry's address prefix
  (`94:DB:56`, verified by live scan) - the original `AC:7B:A1` was never
  actually checked against the hardware and didn't match.

## 0.1.0

- BLE and Bluetooth Classic discovery (`--scan`), with Airoha chipset
  fingerprinting from manufacturer data and known-affected device matching
  against `data/affected_devices.json`.
- Unauthenticated GATT access probe (`--gatt`) for CVE-2025-20700: attempts
  real unpaired reads and notify-subscribe cycles against every discovered
  characteristic, since declared BLE properties can't prove whether
  authentication is enforced.
- RACE protocol reachability probe (`--race`) for CVE-2025-20702: detects
  known Airoha/Sony RACE GATT UUIDs and confirms whether the RACE command
  channel accepts an unauthenticated command and responds, without ever
  issuing a memory read/write command.
- Passive firmware/pairing-bypass check (`--firmware`) for CVE-2025-20701:
  retrieves the RACE build-version string and cross-references it against
  known-patched builds.
- Combined assessment (`--assess`) running all three probes against one
  target device and producing a single PASS/PARTIAL/VULNERABLE/
  SUSPECTED_COMPROMISE verdict, with remediation notes and optional JSON
  export (`--json`).
- `--flags-only` to suppress catalog-unmatched devices from `--scan` output.
- Interactive ownership confirmation before `--gatt`/`--race`/`--firmware`/
  `--assess` do anything on the radio, with a `--yes` flag to skip it for
  scripted use. Added after a live GATT probe against an unconfirmed nearby
  device triggered a real pairing prompt via its Fast Pair service.
