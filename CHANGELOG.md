# Changelog

## 0.9.0

- A fresh `--assess` after letting the confirmed test device rest for six
  hours came back partial (3 characteristics never reached) - a real
  improvement over the worst pre-rest runs (27 unreached) but not full
  determinism, consistent with 0.8.9's unresolved conclusion either way.
- A subsequent wizard run looked like it hung: the terminal sat silent for
  a long stretch and the earbuds eventually powered off mid-run. Every
  individual `await` in `core/gatt.py` was already bounded
  (`asyncio.wait_for` throughout), so this wasn't an actual infinite hang -
  but with `GATT_PROBE_MAX_RECONNECTS` at 25, each paying up to
  `CONNECT_TIMEOUT` (potentially twice, via `_unpaired_connection`'s own
  connect retry) plus `GATT_RECONNECT_SETTLE_SECONDS`, and zero progress
  output between attempts, a sweep against a device that's gone
  unreachable mid-run could silently take on the order of ten minutes
  before giving up.
- Added `on_progress` to `probe_gatt` (`core/gatt.py`): an optional
  callback invoked with a one-line status before each reconnect attempt.
  `run_gatt` and `run_assess` (`buds_audit.py`) pass `print`, so the
  wizard's Option 1 gets this too, since it runs through `run_assess`.
- Added `CONSECUTIVE_CONNECT_FAILURE_BAIL_OUT = 3`: if a reconnect attempt
  fails to even establish (not a mid-sweep disconnect after a successful
  connection, but `_unpaired_connection` itself raising `GattProbeError`)
  three times in a row, the sweep now stops immediately with an explicit
  message instead of exhausting the rest of the retry budget against a
  device that's plainly out of range or powered off. A security-triggered
  reconnect that actually succeeds resets this counter, so it doesn't
  interfere with the normal reconnect-and-resume path.
- Walked `GATT_PROBE_MAX_RECONNECTS` back down from 25 to 15. Live testing
  raised a real concern that hadn't been considered when the budget was
  raised: each reconnect attempt forces the device through another failed
  SMP pairing negotiation, and a bigger budget means more of those per run
  - the run immediately following the 25-budget test came back
  dramatically worse, and the earbuds auto-powered off mid-sweep in a
  later run. Not proven causation, but not worth risking on an unproven
  "more retries can only help" assumption either - paired with the new
  early bail-out above, the remaining budget mostly matters for a device
  that's still reachable but cycling through multiple protected
  characteristics, not one that's genuinely gone.
- Open question, not resolved: whether the device's tendency to degrade
  over a long session of repeated heavy testing (and recover after rest)
  reflects a deliberate connection-layer abuse-prevention/backoff behavior
  on the device, or is simply cumulative BLE-stack stress from repeated
  forced disconnects with no intentional logic behind it. Either way, the
  unauthenticated GATT reads/notifies that constitute the actual
  CVE-2025-20700 finding kept succeeding instantly even in the most
  degraded runs observed - only the connection/reconnect layer showed any
  sign of throttling, never the vulnerability itself.

## 0.8.9

- Follow-up on 0.8.8: live testing found the "one specific characteristic
  requires pairing" model was still incomplete - this device has *more
  than one* such characteristic, and at least one failure surfaced as a
  bare `TimeoutError()` with no message text at all rather than a
  detectable ATT security error, which the 0.8.8 `_is_security_required_error`
  text-matching missed entirely and miscounted against a separate, small
  "unexpected reconnect" budget. Simplified: every notify/indicate failure
  in `_probe_characteristic` (`core/gatt.py`) is now treated as a potential
  security trigger regardless of the specific error (a timeout costs little
  extra to treat this way; miscategorizing a real one is what was silently
  losing most of a sweep). The two-tier reconnect budget from 0.8.8 was
  dropped in favor of one larger, unified `GATT_PROBE_MAX_RECONNECTS`
  (raised to 25) - trying to classify "was this reconnect expected or not"
  turned out to be unreliable in practice, since even a reconnect made
  specifically to recover from a detected trigger can itself fail outright
  while BlueZ is still unwinding in the background. Also increased
  `GATT_RECONNECT_SETTLE_SECONDS` (1.5s to 3.5s) to give that unwinding
  more room, based on the ~2.6s delay confirmed in the original `btmon`
  capture.
- **Known limitation, not fully resolved**: live results after this fix
  ranged from a full clean sweep down to a nearly-empty one on the same
  device in the same session, and a *higher* reconnect budget made one run
  measurably worse, not better - a strong signal the remaining variability
  is genuine live radio/device-state noise (likely from a very long day of
  repeated heavy BLE testing against the same physical earbuds), not a
  further-fixable timing bug in this code. The tool now reliably reports
  when a sweep is incomplete (`GATT probe incomplete: N characteristic(s)
  never reached`) rather than silently presenting a partial result as
  complete, which is the honest, verifiable improvement this round
  actually delivered - full determinism was not achieved and further
  tuning was paused pending a fresh test after the device has rested.

## 0.8.8

- Live re-testing the 0.8.7 fix (with the earbuds confirmed powered on the
  whole time, ruling out the confound of an earlier test where they
  started off) still showed an incomplete GATT sweep - `GATT probe
  incomplete: 9-10 characteristic(s) never reached` - even though 0.8.7's
  proactive-reconnect detection was working. Root cause: this device has
  *more than one* characteristic that requires pairing, not just the one
  found via the original `btmon` capture - each one triggers its own
  proactive reconnect, and the previous single `GATT_PROBE_MAX_RECONNECTS`
  budget (3) was shared between "expected, security-triggered" reconnects
  and "something else is generally wrong" reconnects, so it ran out after
  a handful of legitimately-protected characteristics, well before reaching
  the rest of the device's ~30-characteristic table. Split into two
  separately-tracked budgets in `probe_gatt` (`core/gatt.py`): reconnects
  triggered by a detected `security_required` signal are no longer capped
  (they're expected and deterministic, and always consume at least one
  worklist item, so the loop is naturally bounded by the total
  characteristic count regardless); only reconnects for any other reason
  count against the new `GATT_PROBE_MAX_UNEXPECTED_RECONNECTS` (3), which
  still exists to bound genuine, unexplained instability.

## 0.8.7

- The 0.8.6 reconnect-and-resume fix was still non-deterministic: it only
  reacted to a mid-sweep disconnect after `client.is_connected` actually
  went `False`, but confirmed live, BlueZ doesn't tear down the connection
  until a few seconds *after* the triggering characteristic - so how many
  more characteristics happened to complete in that window (and therefore
  the final finding count) was pure timing luck, reproduced live as 26, 2,
  and 26 findings across otherwise-identical runs. `_probe_characteristic`
  (`core/gatt.py`) now detects the specific ATT security rejection
  (`Insufficient Authentication`/`Authorization`/`Encryption`, via a new
  `_is_security_required_error` helper matching bleak's own
  `PROTOCOL_ERROR_CODES` text) the instant it happens and reports it back;
  `probe_gatt` reconnects immediately on that signal instead of continuing
  to gamble on the delayed disconnect, making the sweep's completeness
  deterministic rather than timing-dependent.
- Also fixed a related honesty gap: when the reconnect budget did run out
  with characteristics never reached, `probe_gatt` silently returned
  whatever partial findings it had, indistinguishable from a genuinely
  complete result. `probe_gatt` now returns `(flags, unreached_count)`, and
  `run_gatt`/`run_assess` (`buds_audit.py`) print an explicit "GATT probe
  incomplete: N characteristic(s) never reached" notice when
  `unreached_count` is nonzero, so an incomplete sweep is never mistaken
  for a clean, complete one.

## 0.8.6

- Fixed a real bug in the 0.8.5 reconnect-and-resume loop, found live via
  the wizard immediately after shipping it: `probe_gatt` only handled a
  mid-sweep disconnect (`client.is_connected` going `False`), but
  `_unpaired_connection` can itself raise `GattProbeError` when a
  *reconnect* attempt fails to establish at all - uncaught, that exception
  propagated straight out of `probe_gatt`, skipping the rest of the
  reconnect budget entirely and defeating the whole point of the loop
  (`GATT probe skipped: ... failed to discover services, device
  disconnected`, then baseline capture failing the same way right after).
  Now caught and retried like any other reconnect, with a
  `GATT_RECONNECT_SETTLE_SECONDS` (1.5s) pause first - paced the same way
  and for the same live-confirmed reason as `buds_audit.py`'s
  `INTER_PROBE_SETTLE_SECONDS`. Only re-raised if every attempt fails and
  nothing was ever collected (`pending` still `None`, meaning not even the
  first connection succeeded) - if earlier attempts already found real
  characteristics, those are kept rather than thrown away over a later
  reconnect failing. **Confirmed fixed live**: a full `--assess
  --memory-read` run completed with zero probe failures and all 26 GATT
  characteristics found.

## 0.8.5

- The 0.8.3 fix (reorder RACE/BD-address/firmware before `probe_gatt`,
  defensively call `StopNotify` even after a failed `StartNotify`) turned
  out to be a partial mitigation, not a complete fix: live-tested via the
  wizard, `probe_gatt`'s own sweep still got cut short the moment it
  reached the pairing-requiring characteristic (1 finding instead of the
  usual 26), and the very next connection (baseline capture, run
  immediately after in the wizard) inherited the same
  `failed to discover services, device disconnected` failure. `probe_gatt`
  (`core/gatt.py`) now builds the full (service, characteristic,
  properties) worklist from the first connection, then works through it
  across as many reconnects as needed (bounded by
  `GATT_PROBE_MAX_RECONNECTS = 3`) instead of assuming one connection can
  survive the whole sweep - `client.is_connected` is checked before each
  attempt, since `_probe_characteristic` deliberately swallows every
  per-characteristic error itself and nothing would otherwise signal the
  link is already gone. `_probe_characteristic` now takes a plain
  characteristic UUID string plus its properties instead of a bleak
  characteristic object, since the worklist needs to survive across
  reconnects to fresh `BleakClient` instances - bleak's own
  `read_gatt_char`/`start_notify`/`stop_notify` already accept a UUID
  string directly, resolved against whichever client is passed in.

## 0.8.4

- Interactive mode's Option 1 ("Full analysis") was silently missing
  `--memory-read` - `run_assess` only includes it when called with
  `include_memory_read=True`, and the wizard called it with no argument at
  all, so the wizard's "full" audit could never actually reach the
  definitive CVE-2025-20702 confirmation, with no indication to the user
  that it was being skipped. Added `_confirm_memory_read_async` (wizard
  equivalent of `_confirm_memory_read`, using `_async_input` like the rest
  of the wizard) and wired it into `_wizard_full_analysis`: it now asks the
  same memory-read question after the ownership confirmation, framed as an
  optional addition rather than a gate on an explicit flag - declining
  skips just that one check and still runs the rest of the audit, unlike
  the CLI path's --memory-read handling, which aborts the whole command on
  decline since there the user already asked for it specifically. Also
  fixed the wizard's stale "Running the full vulnerability audit (GATT,
  RACE, firmware)..." message, which predated the 0.8.0 BD-address addition
  and didn't mention memory-read either.

## 0.8.3

- Found the actual root cause of the 0.8.1/0.8.2 `--assess` failures via a
  live `btmon` capture (the inter-probe delay in 0.8.2 didn't fix it - this
  does, per the mechanism it targets): `probe_gatt`'s per-characteristic
  notify sweep calls `StartNotify` on every notify-capable characteristic,
  including one (on this device) that requires pairing and returns
  `Insufficient Encryption`. BlueZ automatically tries to elevate security
  via SMP pairing to satisfy it; this project's `no_pairing_agent` (by
  design, so no real pairing dialog appears) rejects it; BlueZ then tears
  down the *entire* connection over the failed pairing, not just that one
  characteristic. Confirmed live that BlueZ retains "this characteristic
  wants notifications" afterward and automatically retries the same write
  (and the resulting forced disconnect) on *every subsequent reconnect* to
  this device for the rest of the `bluetoothd` process's life, regardless of
  which probe initiates the reconnect - a completely separate RACE probe
  connection, moments later, went straight from MTU exchange to retrying
  the identical write with no service discovery in between. Two changes:
  `_probe_characteristic` (`core/gatt.py`) now always attempts `StopNotify`
  in a `finally`, even after a failed `StartNotify`, as a best-effort
  attempt to clear that stuck intent rather than leaving every later
  connection in the run poisoned; and `run_assess` (`buds_audit.py`) now
  runs RACE/BD-address/firmware *before* `probe_gatt`, since `probe_gatt`'s
  notify sweep is what triggers this in the first place - giving the other
  probes a clean connection before it has a chance to. **Confirmed fixed**
  live after a fresh `bluetoothd` restart: a full `--assess` run completed
  with zero probe failures (RACE, BD-address, and firmware all completed
  cleanly; GATT probe got the full 26/26 characteristics).

## 0.8.2

- The 0.8.1 connect-retry fix turned out not to be the whole story: live
  re-testing (with the phone's Bluetooth off and the earbuds freshly woken,
  ruling out both a competing reconnect and idle/sleep as causes) still
  reproduced RACE/BD-address/firmware all failing with `failed to discover
  services, device disconnected` - a different bleak error than 0.8.1's fix
  targeted, raised *inside* `client.connect()` itself when BlueZ accepts a
  connection but the peripheral drops it again before GATT service
  discovery finishes. `--assess` opens several separate connections
  back-to-back against the same address with no gap between them;
  reconnecting immediately after the previous probe's disconnect appears to
  not give this device's BLE stack time to settle. Added
  `INTER_PROBE_SETTLE_SECONDS` (1.5s) between each probe's connect/disconnect
  cycle in `run_assess` (`buds_audit.py`) as a live-testable fix for this
  specific failure mode.

## 0.8.1

- Fixed a live-observed `--assess` failure: `BD-address query skipped: could
  not complete BD-address query against ...: device 'dev_...' not found`.
  Root cause (traced into bleak's own source, `bluezdbus/manager.py`'s
  `_check_device`): `--assess` runs several independent BLE
  connect/disconnect cycles back-to-back against the same address, and
  since this tool never pairs, BlueZ treats every connection as
  "temporary" and can drop its D-Bus record for the device between cycles
  if it goes idle/stops advertising in that window - more likely to bite
  now that `--bd-address` (0.8.0) added a fourth cycle. `core/gatt.py`'s
  `_unpaired_connection` and a new equivalent in `core/race.py`
  (`_race_connection`) now retry the connect step once before giving up;
  also fixed `_unpaired_connection` to catch `TimeoutError` alongside
  `BleakError` on that connect step, which it was missing (unlike
  `core/race.py`'s probes, already fixed for this in 0.6.0).
- Restructured `--assess` output for readability: a device with many
  exposed GATT characteristics previously printed one full
  description/remediation block per characteristic - live-tested against
  the project's own Sony WF-1000XM3, this meant the same boilerplate
  remediation paragraph repeated 15+ times, burying the one HIGH-severity
  finding under a wall of near-identical MEDIUM ones. Findings are now
  grouped by `flag_id`, ordered by descending severity (HIGH/CRITICAL
  first), with repeated-instance groups (currently only
  `GATT_UNAUTHENTICATED_ACCESS`) collapsed into one shared
  description/remediation plus a compact per-instance line, instead of
  repeating everything per instance. `--json` output is unaffected - the
  full flat flag list is still exported for machine consumption.

## 0.8.0

- Added two more scope augmentations in the same spirit as Phase 8 - real,
  no-new-risk operations the project's original scope had left out before
  the specifics were understood:
  - `--gatt`/`--assess` now surface the actual value returned by a
    successful unpaired read or notification (`value_hex` in
    `GATT_UNAUTHENTICATED_ACCESS` evidence) instead of discarding it after
    confirming the read succeeded. The read/subscribe already happens; this
    just stops throwing the result away.
  - Added `--bd-address` / `probe_bd_address`: queries the device's real
    Bluetooth Classic (BR/EDR) address via RACE (`RACE_GET_BD_ADDRESS`/
    `0xCD5`, cross-checked directly against race-toolkit's
    `librace/constants.py` and `librace/packets.py`). Same zero-payload
    metadata-query risk shape as the existing firmware buildversion check,
    so no separate confirmation gate - runs automatically as part of
    `--assess`. Useful for pursuing CVE-2025-20701 active testing with a
    user's own Classic-capable radio, since this tool has no Classic
    transport of its own.
  - A third candidate, Bluetooth Classic SDP service discovery, was scoped
    but deliberately not built - Classic Bluetooth's pairing/security model
    is more likely to trigger a real pairing prompt from a bare connection
    attempt than BLE's is (this project has already been surprised once by
    exactly that shape of problem, in Phase 5's Fast Pair incident), so it
    needs a live side-effect check against real hardware before being
    trusted as safe. See ROADMAP.md's Phase 9 for the full reasoning.

## 0.7.3

- `--memory-read` now reports *why* nothing was disclosed instead of one
  generic message for every case: total silence, a response that didn't
  look like a well-formed flash-read reply, and (most importantly) the
  device explicitly declining with a specific return code are three
  different results and were printing identically. `probe_memory_read` now
  returns a `note` alongside `service_found`/`flags`; `--assess
  --memory-read` prints it too when present. Found immediately after 0.7.2:
  the internal fix there correctly captured a real return code, but the
  print path had never been updated to surface it, so the same generic
  "no memory disclosed" text kept showing regardless.

## 0.7.2

- Fixed a regression the 0.7.1 fragmentation fix introduced: `_send_race_command`
  required the *full* declared frame length before trusting a response, which
  meant a response the device deliberately never finishes sending - confirmed
  live, twice, with both write types: a declined flash-page-read's first
  (233-byte) fragment arrived reliably every time, but a second fragment
  never did, even after the full 8-second response timeout - got silently
  discarded entirely instead of being reported, even though that first
  fragment already carried the complete, decisive return code. A response
  timeout with at least some bytes already buffered is now returned as that
  partial frame rather than treated as no response; only genuinely getting
  zero bytes at all still falls through to trying the next write type / a
  final None.

## 0.7.1

- Fixed `_send_race_command` (`core/race.py`) only capturing the first BLE
  notification of a RACE response and treating it as the whole thing.
  Found live testing `--memory-read` against this project's own Sony
  WF-1000XM3: a real 270-byte flash-page-read response over a 242-byte
  negotiated ATT MTU arrives as two notification fragments, and the probe
  disconnected after the first (233 of 264 payload bytes) instead of
  waiting for the second. Every notification is now accumulated against the
  full logical frame size declared in the first fragment's header
  (`length + 4`, matching race-toolkit's own `RACE._recv` reassembly in
  `librace/race.py`) before the response is considered complete. Didn't
  change that specific test's conclusion (the return code sits in the first
  byte of the payload, already fully captured), but would have silently
  truncated a larger legitimately-disclosed page in a different scenario.

## 0.7.0

- Added an opt-in, definitive CVE-2025-20702 confirmation: `--memory-read`
  attempts one real, read-only RACE flash-page read (256 bytes, fixed
  address) against `--target`, standalone or combined with `--assess`.
  Added after live testing against this project's own Sony WF-1000XM3 found
  `--race` reachable-but-silent to its benign SDK-info query, and a `btmon`
  capture confirmed that silence was genuine rather than a probe artifact -
  but a benign query never touches memory, so it can't rule out the actual
  attack (a memory read) succeeding. Reviewed ERNW's race-toolkit source
  directly and confirmed no dongle is required: RACE commands go over the
  same tx/rx GATT characteristics regardless of transport, and the toolkit
  ships a bleak-based transport alongside its default Bumble/raw-HCI one.
  Deliberately narrow in scope, not a general memory-dump capability: one
  fixed address, one fixed page, no caller-supplied address/size, no
  looping, flash only (never RAM/registers, which can have read side
  effects on some architectures unlike flash), and never
  Program/Erase/FOTA/GetLinkKey - those remain fully out of scope regardless
  of this flag. Requires its own explicit confirmation, describing exactly
  what it does, beyond the standard ownership prompt (skippable via `--yes`
  like every other prompt, for scripted use). Flags `RACE_MEMORY_READ_CONFIRMED`
  (HIGH) only on a well-formed response with a success return code and
  actual page data - a device that responds but explicitly declines the
  read raises no flag, since reachable-and-responsive isn't the same as
  confirmed disclosure.

## 0.6.0

- Fixed two real sources of ambiguity in the RACE reachability/firmware probe
  (`core/race.py`) that could make a live device look like it "didn't
  respond" for reasons unrelated to whether it actually enforces
  authentication - found while investigating a live result against the
  project's own Sony WF-1000XM3, where the RACE service accepted a command
  cleanly but never replied:
  - The response timeout was 3 seconds; ERNW's own race-toolkit waits up to
    8 seconds for the same kind of single RACE command/response round trip,
    so a shorter wait here could report "no response" before the device had
    a realistic chance to answer. Bumped to match.
  - The command write always forced `response=True` (a GATT Write Request)
    regardless of what the tx characteristic actually declares support for.
    A firmware that only listens on Write-Without-Response would look
    identical to a genuinely silent device. The write type is now read from
    the characteristic's own declared properties, and both types are tried
    in turn when both are declared, before a "no response" result is
    trusted.
  - A `BleakError` or operation-level timeout from the underlying
    start_notify/write_gatt_char/stop_notify calls no longer collapses into
    the same "no response" result as a clean write met with silence - it now
    raises `RaceProbeError`, since a failed probe and a genuinely
    unresponsive device are different findings and shouldn't be reported the
    same way.
  - Cross-checked directly against race-toolkit's own source: its `setup()`
    performs no RACE-level handshake beyond connecting and subscribing to
    notifications, so no session-establishment step was missing here. Its
    `check` subcommand's own BLE finding, however, uses Bumble's raw-HCI
    transport and an actual flash-read command rather than bleak and
    GetSDKInfo, and its own code treats a timeout there as "might be fixed,"
    not certain - the same inherent ambiguity this project already reports
    honestly rather than overclaiming.

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
