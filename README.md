# buds-audit

**Version 0.5.0**

Bluetooth security assessment tool for wireless earbuds affected by the
Airoha SDK vulnerability chain (CVE-2025-20700 / CVE-2025-20701 /
CVE-2025-20702). Scans for nearby devices, fingerprints known-affected
Airoha-based chipsets, and probes for unauthenticated GATT access and RACE
protocol reachability - entirely through the OS Bluetooth stack (BlueZ) via
`bleak`. No external Bluetooth dongle is required and root is not needed.

## Ethical use statement

This tool is for assessing devices you own or have explicit authorisation to
test. GATT and RACE probing are active operations: they connect to and send
commands to the target device. Do not run `--gatt`, `--race`, `--firmware`,
`--assess`, `--baseline`, or `--check-drift` against a device that isn't
yours or that you haven't been given permission to test. `--scan` is passive
and only listens to advertisements already being broadcast publicly, so it's
safe to run against whatever's in range.

Probing an arbitrary nearby device isn't just a policy concern - it can have
real side effects. `--gatt` attempts a read or notify-subscribe on every
characteristic it finds, and some consumer devices expose provisioning-style
services (e.g. Google's Fast Pair service) that react to that by kicking off
a real pairing handshake on the target device, independent of anything this
tool explicitly requests. A characteristic requiring encryption can trigger
the same thing even against your own device, since BlueZ can silently route
that authentication request to whatever agent your desktop has registered
(e.g. KDE's pairing prompt) - every active command therefore also registers
its own temporary BlueZ agent that auto-rejects any such request for the
duration of the probe, so no pairing prompt can appear at all. Every active
command also still prompts for confirmation that the target address is
yours before doing anything on the radio; pass `--yes` to skip the prompt
for scripted use once you've already confirmed it's your device:

```bash
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF --yes
```

`--watch` is passive, like `--scan` - it only listens to advertisements
already being broadcast and never connects to anything, so it doesn't
prompt for confirmation.

## Installation

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Requires Python 3.10+ (developed against 3.14) and a Linux system running
BlueZ with a powered-on Bluetooth adapter.

## Platform support

Linux only, and not automatically every Linux system:

- **Windows is not supported.** `bleak` itself has a Windows backend, but
  this tool doesn't rely on bleak alone - Bluetooth Classic discovery
  (`core/scanner.py`) and bonding-state checks (`core/gatt.py`) both shell
  out directly to `bluetoothctl`, a BlueZ-only CLI tool that doesn't exist
  on Windows. Those code paths would just fail with "command not found."
- **Requires BlueZ with `bluetoothctl` on PATH**, not just any Linux
  kernel. Most desktop distros ship this; a minimal or server image without
  the `bluez` package installed won't have it out of the box. Verified
  root-free on BlueZ 5.86 - other versions should work the same way since
  bleak targets BlueZ's standard D-Bus API, but that's not independently
  re-verified.
- **WSL is hardware-dependent, not a clean yes.** WSL2 can run BlueZ like
  any Linux, but reaching a real Bluetooth radio requires forwarding it
  from Windows via `usbipd-win`, which only forwards USB-attached
  adapters. Most laptops' built-in Bluetooth is wired in over a non-USB
  bus (SDIO/PCIe, alongside Wi-Fi), which `usbipd-win` generally can't
  forward - so this depends entirely on the specific hardware.

## A note on device power state

Many TWS earbuds stop advertising (and drop any active connection) after a
period of inactivity to save power, and some fully power off on their own.
If a scan can't find a device it found a minute ago, or a probe fails
partway through, that's usually the earbuds going idle, not a bug - take
them out of the case or press the pairing button again and retry.

This also affects address stability: this project's confirmed test unit (a
Sony WF-1000XM3) kept the same BLE address across every power cycle tested,
which is expected for earbuds designed for companion-app reconnection - they
typically use a fixed/public BLE address rather than a rotating one (unlike
phones, which do rotate private addresses and aren't a suitable target for
this tool for that reason). That's not guaranteed for every earbud model,
though - some vendors use resolvable private addresses even in
pre-pairing/reconnect mode, which would appear as a different address after
each power cycle to an unpaired scanner like this tool.

## Interactive mode

```bash
buds_audit.py
```

Running it with no flags at all launches a numbered menu instead of
requiring you to already know a BLE address or which flag does what:

```
1) Full analysis (scan, run the full CVE audit, and save a baseline)
2) Check current state against a saved baseline
3) Scan for spoofed/impersonating devices
4) Exit
```

Option 1 scans for nearby known-affected devices and lists them for you to
pick by number (rather than typing a MAC address), runs the full CVE audit
(same as `--assess`), and saves a baseline (same as `--baseline`) so future
runs can detect changes. Option 2 lists devices you've already baselined
and re-checks the one you pick for drift (same as `--check-drift`). Option
3 is `--watch`. Every option still goes through the same ownership
confirmation as the flag-based interface before touching the radio - the
wizard is a friendlier front end over the exact same underlying checks, not
a separate, less careful path.

The flag-based interface below is still there for scripted use or anyone
who already knows the address they want to target.

## Usage

All commands are run via `venv/bin/python buds_audit.py`.

```bash
buds_audit.py --help
```

Works from a bare `python3 buds_audit.py --help` even with no venv and no
dependencies installed - it doesn't import bleak until a command that
actually needs the radio is run.

### Discovery

```bash
buds_audit.py --scan
buds_audit.py --scan --flags-only   # only show devices matching the known-affected catalog
buds_audit.py --scan --target AA:BB:CC:DD:EE:FF
```

Passively scans for nearby BLE and Bluetooth Classic devices, fingerprints
Airoha chipsets from manufacturer data and address prefix, and cross-
references against `data/affected_devices.json`.

### Individual probes

Each of these requires `--target ADDR` and is an active operation against
that one device:

```bash
buds_audit.py --gatt --target AA:BB:CC:DD:EE:FF       # CVE-2025-20700: unauthenticated GATT access
buds_audit.py --race --target AA:BB:CC:DD:EE:FF       # CVE-2025-20702: RACE channel reachability
buds_audit.py --firmware --target AA:BB:CC:DD:EE:FF   # CVE-2025-20701: passive firmware/pairing-bypass check
```

All three skip cleanly (no error) if the device is already paired - an
"unauthenticated access" finding is meaningless against a bonded device.

### Full assessment

```bash
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF --json result.json
```

Runs all three probes above against one target and produces a single
verdict: `PASS`, `PARTIAL`, `VULNERABLE`, or `SUSPECTED_COMPROMISE`. `--json`
additionally writes the full result (device info, verdict, flags, evidence,
remediation notes) to a file.

`--assess` is deliberately single-target only, same as the individual
probes - there's no "assess every device in range" mode, since that would
mean actively probing devices that may not be yours.

### Compromise assessment (baseline and drift)

```bash
buds_audit.py --baseline --target AA:BB:CC:DD:EE:FF
buds_audit.py --check-drift --target AA:BB:CC:DD:EE:FF
```

`--baseline` captures a trusted snapshot for a device the first time you
assess it - identity (name and manufacturer data), GATT table, RACE firmware
build, and local bonding state (paired/trusted/bonded booleans only, never
key material) - and stores it in `data/device_baselines.json`. It's never
captured automatically; you have to ask for it explicitly, and running it
again overwrites the existing baseline.

`--check-drift` re-captures the same snapshot and compares it against the
stored baseline, producing a verdict from whatever drift is found:
`IDENTITY_DRIFT`, `GATT_TABLE_DRIFT`, `FIRMWARE_DOWNGRADE`, or
`BOND_STATE_DRIFT`. This answers "has something changed since I last
trusted this device," not "is this device vulnerable" - it's a heuristic
compromise signal, not forensic proof. A device with any drift flag gets a
`SUSPECTED_COMPROMISE` verdict, which supersedes everything else.

### Impersonation / relay monitoring

```bash
buds_audit.py --watch
```

Continuously scans in fixed-length windows (Ctrl+C to stop) and correlates
every advertisement seen by name and manufacturer data. If two different
addresses broadcast the same identity with overlapping observation windows -
meaning both were on the air with that identity at the same time - it flags
`POSSIBLE_IMPERSONATION`. A single physical device rotating its BLE address
over time (seen sequentially, not concurrently) is not flagged; only a
genuine second transmitter is. Maps to the threat model's final step:
impersonating the earbuds to the victim's phone.

## Known-affected devices

`data/affected_devices.json` is a curated catalog, not an exhaustive list.
Currently confirmed:

| Brand | Model | Airoha SoC | CVEs | Patched firmware |
|-------|-------|------------|------|-------------------|
| Sony | WF-1000XM3 | AB1562 | CVE-2025-20700, CVE-2025-20701, CVE-2025-20702 | None released |

Per the ERNW disclosure, other brands using Airoha AB1562/AB1565/AB1568-series
SoCs (including Bose, Jabra, JBL, Marshall, and pre-patch Beats models) are
also reported affected, but aren't in the catalog yet since their exact
address prefixes and chipset details haven't been confirmed against real
hardware in this project. A device outside the catalog can still be actively
probed with `--gatt`/`--race`/`--firmware`/`--assess` - the catalog only
affects the passive `--scan` match and verdict weighting, not what the
probes themselves test.

## Hardware requirement for CVE-2025-20701 active testing

This tool assesses CVE-2025-20701 (missing Bluetooth Classic pairing
enforcement) passively only, via the RACE firmware build-version check.
Actively testing whether a silent pairing handshake can be completed
requires raw HCI access via [Bumble](https://github.com/google/bumble) and a
dedicated Bumble-compatible USB Bluetooth dongle - not achievable through
BlueZ/bleak, which is why this tool doesn't attempt it. See ERNW's
[race-toolkit](https://github.com/auracast-research/race-toolkit) for an
interactive, dongle-based reference implementation covering all three CVEs.

## Acknowledgments

The Airoha SDK vulnerability chain (CVE-2025-20700 / CVE-2025-20701 /
CVE-2025-20702) was discovered and disclosed by Dennis Heinze and Frieder
Steinmetz at ERNW. Their [race-toolkit](https://github.com/auracast-research/race-toolkit)
is the reference implementation this project fills a no-dongle gap next
to, and the exact RACE protocol GATT UUIDs and packet framing used here
were read directly from its source rather than guessed - see `core/race.py`
for specifics. race-toolkit is unlicensed (no `LICENSE` file, checked
directly against the repo) - nothing from its source is reused here beyond
the underlying protocol facts (UUIDs, struct layout, command codes), which
describe Airoha's own protocol and aren't its authors' original expression
to license in the first place.

## License

MIT - see [LICENSE](LICENSE).

## Development

```bash
venv/bin/ruff check . --fix && venv/bin/ruff format .
venv/bin/python -m pytest tests/
```
