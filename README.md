# buds-audit

**Version 1.0.0**

Bluetooth security assessment tool for wireless earbuds affected by the
Airoha SDK vulnerability chain (CVE-2025-20700 / CVE-2025-20701 /
CVE-2025-20702). Scans for nearby devices, fingerprints known-affected
Airoha-based chipsets, and probes for unauthenticated GATT access and RACE
protocol reachability - entirely through the OS Bluetooth stack (BlueZ) via
`bleak`. No external Bluetooth dongle is required and root is not needed.
Results are reported in plain language alongside the technical detail, so you
can act on them without deep Bluetooth knowledge.

## Ethical use statement

This tool is for assessing devices you own or have explicit authorisation to
test. GATT and RACE probing are active operations: they connect to and send
commands to the target device. Do not run `--gatt`, `--race`, `--firmware`,
`--bd-address`, `--assess`, `--baseline`, `--check-drift`, or `--memory-read`
against a device that isn't yours or that you haven't been given permission
to test. `--scan` is passive and only listens to advertisements already
being broadcast publicly, so it's safe to run against whatever's in range.

`--memory-read` goes a step further than the other active probes: it
retrieves one real, read-only page (256 bytes) of the device's actual flash
content, at a fixed address, as a definitive confirmation of CVE-2025-20702
when the reachability-only `--race` probe gets no response. It is read-only
(flash reads carry no wear or bricking risk, unlike write/erase/FOTA
commands, which this tool never sends), opt-in, and requires its own
separate confirmation beyond the standard ownership prompt describing
exactly what it does before it runs anything.

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

### Running it from Windows or macOS

You don't need a Linux machine of your own - you just need Linux with real
access to a Bluetooth radio. Two practical ways to get that:

- **Boot Fedora from a live USB (easiest, recommended).** A Fedora live USB
  runs the whole OS off the stick without installing anything, on bare
  metal - so it has direct access to *all* your hardware, including the
  laptop's built-in Bluetooth. Boot it, install the dependencies (see
  Installation), run the tool, reboot back into your normal OS when you're
  done. Nothing is written to your disk. This is the least fiddly option
  for occasionally checking your own devices.
- **A Fedora VM with a USB Bluetooth dongle passed through.** If you'd
  rather keep a persistent install, run Fedora in a VM (VirtualBox with the
  Extension Pack, or VMware Workstation/Fusion - these handle per-device USB
  passthrough cleanly; Hyper-V does not). The catch is the adapter: a VM
  generally *cannot* borrow your laptop's built-in Bluetooth, so pass
  through a cheap external USB Bluetooth dongle (4.0+, a Linux-friendly
  chipset like CSR8510, Realtek RTL8761B, or Intel) instead. Once Fedora
  sees that dongle, BlueZ drives it directly and the tool works exactly as
  on bare metal. On Apple Silicon Macs, run the ARM64 build of Fedora (the
  tool is architecture-agnostic) and use a hypervisor that supports USB
  passthrough, such as UTM.

Either way, the rule is the same: the tool itself is unchanged - it just
needs Linux with a Bluetooth adapter BlueZ can actually reach.

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

The GATT probe (`--gatt`, and the GATT stage of `--assess`) can need several
reconnects if the device has characteristics that require pairing - each one
makes BlueZ attempt (and this tool's own agent reject) a real pairing
negotiation before reconnecting to resume the sweep, and prints a one-line
status before each attempt so a slow sweep doesn't look hung. When such a
subscription is rejected, BlueZ retains the intent and re-issues it on every
later connection to that device; to stop that from derailing subsequent
reconnects, the probe clears BlueZ's cached record of the device (equivalent
to `bluetoothctl remove`) before each reconnect, so every attempt starts from
a clean state. With that in place, repeated back-to-back sweeps against the
confirmed test device return the same complete result each time. An earlier
observation - completeness appearing to degrade over a session of heavy
testing and recover after a rest - has not recurred since, and is believed to
have been the same retained-state accumulation rather than device fatigue.

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
(same as `--assess`, including the BD-address query), and saves a baseline
(same as `--baseline`) so future runs can detect changes. It also asks the
same memory-read question `--assess --memory-read` answers via its
confirmation prompt - answering yes there includes the same real, read-only
RACE flash-page read described above; answering no just runs the audit
without it, it doesn't cancel the whole analysis. Option 2 lists devices
you've already baselined and re-checks the one you pick for drift (same as
`--check-drift`). Option 3 is `--watch`. Every option still goes through
the same ownership confirmation as the flag-based interface before
touching the radio - the wizard is a friendlier front end over the exact
same underlying checks, not a separate, less careful path.

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
buds_audit.py --bd-address --target AA:BB:CC:DD:EE:FF # Classic BD address via RACE, informational
```

All four skip cleanly (no error) if the device is already paired - an
"unauthenticated access" finding is meaningless against a bonded device.

`--gatt` now shows the actual value returned by each successful unpaired
read or notification (hex-encoded), not just that the read succeeded - the
value was already being retrieved, so this is no additional risk, just no
longer discarded.

`--race` only tests reachability (a benign SDK-info query, no memory
access) - a RACE service can be present and accept the write cleanly but
still not reply, which is a genuinely inconclusive result, not evidence of
anything fixed. For a definitive answer, see `--memory-read` below.

`--bd-address` is informational, not a vulnerability finding on its own: it
queries the device's real Bluetooth Classic (BR/EDR) address over the same
unauthenticated RACE channel, same risk shape as `--firmware`'s buildversion
query (a zero-payload metadata command). Useful if you want to pursue
CVE-2025-20701 active testing yourself with a Classic-capable radio/dongle,
since this tool has no Classic transport of its own - see the Hardware
requirement section below.

### Memory-read confirmation (opt-in)

```bash
buds_audit.py --memory-read --target AA:BB:CC:DD:EE:FF
```

Attempts one real, read-only RACE flash-page read (256 bytes, from a fixed
address) for a definitive CVE-2025-20702 confirmation - useful when
`--race` finds the RACE service present but unresponsive to its benign
query. This is opt-in and separate from `--race` on purpose: a success here
retrieves real device firmware content, not just a yes/no signal about
whether the channel is reachable. It never writes, erases, extracts link
keys, or reads RAM/registers (only flash, which has no read side effects) -
see ROADMAP.md's Phase 8 and Out of Scope sections for the full reasoning.
It requires its own separate confirmation, describing exactly what it does,
beyond the standard ownership prompt.

### Full assessment

```bash
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF --json result.json
buds_audit.py --assess --target AA:BB:CC:DD:EE:FF --memory-read
```

Runs the GATT, RACE, firmware, and BD-address probes above against one
target and produces a single verdict: `PASS`, `PARTIAL`, `VULNERABLE`, or
`SUSPECTED_COMPROMISE`. The verdict and every individual finding are printed
with a plain-language interpretation next to the technical detail, so the
result is readable without deep Bluetooth knowledge - this tool is meant for
anyone checking their own devices, not only security specialists. `--json`
additionally writes the full result (device info, verdict and its plain-
language explanation, flags with evidence and their plain-language gloss, and
remediation notes) to a file.
Adding `--memory-read` folds the memory-read confirmation into the same
audit and verdict, with its own separate confirmation prompt first. The
BD-address query runs automatically as part of `--assess` (no separate flag
needed, no extra confirmation prompt) since it's the same low-risk
metadata-query shape as the firmware check.

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
