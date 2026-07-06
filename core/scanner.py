"""BLE advertisement scanning (bleak) and Bluetooth Classic discovery.

hcitool is absent on modern BlueZ-only systems (5.86+ here), so Classic
discovery shells out to `bluetoothctl --timeout N scan bredr` and parses its
device-change output instead of using hcitool directly. BLE stays on bleak,
which talks to BlueZ over D-Bus without a subprocess.

BLE and Classic scans run sequentially rather than concurrently: both are
driven through BlueZ discovery filters on the same adapter, and this avoids
relying on unverified assumptions about how BlueZ merges concurrent
discovery sessions from two independent clients (bleak's D-Bus connection
and the bluetoothctl subprocess).

scan_ble raises ScanError if the adapter isn't available (off, missing, or
rfkill-blocked) - confirmed live: bleak raises
BleakBluetoothNotAvailableError (a BleakError subclass) rather than
returning an empty result, so an unhandled scan_ble call previously crashed
with a raw traceback instead of failing cleanly. scan_classic doesn't need
the same handling: bluetoothctl itself degrades gracefully when the adapter
is off (prints "Failed to start discovery: org.bluez.Error.NotReady" to its
own output and exits 0), so it just yields an empty device list rather than
raising anything - confirmed live rather than assumed.
"""

from __future__ import annotations

import asyncio
import re

from bleak import BleakScanner
from bleak.exc import BleakError

from core.models import BtDevice

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_DEVICE_LINE_RE = re.compile(r"\[(NEW|DEL)\] Device ([0-9A-Fa-f:]{17})\s*(.*)")


class ScanError(Exception):
    """Raised when a scan could not run - most commonly because the local
    Bluetooth adapter is off, missing, or blocked."""


async def scan_ble(timeout: float = 10.0) -> list[BtDevice]:
    try:
        discovered = await BleakScanner.discover(timeout=timeout, return_adv=True)
    except BleakError as exc:
        raise ScanError(f"could not scan for BLE devices: {exc}") from exc

    devices = []
    for address, (ble_device, adv) in discovered.items():
        devices.append(
            BtDevice(
                address=address,
                name=adv.local_name or ble_device.name,
                rssi=adv.rssi,
                transport="le",
                manufacturer_data=dict(adv.manufacturer_data),
            )
        )
    return devices


async def scan_classic(timeout: float = 10.0) -> list[BtDevice]:
    proc = await asyncio.create_subprocess_exec(
        "bluetoothctl",
        "--timeout",
        str(int(timeout)),
        "scan",
        "bredr",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()

    seen: dict[str, str] = {}
    for raw_line in stdout.decode(errors="replace").splitlines():
        line = _ANSI_RE.sub("", raw_line)
        match = _DEVICE_LINE_RE.search(line)
        if not match:
            continue
        tag, address, name = match.groups()
        if tag == "NEW":
            seen[address] = name
        elif tag == "DEL":
            seen.pop(address, None)

    return [
        BtDevice(address=address, name=name or None, rssi=None, transport="classic")
        for address, name in seen.items()
    ]


async def scan_all(timeout: float = 10.0) -> list[BtDevice]:
    ble_devices = await scan_ble(timeout=timeout)
    classic_devices = await scan_classic(timeout=timeout)
    return ble_devices + classic_devices
