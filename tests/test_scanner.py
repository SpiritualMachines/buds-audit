"""Unit tests for scan error handling (core/scanner.py).

Real scanning needs live BLE hardware and isn't covered here - only that a
BleakError from bleak's own scanner is turned into the project's own
ScanError rather than surfacing as a raw traceback. Confirmed live against
an actually-powered-off adapter (BleakScanner.discover raises
BleakBluetoothNotAvailableError, a BleakError subclass, instead of
returning no results); this test locks in the wrapping behavior without
needing to touch real hardware to re-check it every time.
"""

import asyncio

import pytest
from bleak.exc import BleakError

from core.scanner import ScanError, scan_ble


def test_scan_ble_wraps_bleak_error_as_scan_error(monkeypatch):
    async def _raise(*args, **kwargs):
        raise BleakError("adapter not available")

    monkeypatch.setattr("core.scanner.BleakScanner.discover", _raise)

    with pytest.raises(ScanError):
        asyncio.run(scan_ble(timeout=1.0))
