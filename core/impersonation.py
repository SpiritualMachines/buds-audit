"""Impersonation / relay detection: correlate concurrent advertisers by
identity to catch a second physical transmitter presenting as an
already-known device (threat model Step 5 - impersonate the earbuds to the
victim's phone).

Detection is intentionally narrow: only advertisements carrying a name
(local name) are grouped, since an empty-name identity fingerprint is too
weak a signal and would false-positive against every anonymous BLE beacon
in range. Two different addresses reporting an identical (name,
manufacturer_data) fingerprint is not on its own proof of impersonation
either - BLE privacy features rotate some devices' addresses over time, so
one physical device handing off from a stale address to a new one is
expected and must not be flagged (see the phone-address-rotation finding
in this project's own live testing). What distinguishes a genuine second
transmitter is concurrency: both addresses' observation windows (first
seen -> last seen) overlap, meaning two radios were both on the air with
that identity at the same time - a single physical device cannot do that.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from bleak import BleakScanner
from bleak.exc import BleakError

from core.models import RuleFlag
from core.scanner import ScanError

CONCURRENCY_TOLERANCE_SECONDS = 2.0


@dataclass(frozen=True)
class AdvertisementSample:
    address: str
    name: str | None
    manufacturer_data: tuple[tuple[int, bytes], ...]
    rssi: int | None
    timestamp: float


async def collect_advertisements(timeout: float) -> list[AdvertisementSample]:
    """Passively record every advertisement seen during timeout seconds.

    Unlike scan_ble/BleakScanner.discover, samples are never collapsed to
    one-per-address: reconstructing whether two addresses were on the air
    at the same time requires every individual sighting, not just the
    latest one. Raises ScanError (same as core.scanner.scan_ble, and for
    the identical reason - an unavailable adapter) rather than letting
    bleak's own BleakError surface as a raw traceback.
    """
    start = time.monotonic()
    samples: list[AdvertisementSample] = []

    def _on_advertisement(device, adv) -> None:
        samples.append(
            AdvertisementSample(
                address=device.address,
                name=adv.local_name or device.name,
                manufacturer_data=tuple(sorted(adv.manufacturer_data.items())),
                rssi=adv.rssi,
                timestamp=time.monotonic() - start,
            )
        )

    try:
        async with BleakScanner(detection_callback=_on_advertisement):
            await asyncio.sleep(timeout)
    except BleakError as exc:
        raise ScanError(f"could not scan for BLE devices: {exc}") from exc

    return samples


def _identity_key(sample: AdvertisementSample) -> tuple[str, tuple] | None:
    if not sample.name:
        return None
    return sample.name, sample.manufacturer_data


def _windows_overlap(
    a: tuple[float, float], b: tuple[float, float], tolerance: float
) -> bool:
    a_start, a_end = a
    b_start, b_end = b
    return a_start <= b_end + tolerance and b_start <= a_end + tolerance


def detect_duplicate_identities(
    samples: list[AdvertisementSample],
    tolerance: float = CONCURRENCY_TOLERANCE_SECONDS,
) -> list[RuleFlag]:
    by_identity: dict[tuple[str, tuple], dict[str, list[AdvertisementSample]]] = {}

    for sample in samples:
        key = _identity_key(sample)
        if key is None:
            continue
        by_identity.setdefault(key, {}).setdefault(sample.address, []).append(sample)

    flags: list[RuleFlag] = []

    for (name, _manufacturer_data), by_address in by_identity.items():
        if len(by_address) < 2:
            continue

        windows = {
            address: (
                min(s.timestamp for s in addr_samples),
                max(s.timestamp for s in addr_samples),
            )
            for address, addr_samples in by_address.items()
        }

        addresses = sorted(windows)
        conflicting: set[str] = set()
        for i in range(len(addresses)):
            for j in range(i + 1, len(addresses)):
                a, b = addresses[i], addresses[j]
                if _windows_overlap(windows[a], windows[b], tolerance):
                    conflicting.add(a)
                    conflicting.add(b)

        if not conflicting:
            continue

        evidence_addresses = {
            address: {
                "rssi_samples": [s.rssi for s in by_address[address]],
                "first_seen": windows[address][0],
                "last_seen": windows[address][1],
            }
            for address in sorted(conflicting)
        }

        flags.append(
            RuleFlag(
                flag_id="POSSIBLE_IMPERSONATION",
                severity="HIGH",
                description=(
                    f"Identity '{name}' was advertised concurrently by "
                    f"{len(conflicting)} distinct addresses "
                    f"({', '.join(sorted(conflicting))}) - a single physical "
                    "device cannot broadcast from two addresses at once"
                ),
                cve=None,
                evidence={"name": name, "addresses": evidence_addresses},
            )
        )

    return flags
