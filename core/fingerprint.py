"""Airoha chipset fingerprinting from BLE manufacturer data and device identity.

An address_prefix match alone is weak: OUIs are assigned per-vendor, not
per-model, so a prefix hit only means "made by this vendor," not "this exact
model." The Airoha Company ID in manufacturer data is the stronger signal
since it comes from the chipset itself rather than administrative MAC
allocation. Both signals are combined rather than trusting either alone.
"""

from __future__ import annotations

import json
from pathlib import Path

from core.models import BtDevice

AIROHA_COMPANY_ID = 0x05D6


def load_affected_devices(path: Path) -> list[dict]:
    with path.open() as f:
        data = json.load(f)
    return data["devices"]


def has_airoha_manufacturer_id(manufacturer_data: dict[int, bytes]) -> bool:
    return AIROHA_COMPANY_ID in manufacturer_data


def normalize_prefix(address: str) -> str:
    return ":".join(address.split(":")[:3]).upper()


def match_known_device(device: BtDevice, known_devices: list[dict]) -> dict | None:
    prefix = normalize_prefix(device.address)
    for entry in known_devices:
        if entry["address_prefix"].upper() == prefix:
            return entry
    return None


def fingerprint_device(device: BtDevice, known_devices: list[dict]) -> BtDevice:
    airoha_id_present = has_airoha_manufacturer_id(device.manufacturer_data)
    match = match_known_device(device, known_devices)

    if match:
        device.matched_profile = match
        device.airoha_soc = match.get("airoha_soc")
    elif airoha_id_present:
        device.airoha_soc = "unconfirmed (Airoha Company ID present, no catalog match)"

    return device
