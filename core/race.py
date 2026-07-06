"""RACE protocol probes: reachability (CVE-2025-20702) and passive firmware
version check for pairing-bypass assessment (CVE-2025-20701).

RACE (the Airoha SDK's debug/configuration protocol) is what actually lets an
attacker read/write device RAM and flash once reachable. The reachability
probe below answers one question only: does the RACE command channel accept
an unauthenticated command and respond, without pairing. It never issues a
memory read/write command (RACE_STORAGE_PAGE_READ/PROGRAM, GET_LINK_KEY, or
any FOTA command) - those are the attack itself and stay out of scope.

Instead it sends GetSDKInfo (RaceId.RACE_READ_SDK_VERSION), a protocol
handshake query with no RAM/flash payload, and checks only whether a valid
RACE response frame comes back - not what it contains.

The firmware check sends BuildVersion (RaceId.RACE_GET_BUILD_VERSION) and
decodes the returned build string to cross-reference against a known-patched
build in data/affected_devices.json. ERNW's own toolkit (race_toolkit.py)
only ever compares buildversion strings by exact equality against a small
hardcoded allow-list - real buildversion responses are opaque vendor build
identifiers (e.g. "mt2822x_evkMT2822_SDK_Sony-ER69_mdr14_c42sp_1" + a build
date), not semver, so there is no sound "predates fix" ordering to compute.
This module follows the same exact-match approach rather than guessing a
version-comparison scheme the protocol doesn't actually support.

GATT service/characteristic UUIDs and the RACE packet header layout below are
taken directly from the ERNW race-toolkit reference implementation
(librace/constants.py and librace/packets.py) - not guessed. The buildversion
payload offset (6-byte header + 1-byte return code before the string) comes
from race_toolkit.py's own response handling (`res[7:].decode("utf8")`).

As in core/gatt.py, bonding state is verified independently via
`bluetoothctl info <addr>` rather than trusted from bleak's own state, since
a peripheral could in principle request pairing mid-operation and have
BlueZ's default agent silently complete it.
"""

from __future__ import annotations

import asyncio
import struct

from bleak import BleakClient
from bleak.exc import BleakError

from core.gatt import is_paired
from core.models import RuleFlag

CONNECT_TIMEOUT = 10.0
RESPONSE_TIMEOUT = 3.0
CHAR_OPERATION_TIMEOUT = 5.0

# Known RACE GATT UUIDs, from ERNW race-toolkit librace/constants.py:UuidTable.
RACE_SERVICES = {
    "Airoha": {
        "service": "5052494d-2dab-0341-6972-6f6861424c45",
        "tx": "43484152-2dab-3241-6972-6f6861424c45",
        "rx": "43484152-2dab-3141-6972-6f6861424c45",
    },
    "Sony": {
        "service": "dc405470-a351-4a59-97d8-2e2e3b207fbb",
        "tx": "bfd869fa-a3f2-4c2f-bcff-3eb1ec80cead",
        "rx": "2a6b6575-faf6-418c-923f-ccd63a56d955",
    },
}

# RACE packet header, from librace/packets.py:RaceHeader ("<BBHH" = head, type, length, cmd id).
RACE_HEADER_FORMAT = "<BBHH"
RACE_HEADER_SIZE = struct.calcsize(RACE_HEADER_FORMAT)
# Response payload is prefixed with a 1-byte return code before any string content.
RACE_RESPONSE_PREAMBLE_SIZE = 1

RACE_TYPE_CMD_EXPECTS_RESPONSE = 0x5A
RACE_TYPE_RESPONSE = 0x5B
RACE_ID_READ_SDK_VERSION = 0x0301
RACE_ID_GET_BUILD_VERSION = 0x1E08


class RaceProbeError(Exception):
    """Raised when the probe could not run or its result can't be trusted."""


def _build_race_command(cmd_id: int) -> bytes:
    # Mirrors librace.packets classes like GetSDKInfo/BuildVersion: head=0x05,
    # empty payload. RacePacket.pack() sets header.length = len(payload) + 2
    # (the cmd-id field).
    return struct.pack(
        RACE_HEADER_FORMAT, 0x05, RACE_TYPE_CMD_EXPECTS_RESPONSE, 2, cmd_id
    )


def _frame_type(frame: bytes) -> int | None:
    if len(frame) < RACE_HEADER_SIZE:
        return None
    return struct.unpack(RACE_HEADER_FORMAT, frame[:RACE_HEADER_SIZE])[1]


def _decode_build_version(frame: bytes) -> str:
    payload_start = RACE_HEADER_SIZE + RACE_RESPONSE_PREAMBLE_SIZE
    return frame[payload_start:].rstrip(b"\x00").decode("utf-8", errors="replace")


def _find_race_service(client: BleakClient) -> tuple[str, dict[str, str]] | None:
    service_uuids = {service.uuid.lower() for service in client.services}
    for vendor, uuids in RACE_SERVICES.items():
        if uuids["service"] in service_uuids:
            return vendor, uuids
    return None


async def _send_race_command(
    client: BleakClient, uuids: dict[str, str], command: bytes
) -> bytes | None:
    """Write a RACE command frame and return the full raw response frame, or None."""
    # start_notify/write_gatt_char/stop_notify have no bound of their own: a
    # device that silently drops a request instead of returning an ATT error
    # can hang these indefinitely (observed live in core/gatt.py against a
    # real device - same underlying bleak/BlueZ behavior applies here).
    response = asyncio.Event()
    received: dict[str, bytes] = {}

    def _on_notify(_sender, data: bytearray) -> None:
        received["frame"] = bytes(data)
        response.set()

    try:
        await asyncio.wait_for(
            client.start_notify(uuids["rx"], _on_notify), timeout=CHAR_OPERATION_TIMEOUT
        )
        try:
            await asyncio.wait_for(
                client.write_gatt_char(uuids["tx"], command, response=True),
                timeout=CHAR_OPERATION_TIMEOUT,
            )
            try:
                await asyncio.wait_for(response.wait(), timeout=RESPONSE_TIMEOUT)
            except TimeoutError:
                pass
        finally:
            await asyncio.wait_for(
                client.stop_notify(uuids["rx"]), timeout=CHAR_OPERATION_TIMEOUT
            )
    except (BleakError, TimeoutError):
        return None

    return received.get("frame")


def _evaluate_pairing_bypass(
    matched_profile: dict | None, version: str | None
) -> list[RuleFlag]:
    if matched_profile is None:
        return []

    patched_firmware = matched_profile.get("patched_firmware")
    label = f"{matched_profile.get('brand')} {matched_profile.get('model')}"

    if version is None:
        return [
            RuleFlag(
                flag_id="CLASSIC_PAIRING_BYPASS_UNKNOWN",
                severity="MEDIUM",
                description=(
                    f"{label} is a known-affected model but its firmware "
                    "build version could not be retrieved via RACE"
                ),
                cve="CVE-2025-20701",
                evidence={"patched_firmware": patched_firmware},
            )
        ]

    if patched_firmware is not None and version == patched_firmware:
        return []

    return [
        RuleFlag(
            flag_id="CLASSIC_PAIRING_BYPASS_UNPATCHED",
            severity="HIGH",
            description=(
                f"{label} firmware build `{version}` does not match the "
                f"known-patched build `{patched_firmware}`"
                if patched_firmware
                else f"{label} firmware build `{version}` - no patch has been released"
            ),
            cve="CVE-2025-20701",
            evidence={
                "firmware_version": version,
                "patched_firmware": patched_firmware,
            },
        )
    ]


async def probe_race(
    address: str, timeout: float = CONNECT_TIMEOUT
) -> tuple[bool, list[RuleFlag]]:
    """Return (service_found, flags). A known RACE service can be present but
    not respond to an unauthenticated command - that's a materially
    different result from no RACE service existing at all, so callers get
    both rather than having "no response" collapse into "not present"."""
    if await is_paired(address):
        raise RaceProbeError(
            f"{address} is already paired; a RACE-reachability finding "
            "would be meaningless against an already-bonded device"
        )

    flags: list[RuleFlag] = []
    service_found = False

    try:
        async with BleakClient(address, timeout=timeout) as client:
            match = _find_race_service(client)
            if match is None:
                return service_found, flags

            service_found = True
            vendor, uuids = match
            frame = await _send_race_command(
                client, uuids, _build_race_command(RACE_ID_READ_SDK_VERSION)
            )
    except BleakError as exc:
        raise RaceProbeError(
            f"could not complete RACE probe against {address}: {exc}"
        ) from exc

    if await is_paired(address):
        raise RaceProbeError(
            f"{address} became paired during the probe; discarding results as untrustworthy"
        )

    if frame is not None and _frame_type(frame) == RACE_TYPE_RESPONSE:
        flags.append(
            RuleFlag(
                flag_id="RACE_EXPOSED",
                severity="HIGH",
                description=(
                    f"RACE command channel ({vendor} GATT UUIDs) accepted an "
                    "unpaired command and returned a valid response"
                ),
                cve="CVE-2025-20702",
                evidence={
                    "vendor": vendor,
                    "service_uuid": uuids["service"],
                    "tx_characteristic": uuids["tx"],
                    "rx_characteristic": uuids["rx"],
                },
            )
        )

    return service_found, flags


async def probe_firmware_version(
    address: str, matched_profile: dict | None, timeout: float = CONNECT_TIMEOUT
) -> tuple[str | None, list[RuleFlag]]:
    if await is_paired(address):
        raise RaceProbeError(
            f"{address} is already paired; a firmware-version finding "
            "would be meaningless against an already-bonded device"
        )

    version: str | None = None

    try:
        async with BleakClient(address, timeout=timeout) as client:
            match = _find_race_service(client)
            if match is not None:
                _vendor, uuids = match
                frame = await _send_race_command(
                    client, uuids, _build_race_command(RACE_ID_GET_BUILD_VERSION)
                )
                if frame is not None and _frame_type(frame) == RACE_TYPE_RESPONSE:
                    version = _decode_build_version(frame)
    except BleakError as exc:
        raise RaceProbeError(
            f"could not complete firmware check against {address}: {exc}"
        ) from exc

    if await is_paired(address):
        raise RaceProbeError(
            f"{address} became paired during the probe; discarding results as untrustworthy"
        )

    return version, _evaluate_pairing_bypass(matched_profile, version)
