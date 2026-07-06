"""GATT enumeration and unauthenticated-access probing (CVE-2025-20700).

Declared characteristic properties (read/write/notify/etc.) only advertise
capability, not security requirements: BLE has no over-the-air signal for
"this characteristic requires pairing." BlueZ only reports its encrypt-*/
authorize permission flags for its own local GATT server, never for a
remote peripheral being discovered as a client. The only way to know
whether a characteristic actually enforces authentication is to attempt
the operation and see whether it succeeds or is rejected.

This module therefore performs real (unpaired) reads and real notify
subscribe/unsubscribe cycles. It never attempts Write or
Write-Without-Response: that risks changing device state and is left to
the RACE reachability probe, which is scoped to reachability only.

Bonding state is verified independently via `bluetoothctl info <addr>`
rather than trusted from bleak's own state, since bleak never calls
`pair()` on our behalf but a peripheral could in principle request
pairing mid-operation and have BlueZ's default agent silently complete it.
`get_bonding_state` reads BlueZ's own D-Bus-exposed Paired/Trusted/Bonded
properties rather than `/var/lib/bluetooth`'s link-key files directly -
that directory isn't readable without root on this system, and these
properties are sufficient presence/state signals without ever touching key
material.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from bleak import BleakClient
from bleak.exc import BleakError

from core.models import RuleFlag

CONNECT_TIMEOUT = 10.0
NOTIFY_SETTLE_SECONDS = 1.0
CHAR_OPERATION_TIMEOUT = 5.0

BONDING_FIELDS = ("Paired", "Trusted", "Bonded")


class GattProbeError(Exception):
    """Raised when the probe could not run or its result can't be trusted."""


async def get_bonding_state(address: str) -> dict[str, bool]:
    proc = await asyncio.create_subprocess_exec(
        "bluetoothctl",
        "info",
        address,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    stdout, _ = await proc.communicate()

    state = {field.lower(): False for field in BONDING_FIELDS}
    for raw_line in stdout.decode(errors="replace").splitlines():
        line = raw_line.strip()
        for field in BONDING_FIELDS:
            if line.startswith(f"{field}:"):
                state[field.lower()] = line.split(":", 1)[1].strip().lower() == "yes"
    return state


async def is_paired(address: str) -> bool:
    return (await get_bonding_state(address))["paired"]


@asynccontextmanager
async def _unpaired_connection(address: str, timeout: float, action: str):
    if await is_paired(address):
        raise GattProbeError(
            f"{address} is already paired; a finding would be meaningless "
            "against an already-bonded device"
        )

    try:
        async with BleakClient(address, timeout=timeout) as client:
            yield client
    except BleakError as exc:
        raise GattProbeError(f"could not {action} against {address}: {exc}") from exc

    if await is_paired(address):
        raise GattProbeError(
            f"{address} became paired during the operation; discarding results as untrustworthy"
        )


def _make_flag(
    service_uuid: str, char_uuid: str, access: str, properties: list[str]
) -> RuleFlag:
    return RuleFlag(
        flag_id="GATT_UNAUTHENTICATED_ACCESS",
        severity="MEDIUM",
        description=(
            f"Characteristic {char_uuid} on service {service_uuid} accepted an "
            f"unpaired {access} without an authentication/encryption error"
        ),
        cve="CVE-2025-20700",
        evidence={
            "service_uuid": service_uuid,
            "characteristic_uuid": char_uuid,
            "access": access,
            "properties": properties,
        },
    )


async def _probe_characteristic(
    client: BleakClient, service_uuid: str, char
) -> list[RuleFlag]:
    # A device that silently drops an unauthenticated request (no ATT error,
    # no response) rather than rejecting it outright can otherwise hang
    # read_gatt_char/start_notify/stop_notify indefinitely, since neither
    # bleak nor BlueZ enforces its own bound on these D-Bus calls - observed
    # live against a real device. Every one is wrapped so one unresponsive
    # characteristic can't stall the rest of the probe.
    flags: list[RuleFlag] = []
    properties = list(char.properties)

    if "read" in properties:
        try:
            await asyncio.wait_for(
                client.read_gatt_char(char), timeout=CHAR_OPERATION_TIMEOUT
            )
        except (BleakError, TimeoutError):
            pass
        else:
            flags.append(_make_flag(service_uuid, char.uuid, "read", properties))

    if "notify" in properties or "indicate" in properties:
        try:
            received = asyncio.Event()

            def _on_notify(_sender, _data, _event=received) -> None:
                _event.set()

            await asyncio.wait_for(
                client.start_notify(char, _on_notify), timeout=CHAR_OPERATION_TIMEOUT
            )
            try:
                await asyncio.wait_for(received.wait(), timeout=NOTIFY_SETTLE_SECONDS)
            except TimeoutError:
                pass
            await asyncio.wait_for(
                client.stop_notify(char), timeout=CHAR_OPERATION_TIMEOUT
            )
        except (BleakError, TimeoutError):
            pass
        else:
            flags.append(_make_flag(service_uuid, char.uuid, "notify", properties))

    return flags


async def probe_gatt(address: str, timeout: float = CONNECT_TIMEOUT) -> list[RuleFlag]:
    flags: list[RuleFlag] = []

    async with _unpaired_connection(address, timeout, "complete GATT probe") as client:
        for service in client.services:
            for char in service.characteristics:
                flags.extend(await _probe_characteristic(client, service.uuid, char))

    return flags


async def enumerate_gatt_table(
    address: str, timeout: float = CONNECT_TIMEOUT
) -> list[str]:
    """Return the sorted structural GATT table (service/characteristic UUID
    pairs) with no read/notify attempts - for baseline capture, not
    authentication testing."""
    table: list[str] = []

    async with _unpaired_connection(address, timeout, "enumerate GATT table") as client:
        for service in client.services:
            for char in service.characteristics:
                table.append(f"{service.uuid}/{char.uuid}")

    return sorted(table)
