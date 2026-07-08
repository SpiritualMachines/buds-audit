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
from collections.abc import Callable
from contextlib import asynccontextmanager

from bleak import BleakClient
from bleak.exc import BleakError

from core.models import RuleFlag

CONNECT_TIMEOUT = 10.0
NOTIFY_SETTLE_SECONDS = 1.0
CHAR_OPERATION_TIMEOUT = 5.0
# probe_gatt bounds reconnect attempts (beyond the first connection) to
# this many - confirmed live, this device has *more than one* characteristic
# that requires pairing (not just the first one found via btmon), and even
# a reconnect attempt made specifically to recover from one of those can
# itself fail outright while BlueZ is still unwinding its own auto-pair-
# then-reject sequence in the background - trying to classify "was this
# reconnect expected or not" turned out to be too unreliable to budget
# separately (tried a two-tier budget first; a security-triggered reconnect
# failing to even establish doesn't cleanly belong to either bucket).
# Walked back down from 25 (which had briefly been tried) after live
# testing raised a real concern: each reconnect attempt forces the device
# through another failed SMP pairing negotiation (see
# _is_security_required_error), and a bigger budget means more of those per
# run - live testing saw a run immediately following a budget=25 sweep come
# back dramatically worse, and the earbuds auto-powered-off mid-sweep in a
# later run. This project doesn't have proof the retries themselves cause
# that degradation rather than just reflecting it, but until it does,
# hammering the device harder on the strength of an unproven "more retries
# can only help" assumption isn't worth it. See
# CONSECUTIVE_CONNECT_FAILURE_BAIL_OUT below for what actually handles the
# "device is genuinely gone" case now, instead of leaning on a large budget
# to eventually give up.
GATT_PROBE_MAX_RECONNECTS = 15
# Longer than buds_audit.py's INTER_PROBE_SETTLE_SECONDS on purpose: when
# reconnecting after a detected security_required trigger, BlueZ's own
# auto-pair-then-reject sequence is often still unwinding in the
# background (confirmed live via btmon: about 2.6 seconds between the
# triggering ATT error and BlueZ actually tearing down the link) even
# though this module has already proactively disconnected - reconnecting
# before that finishes on BlueZ's end can itself fail outright
# ("failed to discover services, device disconnected") rather than
# actually connect, confirmed live in back-to-back reconnect attempts.
GATT_RECONNECT_SETTLE_SECONDS = 3.5
# If a reconnect attempt fails to even establish (not a mid-sweep
# disconnect after a successful connection - _unpaired_connection itself
# raising GattProbeError) this many times in a row, stop instead of
# grinding through the rest of GATT_PROBE_MAX_RECONNECTS: confirmed live,
# each of those calls already retries its own connect step once
# internally, so this many consecutive raises represents several real
# failed connection attempts, not a fluke - a strong signal the device has
# gone out of range or powered off entirely, not just cycling through a
# security-required disconnect. Continuing to hammer a genuinely
# unreachable device for the rest of a 15-attempt budget only wastes time
# (each attempt pays up to CONNECT_TIMEOUT twice - see
# _unpaired_connection's own retry - plus GATT_RECONNECT_SETTLE_SECONDS,
# with zero terminal output before this fix, which is what made an earlier
# run look "hung" rather than just slow) and forces more radio activity
# against a device that may already be struggling.
CONSECUTIVE_CONNECT_FAILURE_BAIL_OUT = 3

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

    client = BleakClient(address, timeout=timeout)
    try:
        try:
            await client.connect()
        except (BleakError, TimeoutError):
            # One retry on the connect step specifically, not the probe body
            # below: an unpaired ("temporary") device's BlueZ D-Bus record
            # can be dropped between probes if it goes idle/stops
            # advertising in that window - confirmed live during --assess,
            # which runs several independent connect/disconnect cycles
            # back-to-back against the same address (bleak surfaces this as
            # a bare BleakError from its own device-cache check, e.g.
            # "device '<path>' not found", not a real unreachability
            # finding). A fresh scan-and-connect attempt immediately after
            # often succeeds.
            await client.connect()
        try:
            yield client
        finally:
            if client.is_connected:
                await client.disconnect()
    except (BleakError, TimeoutError) as exc:
        raise GattProbeError(f"could not {action} against {address}: {exc}") from exc

    if await is_paired(address):
        raise GattProbeError(
            f"{address} became paired during the operation; discarding results as untrustworthy"
        )


_ATT_SECURITY_ERRORS = (
    "Insufficient Authentication",
    "Insufficient Authorization",
    "Insufficient Encryption",
)


def _is_security_required_error(exc: BaseException) -> bool:
    """True if exc is an ATT-level security rejection (bleak's BleakDBusError
    surfaces these in its message as e.g. "ATT error: 0x0f (Insufficient
    Encryption)" - see bleak/exc.py:PROTOCOL_ERROR_CODES) rather than some
    other failure (a plain timeout, the device just not responding, etc).

    Confirmed live: touching a characteristic that raises this makes BlueZ
    automatically attempt SMP pairing to elevate security, which this
    project's no_pairing_agent (by design) rejects - and BlueZ then
    disconnects the *entire* connection a few seconds later, regardless of
    what else is attempted on it in the meantime. Detecting this immediately
    lets probe_gatt reconnect right away instead of gambling on how many more
    characteristics happen to squeeze in before that delayed disconnect - see
    probe_gatt's own docstring.
    """
    message = str(exc)
    return any(code in message for code in _ATT_SECURITY_ERRORS)


def _make_flag(
    service_uuid: str,
    char_uuid: str,
    access: str,
    properties: list[str],
    value: bytes | None = None,
) -> RuleFlag:
    # value is the actual bytes the unpaired read/notify already retrieved -
    # surfacing it costs nothing extra against the device (the read/notify
    # already happened) and turns "this characteristic is exposed" into
    # "and here's what it disclosed," which is the more complete finding.
    evidence = {
        "service_uuid": service_uuid,
        "characteristic_uuid": char_uuid,
        "access": access,
        "properties": properties,
    }
    if value is not None:
        evidence["value_hex"] = value.hex()

    return RuleFlag(
        flag_id="GATT_UNAUTHENTICATED_ACCESS",
        severity="MEDIUM",
        description=(
            f"Characteristic {char_uuid} on service {service_uuid} accepted an "
            f"unpaired {access} without an authentication/encryption error"
        ),
        cve="CVE-2025-20700",
        evidence=evidence,
    )


async def _probe_characteristic(
    client: BleakClient, service_uuid: str, char_uuid: str, properties: list[str]
) -> tuple[list[RuleFlag], bool]:
    # Takes char_uuid/properties rather than a bleak characteristic object:
    # probe_gatt below can reconnect mid-sweep (a fresh BleakClient, with its
    # own freshly-resolved characteristic objects), and a plain UUID string
    # is exactly what bleak's own read_gatt_char/start_notify/stop_notify
    # already accept, resolved against whichever client is passed in - no
    # need to keep a characteristic object tied to a connection that may no
    # longer exist by the time this runs.
    #
    # A device that silently drops an unauthenticated request (no ATT error,
    # no response) rather than rejecting it outright can otherwise hang
    # read_gatt_char/start_notify/stop_notify indefinitely, since neither
    # bleak nor BlueZ enforces its own bound on these D-Bus calls - observed
    # live against a real device. Every one is wrapped so one unresponsive
    # characteristic can't stall the rest of the probe.
    #
    # Returns (flags, security_required) - see _is_security_required_error
    # and probe_gatt's docstring for why the caller needs to know this
    # specifically, not just "something failed."
    flags: list[RuleFlag] = []
    security_required = False

    if "read" in properties:
        try:
            value = await asyncio.wait_for(
                client.read_gatt_char(char_uuid), timeout=CHAR_OPERATION_TIMEOUT
            )
        except (BleakError, TimeoutError) as exc:
            if _is_security_required_error(exc):
                security_required = True
        else:
            flags.append(
                _make_flag(service_uuid, char_uuid, "read", properties, bytes(value))
            )

    if "notify" in properties or "indicate" in properties:
        try:
            received = asyncio.Event()
            notified_value = bytearray()

            def _on_notify(_sender, data, _event=received, _buf=notified_value) -> None:
                _buf.extend(data)
                _event.set()

            try:
                await asyncio.wait_for(
                    client.start_notify(char_uuid, _on_notify),
                    timeout=CHAR_OPERATION_TIMEOUT,
                )
                try:
                    await asyncio.wait_for(
                        received.wait(), timeout=NOTIFY_SETTLE_SECONDS
                    )
                except TimeoutError:
                    pass
            finally:
                # Confirmed live against a real device: BlueZ appears to
                # record "this characteristic wants notifications" as soon
                # as StartNotify is called, even when the underlying CCCD
                # write is rejected (e.g. Insufficient Encryption) - and
                # automatically retries that same write on every future
                # reconnect to this device for the rest of the bluetoothd
                # process's life, before any of this tool's own commands
                # run, triggering the same failed-pairing-then-forced-
                # disconnect cycle every time (confirmed live via a
                # completely separate probe's connection, moments later,
                # going straight from MTU exchange to retrying this exact
                # write with no service discovery in between). Attempting
                # StopNotify here even after a failed StartNotify is a
                # best-effort attempt to clear that stuck intent rather
                # than poisoning every later connection in the same run.
                # Confirmed this can still cause BlueZ to disconnect the
                # whole link a few seconds later regardless - that's what
                # probe_gatt's reconnect-and-resume loop is for, and why
                # security_required is set below rather than waiting to see.
                try:
                    await asyncio.wait_for(
                        client.stop_notify(char_uuid), timeout=CHAR_OPERATION_TIMEOUT
                    )
                except (BleakError, TimeoutError):
                    pass
        except (BleakError, TimeoutError):
            # Confirmed live: a notify-enable failure on this device can
            # surface either as a clean ATT security error (caught by
            # _is_security_required_error) or as a bare TimeoutError with no
            # message content at all to match against - BlueZ's own
            # auto-pair-then-reject dance can apparently make the
            # underlying D-Bus call hang rather than returning promptly,
            # and it still disconnects the whole connection a few seconds
            # later regardless. Since there's no message to text-match on a
            # timeout, every notify/indicate failure is treated as a
            # potential trigger here, not just ones matching known security
            # error text - a few extra reconnects in the rare case one
            # wasn't actually security-related costs little (reconnects are
            # naturally bounded by the worklist size regardless), but
            # miscategorizing a real trigger as "unexpected" burns through
            # the much smaller capped budget and can silently lose most of
            # the sweep (confirmed live).
            security_required = True
        else:
            flags.append(
                _make_flag(
                    service_uuid,
                    char_uuid,
                    "notify",
                    properties,
                    bytes(notified_value) if notified_value else None,
                )
            )

    return flags, security_required


async def probe_gatt(
    address: str,
    timeout: float = CONNECT_TIMEOUT,
    on_progress: Callable[[str], None] | None = None,
) -> tuple[list[RuleFlag], int]:
    """Enumerate every service/characteristic and attempt an unpaired
    read/notify on each. Builds the full (service_uuid, char_uuid,
    properties) worklist from the first connection, then works through it
    across as many reconnects as needed (bounded by GATT_PROBE_MAX_RECONNECTS
    - see its own comment): confirmed live, a characteristic that requires
    pairing can make BlueZ tear down the whole connection a few seconds
    after it's touched (see _probe_characteristic's StopNotify comment) -
    and confirmed live, this device has more than one such characteristic,
    not just the first one found.

    Reconnects proactively the moment _probe_characteristic reports
    security_required, rather than waiting for client.is_connected to
    eventually go False: confirmed live, the actual disconnect lands a few
    seconds after the triggering characteristic, and how many more
    characteristics happen to complete in that window is pure timing luck -
    reconnecting immediately makes the sweep's completeness deterministic
    instead of depending on that race. client.is_connected is still checked
    each iteration as a backstop for a disconnect that happens for some
    other, undetected reason.

    _unpaired_connection can itself raise GattProbeError establishing a
    reconnect (not just a mid-sweep disconnect) - confirmed live, including
    when reconnecting specifically to recover from a just-detected
    security_required trigger (BlueZ can still be unwinding its own
    auto-pair-then-reject sequence in the background). Caught here and
    retried like any other reconnect, counted against the same budget;
    only re-raised if that budget runs out with nothing to show for it
    (pending is still None, meaning not even the first connection ever
    succeeded) - if earlier attempts already collected some real findings,
    those are returned rather than thrown away over a later reconnect
    failing. CONSECUTIVE_CONNECT_FAILURE_BAIL_OUT stops the sweep early,
    well before the full budget, if this keeps happening back-to-back -
    see its own comment for why that's a different situation than a
    security-triggered reconnect that actually succeeds.

    on_progress, if given, is called with a one-line status message before
    each reconnect attempt (not the first connection). Confirmed live: with
    GATT_PROBE_MAX_RECONNECTS attempts each paying up to CONNECT_TIMEOUT
    (potentially twice - see _unpaired_connection's own retry) plus
    GATT_RECONNECT_SETTLE_SECONDS, a sweep against a device that's gone
    unreachable mid-run can take several minutes with zero terminal output
    otherwise - which reads as a hang even though every individual await in
    this module is already bounded. Callers that want that visibility
    should pass e.g. `print`; the default of None keeps this module quiet
    for callers (and tests) that don't want it.

    Returns (flags, unreached_count): unreached_count is how many
    characteristics were never attempted because GATT_PROBE_MAX_RECONNECTS
    ran out first (or the sweep bailed out early on a plainly unreachable
    device) - confirmed live, a low finding count from an incomplete sweep
    is otherwise indistinguishable from a genuinely clean result, which is
    misleading; callers should report unreached_count explicitly rather
    than silently treating the flags list as the full picture."""
    flags: list[RuleFlag] = []
    pending: list[tuple[str, str, list[str]]] | None = None
    last_error: GattProbeError | None = None
    consecutive_connect_failures = 0

    for attempt in range(GATT_PROBE_MAX_RECONNECTS + 1):
        if attempt > 0:
            if on_progress:
                remaining = len(pending) if pending is not None else "?"
                on_progress(
                    f"GATT probe: reconnect attempt {attempt}/"
                    f"{GATT_PROBE_MAX_RECONNECTS} ({remaining} characteristic(s) "
                    "remaining)..."
                )
            await asyncio.sleep(GATT_RECONNECT_SETTLE_SECONDS)

        try:
            async with _unpaired_connection(
                address, timeout, "complete GATT probe"
            ) as client:
                consecutive_connect_failures = 0
                if pending is None:
                    pending = [
                        (service.uuid, char.uuid, list(char.properties))
                        for service in client.services
                        for char in service.characteristics
                    ]

                while pending and client.is_connected:
                    service_uuid, char_uuid, properties = pending[0]
                    char_flags, security_required = await _probe_characteristic(
                        client, service_uuid, char_uuid, properties
                    )
                    flags.extend(char_flags)
                    pending.pop(0)
                    if security_required:
                        break
        except GattProbeError as exc:
            last_error = exc
            consecutive_connect_failures += 1
            if consecutive_connect_failures >= CONSECUTIVE_CONNECT_FAILURE_BAIL_OUT:
                if on_progress:
                    on_progress(
                        "GATT probe: device unreachable after "
                        f"{consecutive_connect_failures} consecutive failed "
                        "reconnect attempts - stopping early rather than "
                        "exhausting the full retry budget."
                    )
                break
            continue

        if not pending:
            return flags, 0

    if pending is None:
        assert last_error is not None
        raise last_error

    return flags, len(pending)


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
