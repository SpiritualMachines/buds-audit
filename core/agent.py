"""BlueZ pairing-agent management: refuses every pairing/authorization
request for the duration of an active probe.

BlueZ routes any pairing/authentication request to whichever agent is
currently registered as default - normally the desktop's own (KDE's
kded6/bluedevil module here; confirmed no separate agent process exists via
`ps aux`, and `busctl --system tree org.bluez` shows no agent object of our
own before this module registers one). A GATT operation against a
characteristic that requires encryption can make BlueZ route an
authentication/authorization request to that default agent, independent of
anything this tool's own Python code does or wants - confirmed live: it
surfaced as a real KDE pairing prompt while auditing this project's own
confirmed test device. Approving it would both corrupt the "unauthenticated
access" finding (a read that only succeeds because you just paired isn't
the same finding) and leave a real bond behind afterward.

This module takes over as BlueZ's default agent for the duration of one
probe and rejects everything routed to it, then hands the default back by
unregistering, so no such prompt can appear at all rather than relying on a
human to notice and reject it in time. The tradeoff: for that brief window
(bounded by the probe's own timeouts), any *unrelated* Bluetooth pairing
attempt on this machine would also be auto-rejected, since BlueZ's default
agent is system-wide, not scoped to one target device - there is no BlueZ
API to scope an agent to a single address.

org.bluez.AgentManager1's RegisterAgent/RequestDefaultAgent/UnregisterAgent
signatures were confirmed directly against this system's live BlueZ (5.86)
via `busctl --system introspect org.bluez /org/bluez`, not assumed.
org.bluez.Agent1 (the interface an agent must implement) is long-stable,
unversioned BlueZ API that has not changed across releases.
"""

from __future__ import annotations

from contextlib import asynccontextmanager

from dbus_fast import BusType, DBusError
from dbus_fast.aio import MessageBus
from dbus_fast.service import ServiceInterface, method

AGENT_PATH = "/org/buds_audit/agent"
AGENT_CAPABILITY = "NoInputNoOutput"
BLUEZ_SERVICE = "org.bluez"
BLUEZ_ROOT_PATH = "/org/bluez"
REJECTED = "org.bluez.Error.Rejected"


class AgentRegistrationError(Exception):
    """Raised when the reject-all agent could not take over as BlueZ's
    default - the probe must not proceed without it, since that would mean
    running unprotected against exactly the failure mode this exists to
    prevent."""


class _RejectAllAgent(ServiceInterface):
    """Implements org.bluez.Agent1, refusing every pairing/authorization
    request it receives. Release and Cancel are BlueZ notifying the agent,
    not requests to grant or deny, so they just return normally."""

    def __init__(self) -> None:
        super().__init__("org.bluez.Agent1")

    # No return annotation (not even "-> None") on the void methods below:
    # with `from __future__ import annotations` active, "-> None" is stored
    # as the *string* "None", which dbus-fast's annotation parser
    # ast.literal_evals into the actual None object instead of treating it
    # as "no return value" - the native introspection constructor then
    # rejects it, expecting a str. Omitting the annotation entirely leaves
    # it as inspect.Signature.empty, which dbus-fast special-cases correctly.

    @method()
    def Release(self):  # noqa: N802
        pass

    @method()
    def RequestPinCode(self, device: "o") -> "s":  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def DisplayPinCode(self, device: "o", pincode: "s"):  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def RequestPasskey(self, device: "o") -> "u":  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def DisplayPasskey(self, device: "o", passkey: "u", entered: "q"):  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def RequestConfirmation(self, device: "o", passkey: "u"):  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def RequestAuthorization(self, device: "o"):  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def AuthorizeService(self, device: "o", uuid: "s"):  # noqa: F821, N802
        raise DBusError(REJECTED, "rejected by buds-audit")

    @method()
    def Cancel(self):  # noqa: N802
        pass


@asynccontextmanager
async def no_pairing_agent():
    """Register a temporary BlueZ agent that rejects every pairing/
    authorization request for the duration of the `with` block. Restores
    whatever agent BlueZ had as default beforehand on exit (unregistering
    ours makes BlueZ fall back to the next registered agent, if any)."""
    bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
    agent = _RejectAllAgent()
    bus.export(AGENT_PATH, agent)

    try:
        introspection = await bus.introspect(BLUEZ_SERVICE, BLUEZ_ROOT_PATH)
        proxy = bus.get_proxy_object(BLUEZ_SERVICE, BLUEZ_ROOT_PATH, introspection)
        agent_manager = proxy.get_interface("org.bluez.AgentManager1")

        try:
            await agent_manager.call_register_agent(AGENT_PATH, AGENT_CAPABILITY)
            await agent_manager.call_request_default_agent(AGENT_PATH)
        except DBusError as exc:
            raise AgentRegistrationError(
                f"could not register reject-all BlueZ agent: {exc}"
            ) from exc

        try:
            yield
        finally:
            try:
                await agent_manager.call_unregister_agent(AGENT_PATH)
            except DBusError:
                pass
    finally:
        bus.unexport(AGENT_PATH, agent)
        bus.disconnect()
