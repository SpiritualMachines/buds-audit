"""Unit tests for the reject-all BlueZ pairing agent.

Actual D-Bus registration (no_pairing_agent) needs a live system bus and
BlueZ, and isn't covered here - only that every request the agent
implementation can receive is refused, and notifications are accepted
silently.
"""

import pytest
from dbus_fast import DBusError

from core.agent import REJECTED, _RejectAllAgent


@pytest.fixture
def agent() -> _RejectAllAgent:
    return _RejectAllAgent()


def test_request_pin_code_rejected(agent):
    with pytest.raises(DBusError) as exc_info:
        agent.RequestPinCode("/org/bluez/hci0/dev_00_00_00_00_00_00")
    assert exc_info.value.type == REJECTED


def test_display_pin_code_rejected(agent):
    with pytest.raises(DBusError):
        agent.DisplayPinCode("/org/bluez/hci0/dev_00_00_00_00_00_00", "123456")


def test_request_passkey_rejected(agent):
    with pytest.raises(DBusError):
        agent.RequestPasskey("/org/bluez/hci0/dev_00_00_00_00_00_00")


def test_display_passkey_rejected(agent):
    with pytest.raises(DBusError):
        agent.DisplayPasskey("/org/bluez/hci0/dev_00_00_00_00_00_00", 123456, 0)


def test_request_confirmation_rejected(agent):
    with pytest.raises(DBusError):
        agent.RequestConfirmation("/org/bluez/hci0/dev_00_00_00_00_00_00", 123456)


def test_request_authorization_rejected(agent):
    with pytest.raises(DBusError):
        agent.RequestAuthorization("/org/bluez/hci0/dev_00_00_00_00_00_00")


def test_authorize_service_rejected(agent):
    with pytest.raises(DBusError):
        agent.AuthorizeService(
            "/org/bluez/hci0/dev_00_00_00_00_00_00",
            "0000fef3-0000-1000-8000-00805f9b34fb",
        )


def test_release_does_not_raise(agent):
    agent.Release()


def test_cancel_does_not_raise(agent):
    agent.Cancel()
