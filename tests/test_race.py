"""Unit tests for the pure-logic parts of the RACE probes.

Connection/notify/write behaviour in core/race.py needs a live BLE peripheral
and isn't covered here - only packet framing, decoding, and UUID/version
matching logic that can be tested without hardware.
"""

import struct

from core.race import (
    RACE_HEADER_FORMAT,
    RACE_ID_GET_BUILD_VERSION,
    RACE_ID_READ_SDK_VERSION,
    RACE_TYPE_CMD_EXPECTS_RESPONSE,
    RACE_TYPE_RESPONSE,
    _build_race_command,
    _decode_build_version,
    _evaluate_pairing_bypass,
    _find_race_service,
    _frame_type,
)


class _FakeService:
    def __init__(self, uuid: str) -> None:
        self.uuid = uuid


class _FakeClient:
    def __init__(self, uuids: list[str]) -> None:
        self.services = [_FakeService(uuid) for uuid in uuids]


def test_build_race_command_matches_header_layout():
    packet = _build_race_command(RACE_ID_READ_SDK_VERSION)

    assert len(packet) == struct.calcsize(RACE_HEADER_FORMAT)
    head, race_type, length, cmd_id = struct.unpack(RACE_HEADER_FORMAT, packet)
    assert head == 0x05
    assert race_type == RACE_TYPE_CMD_EXPECTS_RESPONSE
    assert length == 2
    assert cmd_id == RACE_ID_READ_SDK_VERSION


def test_build_race_command_uses_requested_cmd_id():
    packet = _build_race_command(RACE_ID_GET_BUILD_VERSION)

    cmd_id = struct.unpack(RACE_HEADER_FORMAT, packet)[3]
    assert cmd_id == RACE_ID_GET_BUILD_VERSION


def test_find_race_service_matches_airoha_uuid_case_insensitively():
    client = _FakeClient(
        ["0000180a-0000-1000-8000-00805f9b34fb", "5052494D-2DAB-0341-6972-6F6861424C45"]
    )

    match = _find_race_service(client)

    assert match is not None
    vendor, uuids = match
    assert vendor == "Airoha"
    assert uuids["tx"] == "43484152-2dab-3241-6972-6f6861424c45"


def test_find_race_service_returns_none_when_absent():
    client = _FakeClient(["0000180a-0000-1000-8000-00805f9b34fb"])

    assert _find_race_service(client) is None


def _make_frame(race_type: int, payload: bytes) -> bytes:
    header = struct.pack(RACE_HEADER_FORMAT, 0x05, race_type, len(payload) + 2, 0x1234)
    return header + payload


def test_frame_type_reads_response_type():
    frame = _make_frame(RACE_TYPE_RESPONSE, b"\x00")

    assert _frame_type(frame) == RACE_TYPE_RESPONSE


def test_frame_type_returns_none_for_short_frame():
    assert _frame_type(b"\x05\x5b") is None


def test_decode_build_version_strips_return_code_and_padding():
    payload = b"\x00" + b"firmware-1.2.3" + b"\x00\x00\x00"
    frame = _make_frame(RACE_TYPE_RESPONSE, payload)

    assert _decode_build_version(frame) == "firmware-1.2.3"


def test_evaluate_pairing_bypass_no_flag_when_not_a_known_model():
    assert _evaluate_pairing_bypass(None, "some-build") == []


def test_evaluate_pairing_bypass_unknown_when_version_unavailable():
    profile = {"brand": "Sony", "model": "WF-1000XM3", "patched_firmware": None}

    flags = _evaluate_pairing_bypass(profile, None)

    assert len(flags) == 1
    assert flags[0].flag_id == "CLASSIC_PAIRING_BYPASS_UNKNOWN"
    assert flags[0].severity == "MEDIUM"


def test_evaluate_pairing_bypass_unpatched_when_no_patch_released():
    profile = {"brand": "Sony", "model": "WF-1000XM3", "patched_firmware": None}

    flags = _evaluate_pairing_bypass(profile, "some-build")

    assert len(flags) == 1
    assert flags[0].flag_id == "CLASSIC_PAIRING_BYPASS_UNPATCHED"
    assert flags[0].severity == "HIGH"


def test_evaluate_pairing_bypass_unpatched_when_build_does_not_match_patch():
    profile = {
        "brand": "Sony",
        "model": "WF-1000XM3",
        "patched_firmware": "fixed-build-2",
    }

    flags = _evaluate_pairing_bypass(profile, "vulnerable-build-1")

    assert len(flags) == 1
    assert flags[0].flag_id == "CLASSIC_PAIRING_BYPASS_UNPATCHED"


def test_evaluate_pairing_bypass_clean_when_build_matches_patch_exactly():
    profile = {
        "brand": "Sony",
        "model": "WF-1000XM3",
        "patched_firmware": "fixed-build-2",
    }

    flags = _evaluate_pairing_bypass(profile, "fixed-build-2")

    assert flags == []
