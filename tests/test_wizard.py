"""Unit tests for the interactive wizard's pure-logic pieces.

Device discovery (_wizard_pick_target) needs live BLE and isn't covered
here - only numbered-choice prompting and reading saved baselines, which
don't need hardware. Importing buds_audit doesn't need bleak either - its
top-level imports are all deferred inside the functions that need them.

_prompt_choice and _wizard_pick_baseline are async (they go through
_async_input, not plain input() - see _async_input's docstring for why:
blocking input() stalls the asyncio event loop and makes bleak miss D-Bus
signals, confirmed live). asyncio.run() drives them here instead of a
pytest-asyncio dependency, since these are simple one-shot coroutines.
"""

import asyncio
import json

import buds_audit
from buds_audit import _prompt_choice, _wizard_pick_baseline


def test_prompt_choice_valid_selection(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "2")
    assert asyncio.run(_prompt_choice(3)) == 1


def test_prompt_choice_cancel_returns_none(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _: "0")
    assert asyncio.run(_prompt_choice(3)) is None


def test_prompt_choice_reprompts_on_invalid_input(monkeypatch, capsys):
    responses = iter(["abc", "9", "2"])
    monkeypatch.setattr("builtins.input", lambda _: next(responses))

    assert asyncio.run(_prompt_choice(3)) == 1
    assert "Please enter a valid number." in capsys.readouterr().out


def test_wizard_pick_baseline_no_baselines(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(
        buds_audit, "BASELINES_PATH", tmp_path / "device_baselines.json"
    )

    assert asyncio.run(_wizard_pick_baseline()) is None
    assert "No saved baseline yet" in capsys.readouterr().out


def test_wizard_pick_baseline_single_entry_auto_selected(tmp_path, monkeypatch):
    baselines_path = tmp_path / "device_baselines.json"
    baselines_path.write_text(json.dumps({"AA:BB:CC:DD:EE:FF": {"name": "Test Buds"}}))
    monkeypatch.setattr(buds_audit, "BASELINES_PATH", baselines_path)

    assert asyncio.run(_wizard_pick_baseline()) == "AA:BB:CC:DD:EE:FF"


def test_wizard_pick_baseline_multiple_entries_prompts(tmp_path, monkeypatch):
    baselines_path = tmp_path / "device_baselines.json"
    baselines_path.write_text(
        json.dumps(
            {
                "AA:AA:AA:AA:AA:AA": {"name": "Buds One"},
                "BB:BB:BB:BB:BB:BB": {"name": "Buds Two"},
            }
        )
    )
    monkeypatch.setattr(buds_audit, "BASELINES_PATH", baselines_path)
    monkeypatch.setattr("builtins.input", lambda _: "2")

    assert asyncio.run(_wizard_pick_baseline()) == "BB:BB:BB:BB:BB:BB"
