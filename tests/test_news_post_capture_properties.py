"""Check general GAP-016 post-verifier rules against generated offline records.

The pinned verifier reads retained captures. These tests import its unchanged
code and vary decoded records in memory so its boundary rules cover more than
the nine captured examples.
"""

import copy
import functools
import importlib.util
import json
import typing as typ
from pathlib import Path
from unittest import mock

import pytest
from hypothesis import example, given, settings
from hypothesis import strategies as st

if typ.TYPE_CHECKING:
    from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-24/news-post-presence-01"
CASE = "334-zero"


@functools.cache
def verifier() -> ModuleType:
    """Import the pinned as-run verifier without changing its source.

    Returns
    -------
    ModuleType
        The retained verifier module.
    """
    spec = importlib.util.spec_from_file_location(
        "news_post_properties", SOURCE / "verify.py"
    )
    assert spec is not None, "the retained verifier must load"
    assert spec.loader is not None, "the retained verifier must have a loader"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@functools.cache
def session_inputs() -> tuple[list[object], dict[str, typ.Any]]:
    """Read the retained packet views and comparison once.

    Returns
    -------
    tuple[list[object], dict[str, typing.Any]]
        The two packet views and their recorded comparison.
    """
    module = verifier()
    views = [module.read_packets(SOURCE / p) for p in ("namespace.pcap", "guest.pcap")]
    comparison = next(
        json.loads(line)
        for line in (SOURCE / "stream-comparison.jsonl").read_text().splitlines()
        if json.loads(line)["case"] == CASE
    )
    return views, comparison


def check_report(report: dict[str, typ.Any]) -> list[dict[str, typ.Any]]:
    """Run the real session verifier with one in-memory report variation.

    Returns
    -------
    list[dict[str, typing.Any]]
        The accepted event list when all session guards pass.
    """
    module = verifier()
    original_load = module.load

    def altered_load(path: str | Path) -> dict[str, typ.Any]:
        """Supply the altered report while retaining all other inputs.

        Returns
        -------
        dict[str, typing.Any]
            The selected retained or altered JSON record.
        """
        if Path(path).name == "report.json":
            return report
        return original_load(path)

    views, comparison = session_inputs()
    with (
        mock.patch.object(module, "load", side_effect=altered_load),
        mock.patch.object(module, "verify_capture", return_value=None),
    ):
        return module.check_session(CASE, views, comparison)


@given(
    st.dictionaries(
        st.integers(min_value=1, max_value=65535),
        st.binary(max_size=12),
        min_size=1,
        max_size=6,
    )
)
def test_fields_count_uniqueness_and_consumption(values: dict[int, bytes]) -> None:
    """Decoded unique fields pass; count, duplicate and trailing bytes fail."""
    module = verifier()
    frame = {
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
        "declared_field_count": len(values),
        "unconsumed_hex": "",
    }
    assert module.fields(frame) == values, "complete generated fields must decode"
    invalid = (
        {**frame, "declared_field_count": len(values) + 1},
        {
            **frame,
            "fields": [*frame["fields"], frame["fields"][0]],
            "declared_field_count": len(values) + 1,
        },
        {**frame, "unconsumed_hex": "00"},
    )
    for altered in invalid:
        with pytest.raises(ValueError, match=r"^field boundaries$"):
            module.fields(altered)


@given(request_id=st.integers(min_value=0, max_value=2**31), same=st.booleans())
@example(request_id=371, same=True)
@example(request_id=371, same=False)
def test_pair_correlates_generated_reply_ids(*, request_id: int, same: bool) -> None:
    """A reply succeeds only when its generated identifier matches."""
    module = verifier()
    request = {
        "type": 371,
        "id": request_id,
        "is_reply": False,
        "fields": [{"id": 325, "hex": "00"}],
        "declared_field_count": 1,
        "unconsumed_hex": "",
    }
    reply = {"type": 0, "id": request_id + (not same), "is_reply": True}
    with mock.patch.object(module, "from_wire", side_effect=(request, reply)):
        if same:
            fields, accepted = module.pair([], 7, 371)
            assert fields == {325: b"\x00"}, "matching request fields must decode"
            assert accepted == reply, "the matching reply must be returned"
        else:
            with pytest.raises(ValueError, match=r"^correlated reply$"):
                module.pair([], 7, 371)


@given(st.lists(st.sampled_from(("quiet", "close")), min_size=2, max_size=5))
@example(tail=["quiet", "close"])
@example(tail=["close", "quiet"])
@settings(max_examples=30, deadline=None)
def test_session_requires_final_quiet_then_close(tail: list[str]) -> None:
    """Only the final two event kinds decide the quiet-close guard."""
    source = json.loads((SOURCE / f"captures/{CASE}/report.json").read_text())
    report = copy.deepcopy(source)
    original_tail = report["events"][-2]
    report["events"][-2:] = [
        {**original_tail, "action": 15 + index, "event": kind}
        for index, kind in enumerate(tail)
    ]
    if tail[-2:] == ["quiet", "close"]:
        assert check_report(report), "the retained final ordering must pass"
    else:
        with pytest.raises(ValueError, match=r"^quiet interval$"):
            check_report(report)


@given(st.binary(min_size=1, max_size=8))
@settings(max_examples=25, deadline=None)
def test_session_rejects_generated_planned_send_changes(payload: bytes) -> None:
    """Every generated change to a planned send fails before stream checks."""
    report = json.loads((SOURCE / f"captures/{CASE}/report.json").read_text())
    sent = next(
        event
        for event in report["events"]
        if event["event"] == "send" and event["action"] == 7
    )
    assert sent["hex"] != payload.hex(), "the generated bytes must change the send"
    sent["hex"] = payload.hex()
    with pytest.raises(ValueError, match=r"^planned send$"):
        check_report(report)
