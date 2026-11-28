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


def check_report(
    report: dict[str, typ.Any], comparison: dict[str, typ.Any] | None = None
) -> list[dict[str, typ.Any]]:
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

    views, retained_comparison = session_inputs()
    if comparison is None:
        comparison = retained_comparison
    with (
        mock.patch.object(module, "load", side_effect=altered_load),
        mock.patch.object(module, "verify_capture", return_value=None),
    ):
        return module.check_session(CASE, views, comparison)


@given(
    values=st.dictionaries(
        st.integers(min_value=1, max_value=65535),
        st.binary(max_size=12),
        min_size=1,
        max_size=6,
    ),
    offset=st.integers(min_value=-3, max_value=3),
    trailing=st.binary(max_size=2),
)
@example(values={1: b""}, offset=0, trailing=b"")
@settings(max_examples=40)
def test_fields_count_uniqueness_and_consumption(
    *, values: dict[int, bytes], offset: int, trailing: bytes
) -> None:
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
    generated = {
        **frame,
        "declared_field_count": len(values) + offset,
        "unconsumed_hex": trailing.hex(),
    }
    if offset or trailing:
        with pytest.raises(ValueError, match=r"^field boundaries$"):
            module.fields(generated)
    else:
        assert module.fields(generated) == values, "matching count and tail must pass"


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


@given(
    variation=st.tuples(
        st.integers(min_value=1, max_value=54),
        st.lists(
            st.tuples(
                st.integers(min_value=0, max_value=30).filter(lambda n: n != 7),
                st.sampled_from(("send", "receive")),
            ),
            max_size=4,
        ),
        st.sampled_from(("main", "guest")),
        st.sampled_from(("send", "receive")),
    )
)
@settings(max_examples=40)
def test_from_wire_fragments_and_action_boundary(
    variation: tuple[int, list[tuple[int, str]], str, str],
) -> None:
    """Only complete main send fragments for action seven decode."""
    split, noise, connection, kind = variation
    module = verifier()
    frame = next(
        e for e in retained_events()[CASE] if e["action"] == 7 and e["event"] == "send"
    )
    raw = bytes.fromhex(frame["hex"])
    pivot = min(split, len(raw) - 1)
    chunks = [
        {**frame, "hex": raw[:pivot].hex(), "connection": connection, "event": kind},
        {**frame, "hex": raw[pivot:].hex(), "connection": connection, "event": kind},
    ]
    events = [
        {**frame, "action": action, "event": event, "hex": "00"}
        for action, event in noise
    ]
    events[0:0] = chunks
    if connection == "main" and kind == "send":
        assert module.from_wire(events, 7, "send") == module.decode_frame(raw), (
            "fragment joining must preserve the decoded request"
        )
    else:
        with pytest.raises(ValueError, match=r"^action boundary$"):
            module.from_wire(events, 7, "send")


@given(
    variation=st.tuples(
        st.integers(min_value=0, max_value=65535),
        st.integers(min_value=0, max_value=65535),
        st.booleans(),
        st.booleans(),
        st.booleans(),
    )
)
@example(variation=(371, 0, False, True, True))
@example(variation=(370, 0, False, True, True))
@example(variation=(371, 1, False, True, True))
@example(variation=(371, 0, True, True, True))
@example(variation=(371, 0, False, False, True))
@example(variation=(371, 0, False, True, False))
@settings(max_examples=40)
def test_pair_requires_transaction_and_reply_flags(
    variation: tuple[int, int, bool, bool, bool],
) -> None:
    """The real pair guard accepts only a correlated transaction."""
    request_type, response_type, request_is_reply, response_is_reply, same_id = (
        variation
    )
    module = verifier()
    request = {
        "type": request_type,
        "id": 23,
        "is_reply": request_is_reply,
        "fields": [{"id": 325, "hex": "00"}],
        "declared_field_count": 1,
        "unconsumed_hex": "",
    }
    response = {
        "type": response_type,
        "id": 23 if same_id else 24,
        "is_reply": response_is_reply,
    }
    with mock.patch.object(module, "from_wire", side_effect=(request, response)):
        if (
            request_type,
            response_type,
            request_is_reply,
            response_is_reply,
            same_id,
        ) == (
            371,
            0,
            False,
            True,
            True,
        ):
            fields, reply = module.pair([], 7, 371)
            assert fields == {325: b"\x00"}, "valid request fields must survive"
            assert reply == response, "valid reply must survive"
        else:
            with pytest.raises(ValueError, match=r"^correlated reply$"):
                module.pair([], 7, 371)


@functools.cache
def retained_events() -> dict[str, list[dict[str, typ.Any]]]:
    """Load all captured event lists once for the replay property.

    Returns
    -------
    dict[str, list[dict[str, typing.Any]]]
        Event lists keyed by captured case.
    """
    return {
        folder.name: json.loads((folder / "report.json").read_text())["events"]
        for folder in (SOURCE / "captures").iterdir()
        if folder.is_dir()
    }


@pytest.mark.parametrize("case", verifier().ORDER)
@given(payload=st.binary(max_size=3))
@settings(max_examples=18, deadline=None)
def test_replay_rejects_generated_post_encodings(case: str, payload: bytes) -> None:
    """Each shape admits only its retained presence and bytes."""
    module = verifier()
    all_events = retained_events()
    target, shape = case.split("-")
    field_id = int(target)
    changed_hex = (b"\xff" + payload).hex()
    assert changed_hex != module.SHAPES[shape], "generated shape must differ"
    selected = all_events[case]
    original_from_wire = module.from_wire

    def altered_frame(
        events: list[dict[str, typ.Any]], action: int, kind: str
    ) -> dict[str, typ.Any]:
        """Change only the selected post's target field.

        Returns
        -------
        dict[str, typing.Any]
            The decoded frame with a different shape.
        """
        frame = original_from_wire(events, action, kind)
        if events is selected and (action, kind) == (9, "send"):
            frame = copy.deepcopy(frame)
            frame["fields"] = [
                item for item in frame["fields"] if item["id"] != field_id
            ]
            frame["fields"].append({"id": field_id, "hex": changed_hex})
            frame["declared_field_count"] = len(frame["fields"])
        return frame

    with (
        mock.patch.object(
            module, "check_session", side_effect=lambda name, *_: all_events[name]
        ),
        mock.patch.object(module, "from_wire", side_effect=altered_frame),
        pytest.raises(ValueError, match=r"^post encoding$"),
    ):
        module.replay()


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


@pytest.mark.parametrize("direction", ["sent_hex", "received_hex"])
def test_session_rejects_false_recorded_stream(direction: str) -> None:
    """A false stream in either direction fails against the retained packets."""
    report = json.loads((SOURCE / f"captures/{CASE}/report.json").read_text())
    report["streams"]["main"][direction] += "00"
    with pytest.raises(ValueError, match=r"^TCP stream$"):
        check_report(report)


@pytest.mark.parametrize("change", ["consumed", "received_sha256", "unread_hex"])
def test_session_rejects_false_wire_comparison(change: str) -> None:
    """The retained comparison must match both captured packet views."""
    report = json.loads((SOURCE / f"captures/{CASE}/report.json").read_text())
    comparison = copy.deepcopy(session_inputs()[1])
    if change == "consumed":
        comparison["consumed"] += 1
    else:
        comparison["views"]["loopback"][change] = "00"
    with pytest.raises(ValueError, match=r"^wire comparison$"):
        check_report(report, comparison)
