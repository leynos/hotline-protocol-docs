"""Check that version presence is the sole request difference in the fixture."""

import typing as typ

from native_login_extras_cases import HANDSHAKE_STEP_COUNT, start
from native_wire_names import FIELD_VERSION
from prepare_native_cases import build_plan
from prepare_native_cases_gaps import gap_ids
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import SUITES, dispatch
from protocol_capture_decode import decode_frame

if typ.TYPE_CHECKING:
    from pathlib import Path


SUITE = "login-version-presence"
VERSION_FIELDS = {
    "version-absent": [],
    "version-empty": [""],
    "version-one-zero": ["00"],
    "version-two-zero": ["0000"],
}


def test_version_lengths_are_explicit_and_other_login_fields_match() -> None:
    """Decode the request produced through the normal suite dispatch."""
    assert SUITE in SUITES, "suite missing from CLI"
    assert gap_ids(SUITE) == ["GAP-016"], "suite must identify GAP-016"
    inputs = Inputs(
        account_inventory=None,
        original_agreement=None,
        article_parent=0,
        case_name=None,
        completed_nodes=0,
        category_exists=False,
        first_child=1,
        last_child=10,
    )
    cases = dispatch(inputs)[SUITE]()
    assert set(cases) == set(VERSION_FIELDS), "version matrix incomplete"
    control = start(None, early=False)
    baseline = decode_frame(bytes.fromhex(control[HANDSHAKE_STEP_COUNT]["hex"]))
    for name, expected in VERSION_FIELDS.items():
        steps, expectation = cases[name]
        assert steps[:HANDSHAKE_STEP_COUNT] == control[:HANDSHAKE_STEP_COUNT], (
            f"{name} changed the handshake"
        )
        assert expectation["version_hex"] == (expected[0] if expected else None), (
            f"{name} expectation differs from the fixture"
        )
        request = decode_frame(bytes.fromhex(steps[HANDSHAKE_STEP_COUNT]["hex"]))
        assert request["type"] == baseline["type"], f"{name} changed the request type"
        fields = request["fields"]
        assert [v["hex"] for v in fields if v["id"] == FIELD_VERSION] == expected, (
            f"{name} emitted unexpected version bytes"
        )
        assert [v for v in fields if v["id"] != FIELD_VERSION] == baseline["fields"], (
            f"{name} changed another field"
        )
        assert len(request["fields"]) == request["declared_field_count"], (
            f"{name} declared the wrong field count"
        )
        assert isinstance(request["unconsumed_hex"], str), (
            f"{name} lacks a decoded remainder"
        )
        assert not request["unconsumed_hex"], f"{name} left trailing bytes"
        reply, end = steps[HANDSHAKE_STEP_COUNT + 1 :]
        assert reply["op"] == "read_frame", f"{name} must read a reply"
        assert reply["match_frame"] == {"is_reply": 1, "id": request["id"]}, (
            f"{name} must correlate the login reply"
        )
        assert end["op"] == "close", f"{name} must close after the reply"


def test_control_target_is_the_namespace_local_server_forward(tmp_path: Path) -> None:
    """Keep the capture off the fixed relay from the guest to the host."""
    record = tmp_path / "runtime.json"
    record.write_text("{}")
    plan = build_plan("login-version-presence", record, [], {})
    assert plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 16140}}, (
        "wrong namespace-local endpoint"
    )
