"""Check single-field deletion controls against the historical requests."""

import typing as typ

import pytest
from native_news_delete_cases import deletions
from prepare_native_cases import build_plan
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import dispatch
from protocol_capture_decode import decode_frame

if typ.TYPE_CHECKING:
    from pathlib import Path


@pytest.mark.parametrize(
    ("field", "source"), [(326, "missing-id-field"), (334, "parent-four-zero")]
)
@pytest.mark.parametrize(
    ("shape", "encoded"),
    [("absent", []), ("empty", [""]), ("zero", ["00000000"])],
)
def test_delete_presence_preserves_reference_and_followup(
    field: int, source: str, shape: str, encoded: list[str]
) -> None:
    """Retain the listings, eight body reads, liveness and quiet interval."""
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
    cases = dispatch(inputs)["news-delete-presence"]()
    references = deletions()
    assert len(cases) == 6, "missing deletion control"
    original, _ = references[source]
    steps, _ = cases[f"{field}-{shape}"]
    assert len(steps) == len(original), "observation count"
    for step, ref in zip(steps, original, strict=True):
        if step == ref:
            continue
        assert step["op"] == ref["op"] == "send", "changed observation"
        req = decode_frame(bytes.fromhex(step["hex"]))
        control = decode_frame(bytes.fromhex(ref["hex"]))
        assert req["type"] == control["type"] == 411, "changed transaction"
        assert req["id"] == control["id"], "changed transaction ID"
        assert [v for v in req["fields"] if v["id"] != field] == control["fields"], (
            "fixed fields"
        )
    (request,) = [
        decode_frame(bytes.fromhex(st["hex"]))
        for st in steps
        if st.get("hex", "").startswith("0000019b")
    ]
    assert [v["hex"] for v in request["fields"] if v["id"] == field] == encoded, (
        "field encoding"
    )
    assert (steps == original) == (shape == "absent"), "reference equivalence"


def test_delete_plan_uses_isolated_endpoint(tmp_path: Path) -> None:
    """Bind the GAP-016 comparison to the isolated guest forward."""
    record = tmp_path / "runtime.json"
    record.write_text("{}")
    plan = build_plan("news-delete-presence", record, [], {})
    assert plan["gap_ids"] == ["GAP-016"], "wrong gap"
    assert plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 16140}}, (
        "wrong endpoint"
    )
