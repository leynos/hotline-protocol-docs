"""Check the read-only news presence matrix against the retained control."""

import typing as typ

import pytest
from native_news_steps import FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE, bodies
from prepare_native_cases import build_plan, check_inputs
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import dispatch
from protocol_capture_decode import decode_frame
from script_cli import UsageError

if typ.TYPE_CHECKING:
    from pathlib import Path


def test_matrix_changes_only_the_named_field() -> None:
    """Compare each read with the successful native reference request."""
    inputs = Inputs(
        account_inventory=None,
        original_agreement=None,
        article_parent=1,
        case_name=None,
        completed_nodes=0,
        category_exists=False,
        first_child=1,
        last_child=10,
    )
    cases = dispatch(inputs)["news-read-presence"]()
    control_steps, _ = bodies()["root-first"]
    control = next(s for s in control_steps if s.get("hex", "").startswith("00000190"))
    original = decode_frame(bytes.fromhex(control["hex"]))
    expected_fields = {FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE}
    assert len(cases) == len(expected_fields) * 3, "missing news encoding"
    for field in expected_fields:
        for shape, values in (("absent", []), ("empty", [""]), ("zero", ["00000000"])):
            steps, _ = cases[f"{field}-{shape}"]
            send = next(s for s in steps if s.get("hex", "").startswith("00000190"))
            modified = decode_frame(bytes.fromhex(send["hex"]))
            assert [
                v["hex"] for v in modified["fields"] if v["id"] == field
            ] == values, "wrong field encoding"
            assert [v for v in modified["fields"] if v["id"] != field] == [
                v for v in original["fields"] if v["id"] != field
            ], "unexpected change to another field"
            assert modified["id"] == original["id"], "uncorrelated article read"
            assert (
                steps[steps.index(send) + 1 :]
                == control_steps[control_steps.index(control) + 1 :]
            ), "read must retain the reference reply and liveness checks"


def test_read_plan_targets_isolated_control_and_names_gap(tmp_path: Path) -> None:
    """Bind the suite to the namespace forward and the presence gap."""
    record = tmp_path / "runtime.json"
    record.write_text("{}")
    plan = build_plan("news-read-presence", record, [], {})
    assert plan["gap_ids"] == ["GAP-016"], "wrong gap"
    assert plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 16140}}, (
        "wrong endpoint for the isolated guest"
    )


@pytest.mark.parametrize("suite", ["news-read-presence", "news-thread-children"])
def test_article_read_requires_a_listed_parent(suite: str) -> None:
    """Reject an article ID of zero before planning either read suite."""
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
    with pytest.raises(
        UsageError,
        match=f"^{suite} requires a positive --article-parent from a captured list$",
    ):
        check_inputs(suite, inputs)
