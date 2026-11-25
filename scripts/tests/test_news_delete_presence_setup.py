"""Check the preparation and cleanup of the two article deletion controls."""

import json
import typing as typ

from native_folder_cases import path
from native_news_delete_cases import (
    cleanup,
    preflight,
    publish_cleanup,
    remove_publisher,
    resume_category,
    seed,
)
from native_news_delete_specs import ROOT
from prepare_native_cases import build_plan
from prepare_native_cases_inputs import Cases, Inputs
from prepare_native_cases_table import dispatch
from protocol_capture_decode import decode_frame

if typ.TYPE_CHECKING:
    from pathlib import Path


def setup_cases() -> Cases:
    """Build the two-category presence fixture without a runtime dependency.

    Returns
    -------
    Cases
        The separately capturable setup and cleanup plans.
    """
    inputs = Inputs(
        None, None, 0, None, 0, category_exists=False, first_child=1, last_child=10
    )
    return dispatch(inputs)["news-delete-presence-setup"]()


def test_setup_reuses_scoped_historical_cases() -> None:
    """Retain the preflight, paced seeds and original cleanup controls."""
    cases = setup_cases()
    references = {
        "preflight": preflight(),
        "root": seed(),
        "cleanup": cleanup(),
        "publish": publish_cleanup(),
        "remove": remove_publisher(),
    }
    names = ("missing-id-field", "parent-four-zero")
    for name in names:
        references[f"seed-{name}"] = resume_category(name)
    assert set(cases) == {*references, "flush"}, "wrong preparation inventory"
    for name, reference in references.items():
        assert cases[name] == next(iter(reference.values())), "changed historical case"


def test_flush_reads_both_owned_categories() -> None:
    """Keep the upload, both final lists and the liveness barrier in order."""
    steps, _ = setup_cases()["flush"]
    requests = [
        decode_frame(bytes.fromhex(st["hex"]))
        for st in steps
        if st.get("connection") == "main"
        and st.get("op") == "send"
        and len(st["hex"]) >= 40
    ]
    assert [req["type"] for req in requests] == [107, 203, 371, 371, 370, 500], (
        "wrong finalization sequence"
    )
    names = ("missing-id-field", "parent-four-zero")
    assert [
        bytes.fromhex(req["fields"][0]["hex"]) for req in requests if req["type"] == 371
    ] == [path((ROOT, name.encode())) for name in names], "category paths"


def test_setup_plans_bind_only_isolated_forwards(tmp_path: Path) -> None:
    """Bind each plan to GAP-016 and its actual namespace endpoints."""
    record = tmp_path / "runtime.json"
    record.write_text(json.dumps({"runtime": "offline"}))
    available = {
        "control": {"host": "127.0.0.1", "port": 16140},
        "data": {"host": "127.0.0.1", "port": 16141},
    }
    for steps, expectation in setup_cases().values():
        plan = build_plan("news-delete-presence-setup", record, steps, expectation)
        assert plan["gap_ids"] == ["GAP-016"], "wrong gap"
        used = {step["endpoint"] for step in steps if step["op"] == "connect"}
        assert plan["endpoints"] == {key: available[key] for key in used}, (
            "wrong guest forward"
        )
