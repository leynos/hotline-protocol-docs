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
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import dispatch
from protocol_capture_decode import decode_frame

if typ.TYPE_CHECKING:
    from pathlib import Path


def test_preparation_uses_owned_categories_and_original_cleanup(tmp_path: Path) -> None:
    """Check original setup and cleanup actions, and the two scoped final lists."""
    inputs = Inputs(
        None, None, 0, None, 0, category_exists=False, first_child=1, last_child=10
    )
    cases = dispatch(inputs)["news-delete-presence-setup"]()
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
    steps, _ = cases["flush"]
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
    assert [
        bytes.fromhex(req["fields"][0]["hex"]) for req in requests if req["type"] == 371
    ] == [path((ROOT, name.encode())) for name in names], "category paths"
    record = tmp_path / "runtime.json"
    record.write_text(json.dumps({"runtime": "offline"}))
    for steps, expectation in cases.values():
        plan = build_plan("news-delete-presence-setup", record, steps, expectation)
        assert plan["gap_ids"] == ["GAP-016"], "wrong gap"
        for step in steps:
            if step["op"] == "connect":
                key = step["endpoint"]
                port = 16140 if key == "control" else 16141
                assert plan["endpoints"][key] == {"host": "127.0.0.1", "port": port}, (
                    "wrong guest forward"
                )
