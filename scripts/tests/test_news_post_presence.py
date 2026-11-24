"""Check normal article posting cases against the native root post control."""

import typing as typ

from native_news_cases import posts
from native_news_steps import FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE
from prepare_native_cases import build_plan
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import dispatch
from protocol_capture_decode import decode_frame

if typ.TYPE_CHECKING:
    from pathlib import Path


def test_post_matrix_preserves_reference_and_brackets_each_post() -> None:
    """Check the two listings, the exact varied field, and the liveness barrier."""
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
    cases = dispatch(inputs)["news-post-presence"]()
    original, _ = next(iter(posts().values()))
    packet = next(
        step["hex"] for step in original if step.get("hex", "").startswith("0000019a")
    )
    reference = decode_frame(bytes.fromhex(packet))
    targets = (FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE)
    assert len(cases) == 3 * len(targets), "missing case"
    for field in targets:
        for encoding, expected in (
            ("absent", []),
            ("empty", [""]),
            ("zero", ["00000000"]),
        ):
            steps, _ = cases[f"{field}-{encoding}"]
            frames = [
                decode_frame(bytes.fromhex(step["hex"]))
                for step in steps
                if step["op"] == "send" and len(step["hex"]) >= 40
            ]
            assert [f["type"] for f in frames] == [107, 371, 410, 371, 500], (
                "observation sequence"
            )
            post = frames[2]
            assert (
                frames[1]["fields"] == frames[3]["fields"] == reference["fields"][:1]
            ), "category path"
            assert [v["hex"] for v in post["fields"] if v["id"] == field] == expected, (
                "field value"
            )
            assert [v for v in post["fields"] if v["id"] != field] == [
                v for v in reference["fields"] if v["id"] != field
            ], "unexpected change to another field"
            assert post["id"] == reference["id"], "post transaction ID"
            assert [s["op"] for s in steps[-2:]] == ["expect_quiet", "close"], (
                "terminal checks"
            )


def test_post_plan_targets_isolated_control_and_names_gap(tmp_path: Path) -> None:
    """Use only the fresh guest forward for the posting suite."""
    record = tmp_path / "runtime.json"
    record.write_text("{}")
    plan = build_plan("news-post-presence", record, [], {})
    assert plan["gap_ids"] == ["GAP-016"], "wrong gap"
    assert plan["endpoints"] == {"control": {"host": "127.0.0.1", "port": 16140}}, (
        "wrong endpoint for the isolated guest"
    )
