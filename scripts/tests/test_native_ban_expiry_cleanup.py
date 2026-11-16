"""Offline faults at the owned-account cleanup boundary."""

import json
import tempfile
from pathlib import Path
from unittest import mock

import native_ban_expiry_cleanup as cleanup
import pytest
from ban_expiry_support import iteration
from native_auth_cases import complement
from native_control_readiness import ORIGINAL_ACCOUNTS


def frame(identifier: int, error: int, values: dict[int, bytes]) -> dict:
    """Build one reply frame whose fields carry the hex of ``values``.

    Returns
    -------
    dict
        The frame as the decoder reports it.
    """
    return {
        "connection": "main",
        "is_reply": 1,
        "id": identifier,
        "error": error,
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
    }


def report(stage: str) -> dict:
    """Build the completed report of one cleanup stage.

    Returns
    -------
    dict
        A report whose frames answer the stage's requests.
    """
    frames = []
    for identifier, key, name, access in (
        (
            20,
            cleanup.expiry.ZERO_KEY,
            cleanup.expiry.ZERO_NAME,
            cleanup.expiry.ZERO_ACCESS,
        ),
        (
            21,
            cleanup.expiry.PROTECTED_KEY,
            cleanup.expiry.PROTECTED_NAME,
            cleanup.expiry.PROTECTED_ACCESS,
        ),
    ):
        if stage == "guard":
            frames.append(
                frame(
                    identifier,
                    0,
                    {102: name, 105: complement(key), 106: b"x", 110: access},
                )
            )
        else:
            frames.extend((
                frame(identifier, 0, {}),
                frame(
                    identifier + 2,
                    1,
                    {100: b"No account with login \xd2" + key + b"\xd3."},
                ),
            ))
    if stage == "delete":
        frames.append({
            "connection": "main",
            "is_reply": 1,
            "id": 24,
            "error": 0,
            "fields": [
                {"id": 101, "hex": value}
                for value in sorted(ORIGINAL_ACCOUNTS, reverse=True)
            ],
        })
    return {
        "status": "completed",
        "completed_actions": len(cleanup.steps(stage)),
        "frames": frames,
    }


class CleanupTests:
    """Offline faults at the owned-account cleanup boundary."""

    def test_produced_plans_touch_only_owned_keys(self) -> None:
        """The produced guard and delete plans send only the owned keys."""
        for stage, opcode in (("guard", 352), ("delete", 351)):
            with iteration(stage):
                plan = cleanup.make_plan(
                    stage,
                    {
                        "fixture_profile": "control-only",
                        "full_file_baseline": "not_exercised",
                    },
                    "a" * 64,
                    None,
                )
                assert plan["endpoints"]["control"]["port"] == 15800, "control port"
                sends = [
                    bytes.fromhex(s["hex"]) for s in plan["steps"] if s["op"] == "send"
                ]
                assert (
                    sum(int.from_bytes(raw[2:4], "big") == opcode for raw in sends) == 2
                ), "owned-key sends differ"
                assert not any(b"fixture-low" in raw for raw in sends), "foreign key"

    def test_guard_rejects_wrong_name_key_access_and_status(self) -> None:
        """The guard stage rejects a wrong name, key, access or status."""
        cleanup.semantic(report("guard"), "guard")
        for field_id in (102, 105, 110):
            with iteration(field_id):
                broken = report("guard")
                next(f for f in broken["frames"][0]["fields"] if f["id"] == field_id)[
                    "hex"
                ] = "00"
                with pytest.raises(ValueError, match="Owned account readback differs"):
                    cleanup.semantic(broken, "guard")
        broken = report("guard")
        broken["status"] = "failed"
        with pytest.raises(ValueError, match="incomplete"):
            cleanup.semantic(broken, "guard")

    def test_delete_requires_missing_proof_and_original_enumeration(self) -> None:
        """The delete stage needs both missing proofs and the original enumeration."""
        cleanup.semantic(report("delete"), "delete")
        for identifier in (22, 23):
            with iteration(identifier):
                broken = report("delete")
                next(f for f in broken["frames"] if f["id"] == identifier)["error"] = 0
                with pytest.raises(ValueError, match="readback"):
                    cleanup.semantic(broken, "delete")
        broken = report("delete")
        broken["frames"][-1]["fields"].pop()
        with pytest.raises(ValueError, match="two-account"):
            cleanup.semantic(broken, "delete")

    def test_deletion_generation_fails_closed_without_accepted_guard(self) -> None:
        """Deletion is generated only from an accepted guard, and never otherwise."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = {
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            }
            runtime, guard = root / "runtime.json", root / "guard"
            runtime.write_text(json.dumps(env))
            guard.mkdir()
            (guard / "plan.json").write_text(
                json.dumps(cleanup.make_plan("guard", env, "a" * 64, None))
            )
            (guard / "report.json").write_text("{}")
            with (
                mock.patch.object(cleanup, "accepted_post", return_value="a" * 64),
                mock.patch.object(
                    cleanup, "verify_capture", return_value=report("guard")
                ),
            ):
                cleanup.prepare(
                    "delete",
                    cleanup.Locations(root / "post", runtime, root / "delete", guard),
                )
            assert (root / "delete/plan.json").is_file(), "delete plan not written"
            broken = report("guard")
            broken["frames"][0]["fields"][0]["hex"] = "00"
            with (
                mock.patch.object(cleanup, "accepted_post", return_value="a" * 64),
                mock.patch.object(cleanup, "verify_capture", return_value=broken),
                pytest.raises(ValueError, match="readback"),
            ):
                cleanup.prepare(
                    "delete",
                    cleanup.Locations(root / "post", runtime, root / "blocked", guard),
                )
            assert not (root / "blocked").exists(), "blocked stage wrote output"
