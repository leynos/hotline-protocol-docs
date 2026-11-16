"""Offline controls for the capture identity of the missing-alias plan."""

import json
import tempfile
from pathlib import Path

import capture_identity
import native_missing_alias_cases as cases
import native_missing_alias_control as control
import pytest
from test_native_missing_alias import ENV


class PlanIdentityTests:
    """Check the identity that the plan records for the control modules."""

    def test_the_plan_records_the_identity_of_the_control_modules(self) -> None:
        """The source hashes hold the control's set digest and its identity record."""
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "plan"
            cases.write_plan(folder, ENV)
            hashes = json.loads((folder / "source-hashes.json").read_text())
            record = hashes[control.IDENTITY_KEY]
            assert hashes["native_missing_alias_control.py"] == record["digest"], (
                "the control's hash is not the digest of its module set"
            )
            assert [item["path"] for item in record["files"]] == [
                f"scripts/{name}" for name in control.CAPTURE_MODULES
            ], "the identity lists other modules than the declared set"
            assert capture_identity.check(record, control.CAPTURE_MODULES), (
                "the identity does not describe the live modules"
            )

    def test_a_prepared_plan_is_refused_when_a_control_module_is_altered(self) -> None:
        """A recorded module hash that differs from the live file is refused."""
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "plan"
            cases.write_plan(folder, ENV)
            path = folder / "source-hashes.json"
            hashes = json.loads(path.read_text())
            hashes[control.IDENTITY_KEY]["files"][0]["sha256"] = "0" * 64
            path.write_text(json.dumps(hashes))
            with pytest.raises(ValueError, match="source hash"):
                control.prepared(folder)
