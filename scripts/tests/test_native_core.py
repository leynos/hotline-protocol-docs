"""Check that native fixture verification rejects semantically wrong evidence."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from native_wire_names import ACCOUNT_PASSWORD_OFFSET
from protocol_capture import verify_capture
from verify_native_core import verify

FIXTURES = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-core-01"
)
TRANSCRIPTS = 16
ID_FIELD = slice(4, 8)


@pytest.fixture
def directory(tmp_path: Path) -> Path:
    """Copy the retained native-core fixtures so a test may alter them.

    Returns
    -------
    pathlib.Path
        The writable copy.
    """
    target = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, target)
    return target


class NativeCoreTests:
    """Verify the retained observations and refuse altered copies of them."""

    def test_retained_native_observations_verify(self, directory: Path) -> None:
        """The unaltered fixtures verify, with every transcript counted."""
        assert verify(directory)["transcripts"] == TRANSCRIPTS, (
            "expected every retained transcript to verify"
        )

    def test_structurally_valid_wrong_correlation_is_rejected(
        self, directory: Path
    ) -> None:
        """A resealed reply with the wrong ID passes capture checks, not these."""
        case = directory / "early-login-and-errors"
        report = json.loads((case / "report.json").read_text())
        first = report["frames"][0]
        event = next(
            e
            for e in report["events"]
            if e["action"] == first["action"] and e["event"] == "receive"
        )
        data = bytearray.fromhex(event["hex"])
        data[ID_FIELD] = bytes(4)
        event["hex"] = data.hex()
        first["id"] = 0
        report["streams"]["main"]["received_hex"] = "".join(
            e["hex"] for e in report["events"] if e["event"] == "receive"
        )
        (case / "report.json").write_text(json.dumps(report))
        (case / "checksums.sha256").write_text(
            "".join(
                f"{hashlib.sha256((case / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ["plan.json", "report.json"]
            )
        )
        verify_capture(case)
        with pytest.raises(ValueError, match="Direct reply correlation"):
            verify(directory)

    def test_wrong_stored_password_is_rejected(self, directory: Path) -> None:
        """Flipping a bit of the stored password is detected."""
        path = directory / "fixture-account-after-update.bin"
        data = bytearray(path.read_bytes())
        data[ACCOUNT_PASSWORD_OFFSET] ^= 1
        path.write_bytes(data)
        with pytest.raises(ValueError, match="Stored nonempty password"):
            verify(directory)
