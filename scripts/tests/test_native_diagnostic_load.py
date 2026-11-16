"""Decision controls for the single owned diagnostic-load cleanup capture."""

import copy
import functools
import re
from pathlib import Path

import pytest
from native_diagnostic_load_cases import NAME, choose_owned_branch
from native_plan import packet, payload
from protocol_capture import decode_frame, verify_capture
from verify_native_diagnostic_load import CASES, semantic

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-diagnostic-load-01"
)


def frame(identifier: int, fields: list[tuple[int, bytes]], error: int = 0) -> dict:
    """Decode a reply frame carrying the given fields.

    Parameters
    ----------
    identifier : int
        The request identifier of the reply.
    fields : list[tuple[int, bytes]]
        The field identifiers and their bytes.
    error : int
        The error code of the reply.

    Returns
    -------
    dict
        The decoded frame.
    """
    return decode_frame(
        bytes.fromhex(packet(0, identifier, payload(fields), reply=1, error=error))
    )


def info(name: bytes | None, error: int = 0) -> dict:
    """Build a file-information reply that names the file, if any.

    Parameters
    ----------
    name : bytes | None
        The file name to report, or ``None`` for no file.
    error : int
        The error code of the reply.

    Returns
    -------
    dict
        The decoded information reply.
    """
    fields = [] if name is None else [(201, name)]
    return frame(10, fields, error)


def listing(*names: bytes) -> dict:
    """Build a file-listing reply holding the given names.

    Parameters
    ----------
    *names : bytes
        The file names to list.

    Returns
    -------
    dict
        The decoded listing reply.
    """
    entries = [(200, bytes(16) + len(name).to_bytes(4, "big") + name) for name in names]
    return frame(11, entries)


class BranchTests:
    """Check that only the exact owned file can be deleted."""

    def test_positive_exact_owned_file_can_be_deleted(self) -> None:
        """The exact owned file in both replies selects the present branch."""
        assert choose_owned_branch(info(NAME), listing(NAME)) == "present", (
            "present branch"
        )

    def test_absent_file_skips_delete(self) -> None:
        """An absent file in both replies selects the absent branch."""
        assert choose_owned_branch(info(None, 1), listing()) == "absent", (
            "absent branch"
        )

    def test_wrong_name_never_deletes(self) -> None:
        """A different file name is ambiguous and is never deleted."""
        with pytest.raises(ValueError, match="ambiguous"):
            choose_owned_branch(info(b"other"), listing(NAME))

    def test_disagreement_never_deletes(self) -> None:
        """Disagreeing replies are ambiguous and are never deleted."""
        with pytest.raises(ValueError, match="ambiguous"):
            choose_owned_branch(info(NAME), listing())
        with pytest.raises(ValueError, match="ambiguous"):
            choose_owned_branch(info(None, 1), listing(NAME))

    def test_duplicate_name_never_deletes(self) -> None:
        """A repeated file name is rejected and never deleted."""
        with pytest.raises(ValueError, match=re.escape("Repeated file-list name")):
            choose_owned_branch(info(NAME), listing(NAME, NAME))


@functools.cache
def _batch_reports() -> dict:
    """Verify each cleanup-batch capture once and attach its plan path.

    Returns
    -------
    dict
        The verified reports keyed by case name.
    """
    reports = {name: verify_capture(BATCH / name) for name in CASES}
    for name, report in reports.items():
        report["_plan_path"] = BATCH / name / "plan.json"
    return reports


class SemanticTests:
    """Check the semantic verdicts for the single diagnostic-load cleanup batch."""

    def test_corpus_has_failed_seed_and_complete_cleanup(self) -> None:
        """The retained batch has a failed seed and a complete cleanup."""
        result = semantic(copy.deepcopy(_batch_reports()))
        assert result["seed_error"] == (
            "ConnectionResetError: [Errno 104] Connection reset by peer"
        ), "seed error"

    def test_failed_seed_cannot_be_relabelled_success(self) -> None:
        """A failed seed cannot be relabelled as a success."""
        reports = copy.deepcopy(_batch_reports())
        reports["seed"]["status"] = "completed"
        with pytest.raises(ValueError, match="Seed failure"):
            semantic(reports)

    def test_cleanup_cannot_target_other_file(self) -> None:
        """A cleanup reply naming another file is rejected."""
        reports = copy.deepcopy(_batch_reports())
        cleanup_frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 10
        )
        next(field for field in cleanup_frame["fields"] if field["id"] == 201)[
            "hex"
        ] = b"other".hex()
        with pytest.raises(ValueError, match="partial file identity"):
            semantic(reports)

    def test_cleanup_cannot_hide_remaining_file(self) -> None:
        """A cleanup reply that hides a remaining file is rejected."""
        reports = copy.deepcopy(_batch_reports())
        cleanup_frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 12
        )
        cleanup_frame["error"] = 0
        with pytest.raises(ValueError, match="remains"):
            semantic(reports)

    def test_cleanup_cannot_change_account_baseline(self) -> None:
        """A cleanup reply that changes the account baseline is rejected."""
        reports = copy.deepcopy(_batch_reports())
        cleanup_frame = next(
            f for f in reports["cleanup"]["frames"] if f["is_reply"] and f["id"] == 14
        )
        cleanup_frame["fields"].pop()
        with pytest.raises(ValueError, match="account enumeration"):
            semantic(reports)
