"""Pin the order of the account-batch verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_account_batch_*`` modules
(commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import native_account_batch_cases as cases
import native_account_batch_model as model
import pytest
from verify_native_account_batches import batch_result, inspect, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-account-batch-01"
)
WRONG_ACK = 1
WRONG_MASK = "ff" * 8
LIVENESS_ID = 90
BATCH_ID = 10
ADMISSION_TYPE = 354
NOTICE_TYPE = 104
CLEAR = "00"


def spec_for(case: str) -> Report:
    """Find the planned specification of a batch case.

    Returns
    -------
    dict[str, typing.Any]
        The specification.
    """
    return next(s for s in cases.specifications() if s["case"] == case)


def load(key: str) -> Report:
    """Load the report of one retained step.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``report.json``.
    """
    return json.loads((BATCH / key / "report.json").read_text())


def reply_frame(report: Report, identifier: int) -> Report:
    """Find the reply with ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return next(f for f in report["frames"] if f["is_reply"] and f["id"] == identifier)


def frames_of(report: Report, kind: int) -> list[Report]:
    """List the frames of one transaction type.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching frames.
    """
    return [f for f in report["frames"] if f["type"] == kind]


type Break = cabc.Callable[[Report], None]
type Chain = list[tuple[str, str, Break]]


def wrong_terminal(report: Report) -> None:
    """Make the terminal ACK an error."""
    reply_frame(report, BATCH_ID)["error"] = WRONG_ACK


def wrong_mask(report: Report) -> None:
    """Give the session an administrator's mask."""
    frames_of(report, ADMISSION_TYPE)[0]["fields"][0]["hex"] = WRONG_MASK


def no_notice(report: Report) -> None:
    """Remove the collision notice."""
    report["frames"].remove(frames_of(report, NOTICE_TYPE)[0])


def extra_notice(report: Report) -> None:
    """Add a notice to a batch that should have none."""
    notice = copy.deepcopy(frames_of(report, ADMISSION_TYPE)[0])
    notice["type"] = NOTICE_TYPE
    report["frames"].append(notice)


def lost_liveness(report: Report) -> None:
    """Make the liveness probe fail."""
    reply_frame(report, LIVENESS_ID)["error"] = WRONG_ACK


COLLISION: Chain = [
    ("terminal ACK", "Batch terminal ACK/error differs", wrong_terminal),
    ("admission", "Batch role admission mask differs", wrong_mask),
    ("notice", "Batch collision notice/continuation differs", no_notice),
    ("liveness", "Batch error lost control liveness", lost_liveness),
]
ORDINARY: Chain = [
    ("terminal ACK", "Batch terminal ACK/error differs", wrong_terminal),
    ("admission", "Batch role admission mask differs", wrong_mask),
    ("notice", "Unexpected per-item batch notice", extra_notice),
    ("liveness", "Batch error lost control liveness", lost_liveness),
]


def broken_report(key: str, chain: Chain, first: int) -> Report:
    """Break a retained report from check ``first`` on, last break first.

    Returns
    -------
    dict[str, typing.Any]
        The broken report.
    """
    report = load(key)
    for _label, _message, apply in reversed(chain[first:]):
        apply(report)
    return report


class BatchResultOrderTests:
    """Keep the batch-result checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(COLLISION)))
    def test_a_collision_reports_the_first_broken_check(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        report = broken_report("batch-collision-continues", COLLISION, first)
        _label, message, _apply = COLLISION[first]
        with pytest.raises(ValueError, match=message):
            batch_result(report, spec_for("collision-continues"))

    @pytest.mark.parametrize("first", range(len(ORDINARY)))
    def test_an_ordinary_batch_reports_the_first_broken_check(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        report = broken_report("batch-ordered-outer-ids", ORDINARY, first)
        _label, message, _apply = ORDINARY[first]
        with pytest.raises(ValueError, match=message):
            batch_result(report, spec_for("ordered-outer-ids"))


class InspectOrderTests:
    """Keep the inspection checks in the order in which they have always run."""

    @staticmethod
    def states() -> dict[str, model.State]:
        """Build the expected states after the first case.

        Returns
        -------
        dict[str, tuple]
            The seeded states with the first case's effects applied.
        """
        states = model.seed_states()
        model.apply(states, model.effects()["ordered-outer-ids"])
        return states

    def test_the_account_reads_precede_the_enumeration(self) -> None:
        """A wrong account state is reported before a wrong enumeration."""
        report = load("after-ordered-outer-ids")
        report["frames"][-1]["fields"] = []
        report["frames"][-1]["payload_hex"] = "0000"
        reply = reply_frame(report, 100)
        reply["error"] = 0
        with pytest.raises(ValueError, match="Expected absent batch account differs"):
            inspect(report, ["order-a", "order-b"], self.states(), [])

    def test_the_enumeration_is_checked_after_the_reads(self) -> None:
        """A wrong enumeration is reported when every account read is right."""
        report = load("after-ordered-outer-ids")
        with pytest.raises(
            ValueError, match="Batch inspection global account state differs"
        ):
            inspect(report, ["order-a", "order-b"], self.states(), ["junk"])


class CorpusOrderTests:
    """Keep the corpus-level checks in the order in which they have always run."""

    @staticmethod
    def copy_corpus(tmp_path: Path) -> Path:
        """Copy the retained corpus so that it can be broken.

        Returns
        -------
        pathlib.Path
            The copy.
        """
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        return directory

    @staticmethod
    def edit_manifest(directory: Path, **changes: object) -> None:
        """Replace keys of the manifest."""
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest.update(changes)
        path.write_text(json.dumps(manifest))

    def test_the_inventory_file_is_read_before_the_report_inventory(
        self, tmp_path: Path
    ) -> None:
        """A missing cleanup inventory is reported although the reports differ."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, reports={})
        (directory / "cleanup-inventory.json").unlink()
        with pytest.raises(FileNotFoundError, match="cleanup-inventory"):
            verify(directory)

    def test_the_report_inventory_precedes_the_packet_reads(
        self, tmp_path: Path
    ) -> None:
        """A wrong report list is reported although the host capture is missing."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, reports={})
        (directory / "host.pcap").unlink()
        with pytest.raises(ValueError, match="Batch report inventory differs"):
            verify(directory)

    def test_the_packets_are_read_before_the_recorder_count(
        self, tmp_path: Path
    ) -> None:
        """A missing guest capture is reported although the drop count is wrong."""
        directory = self.copy_corpus(tmp_path)
        (directory / "guest.pcap").unlink()
        (directory / "host-capture-statistics.txt").write_text("1 packets dropped")
        with pytest.raises(FileNotFoundError, match="guest"):
            verify(directory)

    def test_the_recorder_count_precedes_the_first_plan(self, tmp_path: Path) -> None:
        """A wrong drop count is reported although the first plan differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host-capture-statistics.txt").write_text("1 packets dropped")
        path = directory / "preflight/plan.json"
        plan = json.loads(path.read_text())
        plan["steps"] = []
        path.write_text(json.dumps(plan))
        with pytest.raises(ValueError, match="recorder count/drop differs"):
            verify(directory)

    def test_the_plan_precedes_the_capture_verification(self, tmp_path: Path) -> None:
        """A changed plan is reported before the capture's integrity is checked."""
        directory = self.copy_corpus(tmp_path)
        path = directory / "preflight/plan.json"
        plan = json.loads(path.read_text())
        plan["steps"] = []
        path.write_text(json.dumps(plan))
        with pytest.raises(ValueError, match="Batch as-run plan differs"):
            verify(directory)
