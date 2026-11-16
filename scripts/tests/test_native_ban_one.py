"""Fault controls for the portable option-one native ban corpus."""

import contextlib
import hashlib
import json
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from verify_native_ban_one import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-ban-one-01"
)


def digest(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of a file.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def stack() -> cabc.Iterator[contextlib.ExitStack]:
    """Provide the cleanups of one test, run in reverse order when it ends.

    Yields
    ------
    contextlib.ExitStack
        The stack on which the test registers its cleanups.
    """
    with contextlib.ExitStack() as exit_stack:
        yield exit_stack


class BanOneTests:
    """Fault controls for the portable option-one native ban corpus."""

    corpus: Path

    @pytest.fixture(autouse=True)
    def copied_corpus(self, stack: contextlib.ExitStack) -> None:
        """Copy the corpus and its reference forks into a temporary mothra tree.

        Parameters
        ----------
        stack : contextlib.ExitStack
            The stack that removes the temporary tree when the test ends.
        """
        temporary = Path(tempfile.mkdtemp())
        stack.callback(shutil.rmtree, temporary)
        mothra = temporary / "mothra"
        self.corpus = mothra / "evidence/gap-remediation/2026-11-13/native-ban-one-01"
        self.corpus.parent.mkdir(parents=True)
        shutil.copytree(CORPUS, self.corpus)
        reference = (
            mothra
            / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
        )
        reference.mkdir(parents=True)
        original = (
            CORPUS.parents[3]
            / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
        )
        for suffix in ("data", "rsrc"):
            shutil.copyfile(
                original / f"mothra-race-fixture.{suffix}",
                reference / f"mothra-race-fixture.{suffix}",
            )

    def rehash(self, relative: str) -> None:
        """Recompute the manifest and the checksum list entry of one copied file.

        Parameters
        ----------
        relative : str
            The path of the file, relative to the copied corpus.
        """
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"][relative] = hashlib.sha256(
            (self.corpus / relative).read_bytes()
        ).hexdigest()
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{sha}  {name}\n" for name, sha in sorted(manifest["files"].items())
            )
        )

    def test_frozen_corpus(self) -> None:
        """The frozen corpus verifies as an option-one notice only."""
        status = verify(CORPUS)["status"]
        assert status == "verified_option_one_notice_only", "frozen status differs"

    def test_rehashed_probe_cannot_be_recast_as_completed(self) -> None:
        """A rehashed probe report that claims completion is still rejected."""
        relative = "fixture/probe-capture/report.json"
        report = json.loads((self.corpus / relative).read_text())
        report.update(status="completed", completed_actions=4, error="")
        (self.corpus / relative).write_text(json.dumps(report, indent=2) + "\n")
        checksums = self.corpus / "fixture/probe-capture/checksums.sha256"
        checksums.write_text(
            "".join(
                f"{digest(checksums.parent / name)}  {name}\n"
                for name in ("plan.json", "report.json")
            )
        )
        self.rehash(relative)
        self.rehash("fixture/probe-capture/checksums.sha256")
        with pytest.raises(ValueError, match="Probe failure was recast"):
            verify(self.corpus)

    def test_rehashed_spoofed_302_uid_fails(self) -> None:
        """A rehashed frozen 302 view with a spoofed UID is rejected."""
        relative = "fixture/ban-stream-views.json"
        views = json.loads((self.corpus / relative).read_text())
        views["namespace"]["main"]["frames"][-1]["fields"][0]["hex"] = "ffff"
        (self.corpus / relative).write_text(json.dumps(views, indent=2) + "\n")
        self.rehash(relative)
        with pytest.raises(ValueError, match="Frozen ACK/302 view differs"):
            verify(self.corpus)

    def test_rehashed_truncated_packet_fails(self) -> None:
        """A rehashed namespace capture with a truncated packet is rejected."""
        relative = "boot/lab-namespace.pcap"
        path = self.corpus / relative
        path.write_bytes(path.read_bytes()[:-1])
        self.rehash(relative)
        with pytest.raises(ValueError, match="Truncated packet bytes"):
            verify(self.corpus)
