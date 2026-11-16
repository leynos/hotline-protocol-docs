"""Pin the order of the agreement verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The packet records are not read: the tests replace the readers and
the per-capture checks of the module with stubs, so each expectation is about
the order in which ``verify`` makes its own checks. Every expectation was
observed on the version of the scripts before the verifier was split into
``verify_native_agreement_*`` modules (commit 0b34126).

A corpus that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

import pytest
import verify_native_agreements as module

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-agreement-01"
)
FIRST_LABEL = "absent-delayed-admin"
WRONG_SHA = "0" * 64
CLEANUP_REPLY = (11, 1)


def nothing(*_args: object, **_kwargs: object) -> list[Report]:
    """Stand in for a reader or a per-capture check.

    Returns
    -------
    list[dict[str, typing.Any]]
        An empty result.
    """
    return []


def empty_result(*_args: object, **_kwargs: object) -> Report:
    """Stand in for a check that returns the case's result.

    Returns
    -------
    dict[str, typing.Any]
        An empty result.
    """
    return {}


@dc.dataclass(slots=True)
class Staged:
    """A mirror of the corpus whose files can be replaced one by one."""

    root: Path
    manifest: Report

    @classmethod
    def build(cls, root: Path) -> typ.Self:
        """Mirror the corpus with a symbolic link for each of its entries.

        Returns
        -------
        Staged
            The mirror, which ``verify`` accepts while the readers are stubs.
        """
        for child in BATCH.iterdir():
            (root / child.name).symlink_to(child)
        manifest = json.loads((BATCH / "manifest.json").read_text())
        (root / "manifest.json").unlink()
        return cls(root, manifest)

    def thaw(self, relative: str) -> Path:
        """Make one file of the mirror a real file that can be changed.

        Returns
        -------
        pathlib.Path
            The file's path in the mirror.
        """
        current = self.root
        parts = Path(relative).parts
        for part in parts[:-1]:
            current /= part
            if current.is_symlink():
                target = current.resolve()
                current.unlink()
                current.mkdir()
                for child in target.iterdir():
                    (current / child.name).symlink_to(child)
        leaf = current / parts[-1]
        if leaf.is_symlink():
            content = leaf.read_bytes()
            leaf.unlink()
            leaf.write_bytes(content)
        return leaf

    def edit(self, relative: str, change: cabc.Callable[[typ.Any], None]) -> None:
        """Change the JSON in one file of the mirror."""
        path = self.thaw(relative)
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def verify(self) -> None:
        """Verify the mirror."""
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))
        module.verify(self.root)


type Break = cabc.Callable[[Staged], None]


def another_oracle(staged: Staged) -> None:
    """Name another oracle."""
    staged.manifest["oracle_sha256"] = WRONG_SHA


def fewer_phases(staged: Staged) -> None:
    """Leave one phase out of the inventory."""
    del staged.manifest["phases"]["directory"]


def fewer_setup_cases(staged: Staged) -> None:
    """Leave one setup case out of the inventory."""
    staged.manifest["setup_cases"].pop()


def unfinished_setup(staged: Staged) -> None:
    """Record the first setup case as unfinished."""
    first = staged.manifest["setup_cases"][0]
    staged.edit(f"setup/{first}/report.json", lambda r: r.update(status="failed"))


def kept_account(staged: Staged) -> None:
    """Record that the cleanup readback found the account."""

    def change(report: Report) -> None:
        """Give the readback of the cleanup no error."""
        for frame in report["frames"]:
            if (frame["id"], frame["error"]) == CLEANUP_REPLY:
                frame["error"] = 0

    staged.edit("setup/remove-agreement-bypass-account/report.json", change)


def longer_account(staged: Staged) -> None:
    """Append a byte to the stored bypass account."""
    path = staged.thaw("native-seed/catalog-11296.data")
    path.write_bytes(path.read_bytes() + b"x")


def failed_query(staged: Staged) -> None:
    """Name another program in the first oracle query."""
    first = min(p.name for p in (BATCH / "oracle-queries").glob("*.json"))
    staged.edit(
        f"oracle-queries/{first}", lambda q: q["program"].update(sha256=WRONG_SHA)
    )


def other_plan(staged: Staged) -> None:
    """Change the steps in the first plan."""
    staged.edit(
        f"captures/{FIRST_LABEL}/plan.json", lambda p: p.update(steps=[], extra=1)
    )


def unfinished_case(staged: Staged) -> None:
    """Record the first case as unfinished."""
    staged.edit(
        f"captures/{FIRST_LABEL}/report.json", lambda r: r.update(status="failed")
    )


def not_a_directory(staged: Staged) -> None:
    """Remove the directory record from the directory phase's snapshot."""
    snapshot = staged.manifest["phases"]["directory"]["snapshot"]

    def change(extraction: Report) -> None:
        """Mark each record as a file."""
        for record in extraction["records"]:
            record["directory"] = False

    staged.edit(f"{snapshot}/extraction.json", change)


def longer_agreement(staged: Staged) -> None:
    """Append a byte to the original agreement."""
    path = staged.thaw("original-agreement.data")
    path.write_bytes(path.read_bytes() + b"x")


def other_agreement(staged: Staged) -> None:
    """Change the first byte of the original agreement."""
    path = staged.thaw("original-agreement.data")
    data = bytearray(path.read_bytes())
    data[0] ^= 1
    path.write_bytes(bytes(data))


def fewer_cases(staged: Staged) -> None:
    """Leave one case out of the inventory."""
    staged.manifest["cases"].pop()


CHAIN: list[tuple[str, str, Break]] = [
    ("oracle", "Agreement oracle identity differs", another_oracle),
    ("phases", "Agreement phase inventory differs", fewer_phases),
    ("auxiliary", "Auxiliary transcript inventory differs", fewer_setup_cases),
    ("setup", "Setup/control did not complete", unfinished_setup),
    ("cleanup", "Owned agreement account cleanup/readback differs", kept_account),
    ("account", "Native bypass account bitmap differs", longer_account),
    ("query", "Agreement oracle query failed or identity differs", failed_query),
    ("plan", "Agreement observation plan differs", other_plan),
    ("status", "Agreement observation did not complete", unfinished_case),
    ("directory", "Unreadable path lacks a positive native", not_a_directory),
    ("length", "Original agreement length differs", longer_agreement),
    ("identity", "Original agreement identity differs", other_agreement),
    ("cases", "Agreement case inventory differs", fewer_cases),
]


@pytest.fixture(autouse=True)
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the packet readers and the per-capture checks of the verifier."""
    for name in ("read_packets", "reconcile", "verify_capture", "check_quiet"):
        monkeypatch.setattr(module, name, nothing)
    for name in ("check_state", "check_overflow"):
        monkeypatch.setattr(module, name, empty_result)


class CorpusOrderTests:
    """Keep the corpus checks in the order in which they have run."""

    def test_the_retained_corpus_passes_with_the_stubs(self, tmp_path: Path) -> None:
        """A mirror of the corpus passes every check that is not stubbed."""
        staged = Staged.build(tmp_path)
        staged.verify()

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        staged = Staged.build(tmp_path)
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(staged)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            staged.verify()
