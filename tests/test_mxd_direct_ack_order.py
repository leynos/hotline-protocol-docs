"""Pin the order of the direct-reply verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
package is refused is held here. ``data/mxd_direct_ack_order.tsv`` lists faults
put into the retained package, singly and in pairs, with the ending that each
produced on ``verify`` as it stood in ``scripts/test_mxd_direct_ack.py`` at
commit ``f104c76``, before the verifier moved to ``verify_mxd_direct_ack.py``.
A pair shows the order of two checks: the ending is the one of the check that
runs first. A line with no faults records the ending of the unchanged package.

A fault names a file and a place in it. A JSON file is a tree of values, a
systemd properties file a mapping, and every other file a list of its lines, so
that the changes of ``mutation_support`` apply. The package inventories are kept
valid for every changed file, so that a fault reaches the check that it targets.

``LiveCheckoutTests`` pin the comparison with a live mxd checkout, with the Git
subprocess call replaced by a fake; their expectations were observed on the
same version of the scripts, by running these tests against it.
"""

import contextlib
import json
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the tests replace its Git call
import tempfile
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror
from mutation_support import ending, fault_state, read_table
from verify_mxd_direct_ack import FINAL, PREFIX, sha256, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

PACKAGES = Path(__file__).resolve().parents[1] / "evidence/gap-remediation/2026-11-13"
CORPUS = PACKAGES / "mxd-direct-ack-02"
PRIOR = PACKAGES / "mxd-direct-ack-01"
PRIOR_PREFIX = "evidence/gap-remediation/2026-11-13/mxd-direct-ack-01/"
TABLE = Path(__file__).with_name("data") / "mxd_direct_ack_order.tsv"
JSON_FILES = ("manifest.json",)
PROPERTY_FILES = ("unit-initial-props.txt", "unit-final-props.txt")
LINE_FILES = (
    "run-full.sh",
    "full.log",
    "source-commit-object.txt",
    "source-tree.txt",
    "source-tracked-status.txt",
    "watch-capture.jsonl",
    "c8/SHA256SUMS",
    "SHA256SUMS",
    "prior/SHA256SUMS",
)
PRIOR_NAME = "prior/manifest.json"  # the prior package's manifest, in a state
INVENTORY = "SHA256SUMS"
PRIOR_DIR = "prior/"  # the state names of the prior package's files start with this

type State = dict[str, typ.Any]


def location(name: str) -> Path:
    """Find the retained file that a state name stands for.

    Returns
    -------
    pathlib.Path
        The file, in the package or in its prior.
    """
    if name.startswith(PRIOR_DIR):
        return PRIOR / name.removeprefix(PRIOR_DIR)
    return CORPUS / name


def state_of_package() -> State:
    """Read the files that the faults may change into their fault-ready forms.

    Returns
    -------
    dict[str, typing.Any]
        JSON trees, property mappings and lists of lines, keyed by file name.
    """
    state: State = {n: json.loads((CORPUS / n).read_text()) for n in JSON_FILES}
    state[PRIOR_NAME] = json.loads((PRIOR / "manifest.json").read_text())
    for name in PROPERTY_FILES:
        text = (CORPUS / name).read_text()
        state[name] = dict(line.split("=", 1) for line in text.splitlines())
    for name in LINE_FILES:
        state[name] = location(name).read_text().split("\n")
    return state


def render(name: str, value: dict[str, typ.Any] | list[str]) -> str:
    """Write one state entry back as the text of its file.

    Returns
    -------
    str
        The file's text.
    """
    if isinstance(value, list):
        return "\n".join(value)
    if name in PROPERTY_FILES:
        return "".join(f"{key}={text}\n" for key, text in value.items())
    return json.dumps(value) + "\n"


ORIGINAL = state_of_package()


def refresh(root: Path, prefix: str, changed: cabc.Iterable[str]) -> None:
    """Rewrite the digests of changed files in a package's inventory.

    Parameters
    ----------
    root : pathlib.Path
        The package mirror.
    prefix : str
        The repository path that its inventory entries start with.
    changed : collections.abc.Iterable[str]
        The names of the files that were rewritten.
    """
    wanted = {f"{prefix}{name}" for name in changed}
    if not wanted:
        return
    inventory = root / INVENTORY
    lines = []
    for line in inventory.read_text().splitlines():
        digest, relative = line.split("  ", 1)
        if relative in wanted:
            digest = sha256(root / relative.removeprefix(prefix))
        lines.append(f"{digest}  {relative}\n")
    inventory.unlink()
    inventory.write_text("".join(lines))


@contextlib.contextmanager
def mirrored(state: State) -> cabc.Iterator[Path]:
    """Mirror the package and its prior with every changed file written back.

    Yields
    ------
    pathlib.Path
        The root of the mirrored package, which is removed afterwards.
    """
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / CORPUS.name
        prior = Path(scratch) / PRIOR.name
        root.mkdir()
        prior.mkdir()
        mirror, prior_mirror = Mirror(CORPUS, root), Mirror(PRIOR, prior)
        changed: list[str] = []
        prior_changed: list[str] = []
        for name, value in state.items():
            if value == ORIGINAL[name]:
                continue
            if name.startswith(PRIOR_DIR):
                relative = name.removeprefix(PRIOR_DIR)
                prior_mirror.thaw(relative).write_text(render(name, value))
                prior_changed.append(relative)
            else:
                mirror.thaw(name).write_text(render(name, value))
                changed.append(name)
        # An inventory that a fault changed is left as the fault made it.
        if INVENTORY not in changed:
            refresh(root, PREFIX, changed)
        if INVENTORY not in prior_changed:
            refresh(prior, PRIOR_PREFIX, prior_changed)
        yield root


def call(state: State) -> object:
    """Run ``verify`` on a mirror that holds the changed files.

    Returns
    -------
    object
        What ``verify`` returned.
    """
    with mirrored(state) as root:
        return verify(root)


ROWS = read_table(TABLE)


class MxdDirectAckOrderTests:
    """Keep the direct-reply checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        assert subject == "mxd-direct-ack", "only the direct-reply package is recorded"
        assert ending(call, fault_state(ORIGINAL, faults)) == expected, "ending differs"


FAKE_HEAD = "feedface"


class LiveCheckoutTests:
    """Pin how ``verify`` compares a live mxd checkout, with Git replaced by a fake."""

    @staticmethod
    def run_live(
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        git_says: tuple[str, str],
        changed: str | None = None,
    ) -> str:
        """Verify the package against a fake live checkout.

        Parameters
        ----------
        tmp_path : pathlib.Path
            A scratch directory that becomes the checkout.
        monkeypatch : pytest.MonkeyPatch
            Replaces the Git subprocess call.
        git_says : tuple[str, str]
            What ``git rev-parse HEAD`` prints, and what ``git status
            --porcelain`` prints.
        changed : str | None
            The name of a frozen source whose bytes differ in the checkout.

        Returns
        -------
        str
            How the check ended.
        """
        head, dirty = git_says
        hashes = json.loads((CORPUS / "manifest.json").read_text())[
            "candidate_source_hashes"
        ]
        for name in hashes:
            target = tmp_path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            source = PRIOR / "inputs/candidate" / f"{name}.txt"
            target.write_bytes(b"changed" if name == changed else source.read_bytes())

        def fake(argv: list[str], **_: object) -> str:
            """Answer the two Git commands of the check.

            Returns
            -------
            str
                The canned output, with a trailing newline.
            """
            return (head if "rev-parse" in argv else dirty) + "\n"

        monkeypatch.setattr(subprocess, "check_output", fake)
        return ending(lambda _: verify(CORPUS, tmp_path), {})

    def test_the_final_revision_with_the_frozen_sources_passes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A checkout at the final revision, clean and unchanged, ends in ok."""
        assert self.run_live(tmp_path, monkeypatch, (FINAL, "")).startswith("ok "), "ok"

    def test_another_head_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A checkout at another revision is refused."""
        end = self.run_live(tmp_path, monkeypatch, (FAKE_HEAD, ""))
        assert end == "ValueError: live mxd revision or tracked tree differs", end

    def test_a_dirty_tree_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A checkout with tracked changes is refused, whatever its head."""
        end = self.run_live(tmp_path, monkeypatch, (FINAL, " M src/lib.rs"))
        assert end == "ValueError: live mxd revision or tracked tree differs", end

    def test_a_changed_source_is_named(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A frozen source that differs in the checkout is refused by name."""
        name = next(
            iter(
                json.loads((CORPUS / "manifest.json").read_text())[
                    "candidate_source_hashes"
                ]
            )
        )
        end = self.run_live(tmp_path, monkeypatch, (FINAL, ""), changed=name)
        assert end == f"ValueError: live source differs: {name}", end
