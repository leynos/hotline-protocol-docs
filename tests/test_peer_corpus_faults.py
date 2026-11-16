"""Pin the order of the peer, Classic and mxd verifiers' checks.

The goldens observe only the retained corpora, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/peer_corpus_faults.tsv`` lists faults made in a copy of each
retained corpus, singly and in pairs, with the ending that each produced on the
scripts as they stood before they were brought to the standard (commit 8a3f8cd).
A pair of faults shows the order of the two checks: the ending is the one of the
check that runs first. The copy's ``SHA256SUMS`` is refreshed for the changed
files, so that a fault reaches the checks that follow the inventory. The
changes are described in :mod:`peer_fault_support`.
"""

import dataclasses as dc
import importlib
import os
import typing as typ
from pathlib import Path

import pytest
from mutation_support import ending, read_table
from peer_fault_support import NEVER, REPOSITORY, run_faulted

if typ.TYPE_CHECKING:
    import collections.abc as cabc

TABLE = Path(__file__).with_name("data") / "peer_corpus_faults.tsv"


@dc.dataclass(frozen=True, slots=True)
class Subject:
    """A verifier, the corpus it reads, and how many faults to record for it."""

    corpus: str
    verify: cabc.Callable[[Path], object]
    singles: int = 60
    pairs: int = 25
    link_over: int = NEVER
    needs_mothra: bool = False


def verifier(module: str, function: str = "verify") -> cabc.Callable[[Path], object]:
    """Name a verifier by its module, which is imported when it first runs.

    Returns
    -------
    collections.abc.Callable[[pathlib.Path], object]
        A function that runs ``function`` of the module on a corpus directory.
    """

    def call(root: Path) -> object:
        """Run the named function of the verifier on ``root``.

        Returns
        -------
        object
            What the verifier returned.
        """
        return getattr(importlib.import_module(module), function)(root)

    return call


def verifier_with(
    module: str, function: str, extra: cabc.Callable[[Path], Path]
) -> cabc.Callable[[Path], object]:
    """Name a verifier that takes a second path worked out from the corpus's.

    Returns
    -------
    collections.abc.Callable[[pathlib.Path], object]
        A function that runs ``function`` of the module on the corpus directory
        and the path that ``extra`` finds from it.
    """

    def call(root: Path) -> object:
        """Run the named function of the verifier on ``root`` and its companion.

        Returns
        -------
        object
            What the verifier returned.
        """
        return getattr(importlib.import_module(module), function)(root, extra(root))

    return call


def dated_directory(root: Path) -> Path:
    """Find the retained directory that holds the corpus beside its siblings.

    Returns
    -------
    pathlib.Path
        The retained directory of the same date, whose files the corpus cites.
    """
    return REPOSITORY / root.relative_to(root.parents[3]).parent


def repository_root(root: Path) -> Path:
    """Find the repository that a corpus under ``evidence/`` belongs to.

    Returns
    -------
    pathlib.Path
        The repository itself, which holds the files that the corpus cites.
    """
    return REPOSITORY


GAP = "evidence/gap-remediation"
LARGE = 5_000_000  # larger files are linked, not copied

SUBJECTS: dict[str, Subject] = {
    "classic-baseline": Subject(
        f"{GAP}/2026-11-14/classic-proxy-baseline-01",
        verifier("verify_classic_native_baseline"),
        link_over=LARGE,
    ),
    "classic-rehearsal": Subject(
        f"{GAP}/2026-11-13/classic-proxy-rehearsal-01",
        verifier("verify_classic_proxy_rehearsal"),
    ),
    "classic-roster-115": Subject(
        f"{GAP}/2026-11-14/classic-roster-subject-115-01",
        verifier("verify_classic_roster_subject_115"),
    ),
    "classic-server-name-162": Subject(
        f"{GAP}/2026-11-14/classic-server-name-162-01",
        verifier("verify_classic_server_name_162"),
    ),
    "classic-field-161": Subject(
        f"{GAP}/2026-11-14/classic-field161-01",
        verifier("verify_classic_field161_matrix"),
        needs_mothra=True,
    ),
    "mac-first-session": Subject(
        f"{GAP}/2026-11-13/mac-peer-first-session-01",
        verifier("verify_mac_peer_first_session"),
    ),
    "mac-isolated-session": Subject(
        f"{GAP}/2026-11-13/mac-peer-isolated-session-01",
        verifier("verify_mac_peer_isolated_session"),
        needs_mothra=True,
    ),
    "mxd-limits": Subject(
        f"{GAP}/2026-11-13/mxd-limits-01", verifier("verify_mxd_limits")
    ),
    "mxd-correction": Subject(
        f"{GAP}/2026-11-13/mxd-correction-01", verifier("verify_mxd_correction")
    ),
    "mxd-login-extras": Subject(
        f"{GAP}/2026-11-13/mxd-login-extras-01", verifier("verify_mxd_login_extras")
    ),
    "mxd-reconciliation": Subject(
        f"{GAP}/2026-11-13/delegated-mxd-01", verifier("verify_mxd_reconciliation")
    ),
    "mxd-classic-login": Subject(
        f"{GAP}/2026-11-13/mxd-classic-login-01",
        verifier("verify_mxd_classic_login", "verify_public"),
    ),
    "peer-tolerance": Subject(
        f"{GAP}/2026-11-13/delegated-peer-01",
        verifier_with("verify_peer_tolerance", "verify", dated_directory),
    ),
    "account-attribute": Subject(
        f"{GAP}/2026-11-13/account-attribute-01",
        verifier_with("verify_account_attribute", "verify", repository_root),
    ),
}

ROWS = read_table(TABLE) if TABLE.exists() else []


class PeerCorpusFaultTests:
    """Keep the verifiers' checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        entry = SUBJECTS[subject]
        if entry.needs_mothra and not os.environ.get("MOTHRA_ROOT"):
            pytest.skip("the verifier reads the mothra checkout; set MOTHRA_ROOT")
        corpus = REPOSITORY / entry.corpus

        def call(_state: object) -> object:
            """Make the faults in a copy of the corpus and verify the copy.

            Returns
            -------
            object
                What the verifier returned.
            """
            return run_faulted(corpus, faults, entry.verify, entry.link_over)

        assert ending(call, None) == expected, "ending differs"
