"""Describe the subjects of the order tests of the ban-control verifier.

Each subject is the parsed JSON of some retained files of the isolated
option-two witness and a function that runs a check on a copy of them with the
changed files written back. The checks that replay a capture compare the
capture's files with its ``checksums.sha256``, and the whole verifier compares
every file with the manifest and ``SHA256SUMS``, so the copy refreshes those
digests first, and a fault reaches the check that reads it. The tests replay
recorded faults against these subjects; the recording tool builds the same
subjects while the earlier scripts are on ``sys.path``.
"""

import hashlib
import importlib
import json
import tempfile
import typing as typ
from pathlib import Path

from corpus_mirror import Mirror

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-14/native-ban-control-01"
CAPTURE_FILES = ("plan.json", "report.json")
PHASES = ["readiness", "guard", "seed", "ban", "probe"]
BASELINES = ["c35", "c45", "c50"]
CASE = "case-c56"
BOOT_FILES = [
    "boot-c53/terminal.json",
    "boot-c55/readiness.json",
    "boot-c55/host-ready-final.json",
    "boot-c55/namespace-ready-final.json",
]
CASE_FILES = [
    f"{CASE}/capture-ready.json",
    f"{CASE}/controller-launch.json",
    f"{CASE}/plans/source-hashes.json",
    *[f"{CASE}/plans/{name}.json" for name in PHASES],
    *[f"{CASE}/captures/{name}/{leaf}" for name in PHASES for leaf in CAPTURE_FILES],
]
TERMINAL_FILES = [f"{CASE}/terminal.json", f"{CASE}/cleanup-signals.json"]
FAILED_FILES = [
    f"failed-full-A7/{label}/{leaf}"
    for label in BASELINES
    for leaf in (
        "a7-capture/plan.json",
        "a7-capture/report.json",
        "a7-as-run-plan.json",
    )
]
ALL_FILES = sorted({
    *BOOT_FILES,
    *CASE_FILES,
    *TERMINAL_FILES,
    *FAILED_FILES,
    "packet-views.json",
    f"{CASE}/runtime-asrun.json",
})


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def seal_captures(mirror: Mirror) -> None:
    """Rewrite each capture's ``checksums.sha256`` to match its plan and report.

    Parameters
    ----------
    mirror : corpus_mirror.Mirror
        The copy of the corpus whose changed files are in place.
    """
    for listing in sorted(mirror.root.rglob("checksums.sha256")):
        directory = listing.parent
        text = "".join(
            f"{sha((directory / name).read_bytes())}  {name}\n"
            for name in ("report.json", "plan.json")
        )
        mirror.edit_bytes(
            str(listing.relative_to(mirror.root)), lambda _old, t=text: t.encode()
        )


def seal_manifest(mirror: Mirror) -> None:
    """Rewrite the manifest and ``SHA256SUMS`` to match every file they list.

    Parameters
    ----------
    mirror : corpus_mirror.Mirror
        The copy of the corpus whose changed files are in place.
    """
    manifest = json.loads((mirror.root / "manifest.json").read_text())
    for name in manifest["files"]:
        manifest["files"][name] = sha((mirror.root / name).read_bytes())
    mirror.write_json("manifest.json", manifest)
    text = "".join(
        f"{value}  {name}\n" for name, value in sorted(manifest["files"].items())
    )
    mirror.edit_bytes("SHA256SUMS", lambda _old: text.encode())


def mirrored(
    files: list[str],
    run: cabc.Callable[[Path], object],
    *,
    whole: bool = False,
) -> Subject:
    """Describe the corpus as some of its JSON files and a check that runs on a copy.

    Parameters
    ----------
    files : list[str]
        Corpus-relative names of the files that faults may change.
    run : collections.abc.Callable[[pathlib.Path], object]
        The check, given the root of the copy.
    whole : bool
        Whether to refresh the manifest and ``SHA256SUMS`` too.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The parsed files, and a function that writes the changed ones into a
        resealed copy and runs ``run`` on it.
    """
    original = {name: json.loads((CORPUS / name).read_text()) for name in files}

    def call(state: State) -> object:
        """Run the check on a resealed copy that holds the changed files.

        Returns
        -------
        object
            What the check returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            mirror = Mirror(CORPUS, Path(temporary))
            changed = [name for name, value in state.items() if value != original[name]]
            for name in changed:
                mirror.write_json(name, state[name])
            if changed:
                seal_captures(mirror)
                if whole:
                    seal_manifest(mirror)
            return run(mirror.root)

    return original, call


def module(name: str) -> types.ModuleType:
    """Import one module of the verifier.

    Returns
    -------
    types.ModuleType
        The module.
    """
    return importlib.import_module(name)


def ready_record() -> State:
    """Read the retained C55 readiness record.

    Returns
    -------
    dict[str, typing.Any]
        The record.
    """
    return json.loads((CORPUS / "boot-c55/readiness.json").read_text())


def packets_subject() -> Subject:
    """Build the subject of the packet checks.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The packet views and the phase reports, and a call of ``packets``.
    """
    verifier = module("verify_native_ban_control")
    reports = {
        name: json.loads(
            (CORPUS / CASE / "captures" / name / "report.json").read_text()
        )
        for name in PHASES
    }
    views = json.loads((CORPUS / "packet-views.json").read_text())
    state: State = {"views": views, "reports": reports}

    def call(changed: State) -> object:
        """Run ``packets`` with the changed views and reports.

        Returns
        -------
        object
            What ``packets`` returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            mirror = Mirror(CORPUS, Path(temporary))
            if changed["views"] != views:
                mirror.write_json("packet-views.json", changed["views"])
            return verifier.packets(mirror.root, changed["reports"])

    return state, call


def subjects() -> dict[str, Subject]:
    """Build every subject of the ban-control verifier.

    Returns
    -------
    dict[str, tuple[dict, collections.abc.Callable]]
        Each subject, by name.
    """
    verifier = module("verify_native_ban_control")
    ready = ready_record()
    return {
        "boot": mirrored(BOOT_FILES, verifier.boot),
        "case": mirrored(CASE_FILES, lambda root: verifier.case(root, ready)),
        "packets": packets_subject(),
        "terminal": mirrored(TERMINAL_FILES, verifier.terminal),
        "failed": mirrored(FAILED_FILES, verifier.failed_full_baselines),
        "verify": mirrored(ALL_FILES, verifier.verify, whole=True),
    }
