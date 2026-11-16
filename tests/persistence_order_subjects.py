"""Describe the subjects of the order tests of the persistence verifier.

Each subject is the parsed JSON of some retained files of the A46 and A48
persistence corpus and a function that runs a check on a copy of them with the
changed files written back. A capture is compared with its ``checksums.sha256``,
and the whole verifier compares every file with the manifest and ``SHA256SUMS``,
so the copy refreshes those digests first, and a fault reaches the check that
reads it. The tests replay recorded faults against these subjects; the recording
tool builds the same subjects while the earlier scripts are on ``sys.path``.
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

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-14/native-settings-persistence-01"
CAPTURE_FILES = ("plan.json", "report.json")
PHASES = (1, 2)
SOURCE_FILES = [
    f"phase{n}/plans/{name}.json"
    for n in PHASES
    for name in ("source-code-sha256", "source-hashes")
]
LEGACY_FILES = [
    "phase1/phase1/plan.json",
    "phase1/phase1/report.json",
    "phase1/plans/phase1.json",
    "baseline/a46-parent-verification.json",
]
PLANNED_FILES = [
    "phase2/phase2/plan.json",
    "phase2/phase2/report.json",
    "phase2/plans/phase2.json",
]
CONTROL_FILES = [
    f"phase{n}/{leaf}"
    for n in PHASES
    for leaf in ("readiness/plan.json", "readiness/report.json", "plans/readiness.json")
]
STORAGE_FILES = ["baseline/a41-assets.json"]
LIFECYCLE_FILES = [
    "baseline/operator-timeline.json",
    *[
        f"phase{n}/{leaf}"
        for n in PHASES
        for leaf in (
            "emulator-identity.json",
            f"phase{n}/hold-ready.json",
            f"phase{n}/report.json",
            "readiness/report.json",
            "host-ready-boot.json",
            "host-ready-readiness.json",
            "host-ready-phase.json",
            "namespace-ready-readiness.json",
            "namespace-ready-phase.json",
        )
    ],
]


def packet_files(phase: int) -> list[str]:
    """List the files that the packet pairing of one phase reads as JSON.

    Returns
    -------
    list[str]
        The corpus-relative names.
    """
    return [
        f"phase{phase}/paired-streams.json",
        f"phase{phase}/readiness/report.json",
        f"phase{phase}/phase{phase}/report.json",
    ]


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
            for name in CAPTURE_FILES
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
    root = mirror.root
    manifest = json.loads((root / "manifest.json").read_text())
    for name, record in manifest["files"].items():
        data = (root / name).read_bytes()
        record.update(bytes=len(data), sha256=sha(data))
    mirror.write_json("manifest.json", manifest)
    names = [*manifest["files"], "manifest.json"]
    text = "".join(f"{sha((root / n).read_bytes())}  {n}\n" for n in sorted(names))
    mirror.edit_bytes("SHA256SUMS", lambda _old: text.encode())


def mirrored(
    files: list[str], run: cabc.Callable[[Path], object], *, whole: bool = False
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
            changed = [n for n, value in state.items() if value != original[n]]
            for name in changed:
                mirror.write_json(name, state[name])
            if changed:
                seal_captures(mirror)
                if whole:
                    seal_manifest(mirror)
            return run(mirror.root)

    return original, call


def subjects() -> dict[str, Subject]:
    """Build every subject of the persistence verifier.

    Returns
    -------
    dict[str, tuple[dict, collections.abc.Callable]]
        Each subject, by name.
    """
    verifier = importlib.import_module("verify_native_settings_persistence")
    whole_files = sorted({
        *SOURCE_FILES,
        *LEGACY_FILES,
        *PLANNED_FILES,
        *CONTROL_FILES,
        *STORAGE_FILES,
        *LIFECYCLE_FILES,
        *packet_files(1),
        *packet_files(2),
    })
    return {
        "sources": mirrored(SOURCE_FILES, verifier.source_identity),
        "legacy": mirrored(LEGACY_FILES, verifier.legacy_report),
        "planned": mirrored(PLANNED_FILES, verifier.planned_report),
        "controls": mirrored(CONTROL_FILES, verifier.controls),
        "packets-1": mirrored(packet_files(1), lambda r: verifier.paired_packets(r, 1)),
        "packets-2": mirrored(packet_files(2), lambda r: verifier.paired_packets(r, 2)),
        "storage": mirrored(STORAGE_FILES, verifier.stopped_storage),
        "lifecycle": mirrored(LIFECYCLE_FILES, verifier.lifecycle),
        "verify": mirrored(whole_files, verifier.verify, whole=True),
    }
