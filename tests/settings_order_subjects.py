"""Describe the subjects of the order tests of the settings verifiers.

Each subject is the parsed JSON of some retained files and a function that runs a
check on a copy of them with the changed files written back. The settings corpus
hashes its raw files in ``raw/SHA256SUMS`` and in each capture's
``checksums.sha256``, so the copy refreshes those digests first, and a fault
reaches the check that reads it. The tests replay recorded faults against these
subjects; the recording tool builds the same subjects while the earlier scripts
are on ``sys.path``.
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
BUNDLE = ROOT / "evidence/gap-remediation/2026-11-13/native-settings-01"
CAPTURE_FILES = ("plan.json", "report.json")
CORPUS_CASES = ["absent", "one-byte-refuse"]  # the cases that the corpus faults reach
SEMANTIC_CASES = [
    "absent",
    "one-byte-refuse",
    "two-byte-auto",
    "duplicate-refuse-auto",
    "four-byte-both",
]
CORPUS_FILES = [
    "raw/packet-reconciliation.json",
    "raw/source/a7-plan.json",
    "raw/preflight/capture/plan.json",
    "raw/preflight/capture/report.json",
    "raw/postflight/capture/plan.json",
    "raw/postflight/capture/report.json",
]


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def case_names() -> list[str]:
    """List the retained case directories.

    Returns
    -------
    list[str]
        The names, sorted.
    """
    return sorted(p.name for p in (BUNDLE / "raw/cases").iterdir() if p.is_dir())


def case_files() -> list[str]:
    """List the plan and report of every retained case, below the bundle.

    Returns
    -------
    list[str]
        The bundle-relative names.
    """
    return [
        f"raw/cases/{name}/{leaf}" for name in case_names() for leaf in CAPTURE_FILES
    ]


def replace_line(text: str, name: str, digest: str) -> str:
    """Give the line of a checksum list that names ``name`` a new digest.

    Returns
    -------
    str
        The list with only that line changed.
    """
    lines = [
        f"{digest}  {name}" if line.endswith(f"  {name}") else line
        for line in text.splitlines()
    ]
    return "".join(f"{line}\n" for line in lines)


def set_digest(mirror: Mirror, listing: str, name: str, digest: str) -> None:
    """Give one line of a checksum list of the copy a new digest."""
    mirror.edit_bytes(
        listing, lambda old: replace_line(old.decode(), name, digest).encode()
    )


def reseal(mirror: Mirror, changed: list[str]) -> None:
    """Refresh the digests of changed files in every list that holds them.

    A changed file of a capture is recorded in that capture's
    ``checksums.sha256``, and that list, like every other changed file, in
    ``raw/SHA256SUMS``, whose own digest is in the manifest. Only the lines of
    changed files are rewritten, so a bundle without faults is left as it was.

    Parameters
    ----------
    mirror : corpus_mirror.Mirror
        The copy of the bundle whose changed files are in place.
    changed : list[str]
        The bundle-relative names of the changed files.
    """
    if not changed:
        return
    root = mirror.root
    touched = list(changed)
    for name in changed:
        listing = (root / name).parent / "checksums.sha256"
        if listing.is_file() and Path(name).name in CAPTURE_FILES:
            relative = str(listing.relative_to(root))
            set_digest(
                mirror, relative, Path(name).name, sha((root / name).read_bytes())
            )
            touched.append(relative)
    for name in touched:
        relative = str(Path(name).relative_to("raw"))
        set_digest(mirror, "raw/SHA256SUMS", relative, sha((root / name).read_bytes()))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["raw_sha256sums_sha256"] = sha((root / "raw/SHA256SUMS").read_bytes())
    mirror.write_json("manifest.json", manifest)


def mirrored(files: list[str], run: cabc.Callable[[Path], object]) -> Subject:
    """Describe the bundle as some of its JSON files and a check that runs on a copy.

    Parameters
    ----------
    files : list[str]
        Bundle-relative names of the files that faults may change.
    run : collections.abc.Callable[[pathlib.Path], object]
        The check, given the root of the copy.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The parsed files, and a function that writes the changed ones into a
        resealed copy and runs ``run`` on it.
    """
    original = {name: json.loads((BUNDLE / name).read_text()) for name in files}

    def call(state: State) -> object:
        """Run the check on a resealed copy that holds the changed files.

        Returns
        -------
        object
            What the check returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            mirror = Mirror(BUNDLE, Path(temporary))
            changed = [name for name, value in state.items() if value != original[name]]
            for name in changed:
                mirror.write_json(name, state[name])
            reseal(mirror, changed)
            return run(mirror.root)

    return original, call


def semantic_subject(name: str) -> Subject:
    """Build the subject of ``semantic`` on one retained case.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The case's report and expectation, and a call of ``semantic`` on them.
    """
    verifier = importlib.import_module("verify_native_settings")
    case = BUNDLE / "raw/cases" / name
    state: State = {
        "report": json.loads((case / "report.json").read_text()),
        "expected": json.loads((case / "plan.json").read_text())["expectation"],
    }
    return state, lambda s: verifier.semantic(s["report"], s["expected"])


def cases_subject() -> Subject:
    """Build the subject of ``verify`` on the ten retained cases.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The cases' plans and reports, and a call of ``verify`` on a copy.
    """
    verifier = importlib.import_module("verify_native_settings")
    return mirrored(case_files(), lambda root: verifier.verify(root / "raw/cases"))


def corpus_subject() -> Subject:
    """Build the subject of the corpus verifier.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The corpus's plans and reports, and a call of ``verify`` on a copy.
    """
    verifier = importlib.import_module("verify_native_settings_corpus")
    files = [
        f"raw/cases/{name}/{leaf}" for name in CORPUS_CASES for leaf in CAPTURE_FILES
    ]
    return mirrored([*files, *CORPUS_FILES], verifier.verify)


def subjects() -> dict[str, Subject]:
    """Build every subject of the settings verifiers.

    Returns
    -------
    dict[str, tuple[dict, collections.abc.Callable]]
        Each subject, by name.
    """
    found = {f"semantic-{name}": semantic_subject(name) for name in SEMANTIC_CASES}
    found["cases"] = cases_subject()
    found["corpus"] = corpus_subject()
    return found
