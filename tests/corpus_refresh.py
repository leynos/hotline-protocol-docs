"""Fault the JSON files of a retained corpus whose verifier hashes every file.

A corpus verifier compares each file with the manifest and with ``SHA256SUMS``
before it reads any meaning from the file, so a faulted file would always end with
the digest check. The subject built here refreshes the digest of every changed file
in the manifest and in ``SHA256SUMS`` first, so that the fault reaches the check
that reads it. The packet readers are the verifier's own.
"""

import copy
import dataclasses as dc
import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path

from corpus_mirror import Mirror

if typ.TYPE_CHECKING:
    import collections.abc as cabc

MANIFEST = "manifest.json"
SUMS = "SHA256SUMS"
DIRECTORY_KEYS = ("corpus", "directory")  # result keys that name the corpus


@dc.dataclass(frozen=True, slots=True)
class Layout:
    """How a corpus lists and holds its files.

    Attributes
    ----------
    sums_prefix : str
        What precedes each file name in a line of ``SHA256SUMS``.
    manifest_line : bool
        Whether ``SHA256SUMS`` also lists the manifest itself.
    copy_files : bool
        Whether the mirror holds copies of the files, not links to them.
    in_repository : bool
        Whether the mirror sits at the corpus's own place below a repository root,
        beside links to the corpora around it, for a verifier that reads them.
    """

    sums_prefix: str = ""
    manifest_line: bool = False
    copy_files: bool = False
    in_repository: bool = False


type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]


def lay_out(corpus: Path, base: Path) -> Path:
    """Make the directories above a corpus's mirror, with links to their other entries.

    The corpus lies at ``<root>/evidence/<group>/<date>/<name>``; the mirror is made
    at the same place below ``base``. Every entry beside the path, below
    ``evidence``, is a link to the retained one.

    Returns
    -------
    pathlib.Path
        The empty directory that is to hold the mirror.
    """
    source = corpus.parents[3]
    destination = base
    for depth, part in enumerate(corpus.relative_to(source).parts):
        if depth:
            for sibling in sorted(source.iterdir()):
                if sibling.name != part:
                    (destination / sibling.name).symlink_to(sibling)
        source, destination = source / part, destination / part
        destination.mkdir()
    return destination


def read_json_files(corpus: Path) -> State:
    """Parse every JSON file of a corpus, by corpus-relative name.

    Returns
    -------
    dict[str, typing.Any]
        The content of each file; a file that is named for JSON and is not JSON
        stays out, and so stays as it is in every mirror.
    """
    found: State = {}
    for path in sorted(corpus.rglob("*.json")):
        try:
            found[str(path.relative_to(corpus))] = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
    return found


def write_changes(mirror: Mirror, state: State, original: State) -> State:
    """Write each changed file into the mirror and refresh its digest.

    Returns
    -------
    dict[str, typing.Any]
        The manifest, with the digest of each changed file that it lists refreshed.
    """
    manifest = copy.deepcopy(state[MANIFEST])
    for name, value in state.items():
        if name != MANIFEST and value != original[name]:
            raw = json.dumps(value).encode()
            mirror.edit_bytes(name, lambda _old, new=raw: new)
            if name in manifest.get("files", {}):
                manifest["files"][name] = hashlib.sha256(raw).hexdigest()
    mirror.write_json(MANIFEST, manifest)
    return manifest


def write_sums(mirror: Mirror, manifest: State, layout: Layout) -> None:
    """Rewrite ``SHA256SUMS`` from the manifest of the mirror."""
    files = sorted(manifest.get("files", {}).items())
    if layout.manifest_line:
        own = hashlib.sha256((mirror.root / MANIFEST).read_bytes()).hexdigest()
        files = sorted([*files, (MANIFEST, own)])
    text = "".join(f"{digest}  {layout.sums_prefix}{name}\n" for name, digest in files)
    mirror.edit_bytes(SUMS, lambda _old: text.encode())


def refreshed_subject(
    corpus: Path,
    verify: cabc.Callable[[Path], object],
    layout: Layout | None = None,
) -> Subject:
    """Describe a corpus as its JSON files, and a check that runs on a faulted copy.

    Parameters
    ----------
    corpus : pathlib.Path
        The retained corpus.
    verify : collections.abc.Callable[[pathlib.Path], object]
        The corpus check, which takes the corpus directory.
    layout : Layout | None
        How the corpus lists and holds its files; the plain layout by default.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The parsed files, and a function that mirrors the corpus with the changed
        files and their refreshed digests written back, and runs ``verify`` on it.
    """
    layout = layout or Layout()
    original = read_json_files(corpus)

    def call(state: State) -> object:
        """Run ``verify`` on a mirror that holds the changed files.

        Returns
        -------
        object
            What ``verify`` returned, without the directory it was given.
        """
        with tempfile.TemporaryDirectory() as temporary:
            if layout.in_repository:
                root = lay_out(corpus, Path(temporary))
            else:
                root = Path(temporary) / corpus.name
                root.mkdir()
            mirror = Mirror(corpus, root, copy=layout.copy_files)
            manifest = write_changes(mirror, state, original)
            write_sums(mirror, manifest, layout)
            result = verify(root)
        if isinstance(result, dict):
            return {k: v for k, v in result.items() if k not in DIRECTORY_KEYS}
        return result

    return original, call
