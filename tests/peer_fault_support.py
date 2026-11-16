"""Put recorded faults into a copy of a retained peer corpus and run a verifier.

The peer, mxd and Classic verifiers refuse an unsound corpus with the first
check that it fails, so the order of their checks shows only on a corpus that is
unsound in two ways at once. A fault is a file name and a change. The changes
are ``delete-file`` and ``empty-file`` for any file, and, for a JSON file, the
changes of :mod:`mutation_support` at a path of keys and indexes joined by ``>``
after the file name. The faulted copy sits beneath a directory that repeats the
corpus's path from the repository root, because several verifiers find the
repository from the corpus. Each ``SHA256SUMS`` line is refreshed for the files
that were changed, so that a fault reaches the checks that follow the
inventory.
"""

import hashlib
import json
import shutil
import tempfile
import typing as typ
from pathlib import Path

from mutation_support import PATH_SEPARATOR, Fault, fault_state

if typ.TYPE_CHECKING:
    import collections.abc as cabc

REPOSITORY = Path(__file__).resolve().parents[1]
DELETE_FILE = "delete-file"
EMPTY_FILE = "empty-file"
SUMS = "SHA256SUMS"
SUM_COLUMNS = 2  # a digest, then the path
NEVER = 1 << 60  # a size that no file reaches
TEMPORARY = "<tmp>"  # what a message shows for the temporary directory


def apply_fault(root: Path, fault: Fault) -> None:
    """Make one fault in the copy of the corpus at ``root``.

    Raises
    ------
    FileNotFoundError
        When the fault names a file that the copy does not hold.
    """
    text, change = fault
    name, _, path = text.partition(PATH_SEPARATOR)
    leaf = root / name
    if not leaf.is_file():
        raise FileNotFoundError(name)
    # A file may be a link to the retained evidence, so it is replaced, never
    # written through.
    match change:
        case "delete-file":
            leaf.unlink()
        case "empty-file":
            leaf.unlink()
            leaf.write_bytes(b"")
        case _:
            value = json.loads(leaf.read_text())
            leaf.unlink()
            leaf.write_text(json.dumps(fault_state(value, [(path, change)])))


def refresh_sums(root: Path, anchor: Path, names: set[str]) -> None:
    """Rewrite the digest of each changed file in the copy's ``SHA256SUMS``.

    A line names its file either from the corpus directory or from the
    repository root, as the corpus does; a deleted file keeps its line.
    """
    sums = root / SUMS
    if not sums.is_file():
        return
    lines = []
    for line in sums.read_text().splitlines():
        parts = line.split("  ", 1)
        path = next(
            (
                base / parts[1]
                for base in (root, anchor)
                if len(parts) == SUM_COLUMNS and changed(base / parts[1], root, names)
            ),
            None,
        )
        if path is not None:
            parts[0] = hashlib.sha256(path.read_bytes()).hexdigest()
            line = "  ".join(parts)
        lines.append(line)
    sums.write_text("".join(f"{line}\n" for line in lines))


def changed(path: Path, root: Path, names: set[str]) -> bool:
    """Say whether ``path`` is a file of the copy that a fault changed.

    Returns
    -------
    bool
        True for an existing file of the copy whose name is in ``names``.
    """
    return (
        path.is_file()
        and path.is_relative_to(root)
        and str(path.relative_to(root)) in names
    )


def run_faulted(
    corpus: Path,
    faults: list[Fault],
    verify: cabc.Callable[[Path], object],
    link_over: int = NEVER,
) -> object:
    """Copy ``corpus``, make the faults in the copy and run ``verify`` on it.

    A file larger than ``link_over`` bytes is linked, not copied.

    Returns
    -------
    object
        What ``verify`` returned for the faulted copy.
    """
    with tempfile.TemporaryDirectory() as temporary:
        anchor = Path(temporary)
        root = anchor / corpus.relative_to(REPOSITORY)

        def place(source: str, target: str) -> object:
            """Link a file larger than the bound; copy any other.

            Returns
            -------
            object
                The path that ``copytree`` records for the file.
            """
            if Path(source).stat().st_size > link_over:
                Path(target).symlink_to(source)
                return target
            return shutil.copy2(source, target)

        shutil.copytree(corpus, root, copy_function=place)
        for fault in faults:
            apply_fault(root, fault)
        names = {text.partition(PATH_SEPARATOR)[0] for text, _ in faults}
        refresh_sums(root, anchor, names)
        try:
            return verify(root)
        except Exception as error:  # ruff: ignore[blind-except]  # every ending is recorded
            # A message that names the temporary directory would differ per run.
            message = str(error).replace(temporary, TEMPORARY)
            raise type(error)(message) from None
