"""Check an imported ``evidence/`` tree against its curation record.

Three questions are answered. Is the set of corpora present exactly the set
that ``curation.json`` includes? Does every evidence path that the citing files
name resolve to a file, a directory or a withheld path? And, given the source
checkout and commit, is every file of every included corpus byte-identical to
the source's, with nothing extra and nothing missing (obligation INV-IMPORT)?
"""

import dataclasses as dc
import functools
import hashlib
import json
import typing as typ
from concurrent import futures

from evidence_corpus import INCLUDED, corpus_of, load_curation
from evidence_files import CitingRoot, cited_paths, citing_files, list_files
from git_lossless import as_arg, git_names, git_text
from lfs_rule import POINTER_PREFIX
from tool_support import MissingInputError
from withheld_model import MANIFEST_RELATIVE, NotedReport, load_manifest

if typ.TYPE_CHECKING:
    from pathlib import Path

CURATION_RELATIVE = "evidence/curation.json"
# Corpora created in this repository, which the source never held.
LOCAL_RELATIVE = "evidence/local-corpora.json"
ALLOWED_NAMES = frozenset({MANIFEST_RELATIVE, CURATION_RELATIVE, LOCAL_RELATIVE})
PATCH_SUFFIX = ".bsdiff"
WORKERS = 8
# A cited path ending in one of these was truncated at a format placeholder.
TEMPLATE_ENDINGS = ("-", "_")


@dc.dataclass(frozen=True, slots=True)
class CheckRequest:
    """What a curation check examines.

    Attributes
    ----------
    root : pathlib.Path
        The repository that holds the imported ``evidence/``.
    curation : pathlib.Path | None
        The curation file; defaults to ``evidence/curation.json``.
    withheld : pathlib.Path | None
        The withheld manifest; defaults to ``evidence/withheld.json``.
    citing : tuple[CitingRoot, ...]
        Files and directories whose citations must resolve.
    source_root : pathlib.Path | None
        The source checkout, for the content comparison.
    source_commit : str
        The commit of the source checkout to compare against.
    local_files : tuple[str, ...]
        Extra paths that may exist here without existing in the source.
    """

    root: Path
    curation: Path | None = None
    withheld: Path | None = None
    citing: tuple[CitingRoot, ...] = ()
    source_root: Path | None = None
    source_commit: str = ""
    local_files: tuple[str, ...] = ()


@dc.dataclass(slots=True)
class CheckResult(NotedReport):
    """The outcome of a curation check.

    Attributes
    ----------
    compared : int
        How many files were compared with the source.
    differences : int
        How many differences the comparison found.
    """

    compared: int = 0
    differences: int = 0


def _check_corpora(here: list[str], included: set[str], result: CheckResult) -> None:
    """Require the corpora present to be exactly the included ones."""
    present = {c for c in map(corpus_of, here) if c}
    result.failures += [
        f"{c}: present but not included" for c in sorted(present - included)
    ]
    result.failures += [f"{c}: included but absent" for c in sorted(included - present)]
    result.notes.append(f"{len(present)} corpora present, {len(included)} included")


def _resolves(root: Path, path: str) -> bool:
    """Say whether a cited evidence path names something that exists.

    A citation that ends in a hyphen or an underscore was cut short at a format
    placeholder, as in ``queries/D-{address}.c``. It names a family of files
    and resolves when any file in that directory begins with it.

    Returns
    -------
    bool
        ``True`` if the path, or a file completing the template, exists.
    """
    target = root / path
    if target.exists():
        return True
    if not path.endswith(TEMPLATE_ENDINGS) or not target.parent.is_dir():
        return False
    return any(child.name.startswith(target.name) for child in target.parent.iterdir())


def _check_citations(
    request: CheckRequest, withheld: frozenset[str], result: CheckResult
) -> None:
    """Require every cited evidence path to resolve."""
    first: dict[str, Path] = {}
    for citing in request.citing:
        for file in citing_files(citing):
            for path in cited_paths(file.read_bytes()):
                first.setdefault(path, file)
    for path, file in sorted(first.items()):
        if path in withheld or _resolves(request.root, path):
            continue
        result.failures.append(f"{path}: cited by {file}, does not resolve")
    result.notes.append(f"{len(first)} cited paths checked")


def _digest_here(path: Path) -> tuple[str, bool]:
    """Hash a local file.

    Returns
    -------
    tuple[str, bool]
        The SHA-256 of its content, and whether it is a Git LFS pointer.
    """
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest(), data.startswith(POINTER_PREFIX)


def _digest_source(source: Path, commit: str, name: str) -> str:
    """Hash a file as the source commit holds it.

    Returns
    -------
    str
        The SHA-256 of the blob.
    """
    blob = git_text(source, "cat-file", "blob", f"{commit}:{name}").encode("latin-1")
    return hashlib.sha256(blob).hexdigest()


def _judge(request: CheckRequest, name: str) -> str | None:
    """Compare one file here with the source commit's.

    Returns
    -------
    str | None
        A failure message, or ``None`` when the content is identical.
    """
    source = typ.cast("Path", request.source_root)
    here, pointer = _digest_here(request.root / name)
    if here == _digest_source(source, request.source_commit, name):
        return None
    hint = ": Git LFS pointer, not content; run git lfs pull" if pointer else ""
    return f"{name}: content differs from the source{hint}"


def _compare(request: CheckRequest, names: list[str], result: CheckResult) -> None:
    """Compare the content of ``names`` here and in the source."""
    with futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        verdicts = list(pool.map(functools.partial(_judge, request), names))
    result.failures += [v for v in verdicts if v]
    result.differences += sum(1 for v in verdicts if v)


def _unexpected(request: CheckRequest, names: set[str]) -> list[str]:
    """List files absent from the source that nothing accounts for.

    The manifests, the patches, files named by ``--local-file`` and files in a
    corpus created here are all accounted for.

    Returns
    -------
    list[str]
        The remaining paths, sorted.
    """
    allowed = ALLOWED_NAMES | set(request.local_files)
    created_here = _local_corpora(request.root)
    return sorted(
        name
        for name in names
        if name not in allowed
        and not name.endswith(PATCH_SUFFIX)
        and corpus_of(name) not in created_here
    )


def _check_source(
    request: CheckRequest, included: set[str], here: list[str], result: CheckResult
) -> None:
    """Compare every included file with the source commit (INV-IMPORT)."""
    source = typ.cast("Path", request.source_root)
    withheld = _withheld(request)
    listing = git_names(
        source,
        "ls-tree",
        "-r",
        "-z",
        "--name-only",
        request.source_commit,
        "--",
        "evidence",
    )
    in_source = {as_arg(name) for name in listing}
    expected = {n for n in in_source if corpus_of(n) in included and n not in withheld}
    local = set(here)
    extras = _unexpected(request, local - in_source)
    missing = sorted(expected - local)
    result.failures += [f"{n}: missing from the import" for n in missing]
    result.failures += [f"{n}: absent from the source commit" for n in extras]
    result.differences += len(missing) + len(extras)
    common = sorted(expected & local)
    _compare(request, common, result)
    result.compared = len(expected)


def _local_corpora(root: Path) -> set[str]:
    """Read the corpora that were created in this repository.

    ``evidence/local-corpora.json`` lists them, each with the reason it exists.
    They belong in the tree although the source commit never held them.

    Returns
    -------
    set[str]
        The corpus paths; empty when there is no such file.
    """
    record = root / LOCAL_RELATIVE
    if not record.is_file():
        return set()
    listed = json.loads(record.read_text(encoding="utf-8"))["corpora"]
    return {entry["path"] for entry in listed}


def _withheld(request: CheckRequest) -> frozenset[str]:
    """Read the withheld paths, if there is a manifest.

    Returns
    -------
    frozenset[str]
        The paths.
    """
    manifest = request.withheld or request.root / MANIFEST_RELATIVE
    if request.withheld is None and not manifest.is_file():
        return frozenset()
    return load_manifest(manifest).paths


def check(request: CheckRequest) -> CheckResult:
    """Run the curation check.

    Parameters
    ----------
    request : CheckRequest
        What to examine.

    Returns
    -------
    CheckResult
        The failures and counts.

    Raises
    ------
    MissingInputError
        If the root has no ``evidence/`` directory, or the source comparison
        lacks a commit.
    """
    if not (request.root / "evidence").is_dir():
        message = f"no evidence directory below {request.root}"
        raise MissingInputError(message)
    curation = request.curation or request.root / CURATION_RELATIVE
    included = {c.path for c in load_curation(curation) if c.disposition == INCLUDED}
    result = CheckResult()
    here = list_files(request.root)
    _check_corpora(here, included | _local_corpora(request.root), result)
    _check_citations(request, _withheld(request), result)
    if request.source_root is not None:
        if not request.source_commit:
            message = "--source-commit is required with --source-root"
            raise MissingInputError(message)
        _check_source(request, included, here, result)
    return result
