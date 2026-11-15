"""The withheld-files manifest: its shape, parsing and rendering.

``evidence/withheld.json`` records every file that the repository does not
publish (a third-party binary's forks). Each entry has a size and a SHA-256, so
a local copy can be verified and a leak found; an entry may carry a BSDIFF40
patch that rebuilds a modified copy from a withheld base.
"""

import dataclasses as dc
import hashlib
import json
import re
import typing as typ

from tool_support import MissingInputError, Report, ToolError

if typ.TYPE_CHECKING:
    from pathlib import Path

MANIFEST_RELATIVE = "evidence/withheld.json"
SCHEMA_VERSION = 1
FORKS = ("data", "resource", "container")
PATCH_FORMAT = "BSDIFF40"
PATCH_SUFFIX = ".bsdiff"
SHA256 = re.compile(r"[0-9a-f]{64}")
INDENT = 2


class ManifestError(ToolError):
    """The withheld manifest is malformed."""


@dc.dataclass(slots=True)
class NotedReport(Report):
    """A :class:`Report` that also carries informational lines.

    Attributes
    ----------
    notes : list[str]
        Outcomes that are not failures, such as ``withheld (absent)``.
    """

    notes: list[str] = dc.field(default_factory=list)


@dc.dataclass(frozen=True, slots=True)
class Patch:
    """A BSDIFF40 patch that rebuilds a withheld file from a withheld base.

    Attributes
    ----------
    path : str
        Where the patch is stored, relative to the repository root.
    base_sha256 : str
        The SHA-256 of the file that the patch is applied to.
    patch_sha256 : str
        The SHA-256 of the patch file.
    result_sha256 : str
        The SHA-256 of the rebuilt file.
    """

    path: str
    base_sha256: str
    patch_sha256: str
    result_sha256: str


@dc.dataclass(frozen=True, slots=True)
class Entry:
    """One withheld file.

    Attributes
    ----------
    path : str
        The file's repository-relative POSIX path.
    size : int
        Its length in bytes (``bytes`` in the JSON).
    sha256 : str
        Its SHA-256.
    fork : str
        ``data``, ``resource`` or ``container``.
    patch : Patch | None
        The patch that rebuilds the file, if it is stored as one.
    """

    path: str
    size: int
    sha256: str
    fork: str
    patch: Patch | None = None


@dc.dataclass(frozen=True, slots=True)
class Manifest:
    """The parsed withheld manifest.

    Attributes
    ----------
    reason : str
        Why the files are withheld.
    files : tuple[Entry, ...]
        The entries, in manifest order.
    """

    reason: str
    files: tuple[Entry, ...]

    @property
    def paths(self) -> frozenset[str]:
        """The withheld paths."""
        return frozenset(entry.path for entry in self.files)

    @property
    def sizes(self) -> frozenset[int]:
        """The distinct withheld sizes."""
        return frozenset(entry.size for entry in self.files)

    @property
    def hashes(self) -> frozenset[str]:
        """The distinct withheld SHA-256 values."""
        return frozenset(entry.sha256 for entry in self.files)


def sha256_bytes(data: bytes) -> str:
    """Hash bytes.

    Parameters
    ----------
    data : bytes
        The content.

    Returns
    -------
    str
        The hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def sha256_of(path: Path) -> str:
    """Hash a file.

    Parameters
    ----------
    path : pathlib.Path
        The file to read.

    Returns
    -------
    str
        The hexadecimal SHA-256 of its bytes.
    """
    return sha256_bytes(path.read_bytes())


def _text(value: object, label: str) -> str:
    """Return ``value`` if it is a non-empty string.

    Returns
    -------
    str
        The string.

    Raises
    ------
    ManifestError
        If it is not.
    """
    if not isinstance(value, str) or not value:
        message = f"{label} must be a non-empty string"
        raise ManifestError(message)
    return value


def _digest(value: object, label: str) -> str:
    """Return ``value`` if it is a lower-case SHA-256.

    Returns
    -------
    str
        The digest.

    Raises
    ------
    ManifestError
        If it is not.
    """
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        message = f"{label} must be a lower-case SHA-256"
        raise ManifestError(message)
    return value


def _patch(raw: object, path: str) -> Patch | None:
    """Build the optional patch of the entry at ``path``.

    Returns
    -------
    Patch | None
        The patch, or ``None`` when the entry has none.

    Raises
    ------
    ManifestError
        If the patch is malformed.
    """
    if raw is None:
        return None
    if not isinstance(raw, dict) or raw.get("format") != PATCH_FORMAT:
        message = f"{path}: patch must be an object of format {PATCH_FORMAT}"
        raise ManifestError(message)
    stored = _text(raw.get("path"), f"{path}: patch path")
    if stored != path + PATCH_SUFFIX:
        message = f"{path}: patch path must be the path plus {PATCH_SUFFIX}"
        raise ManifestError(message)
    return Patch(
        path=stored,
        base_sha256=_digest(raw.get("base_sha256"), f"{path}: base_sha256"),
        patch_sha256=_digest(raw.get("patch_sha256"), f"{path}: patch_sha256"),
        result_sha256=_digest(raw.get("result_sha256"), f"{path}: result_sha256"),
    )


def _entry(raw: object) -> Entry:
    """Build one entry from its JSON object.

    Returns
    -------
    Entry
        The entry.

    Raises
    ------
    ManifestError
        If the entry is malformed.
    """
    if not isinstance(raw, dict):
        message = "every file entry must be an object"
        raise ManifestError(message)
    path = _text(raw.get("path"), "entry path")
    size = raw.get("bytes")
    if type(size) is not int or size < 0:
        message = f"{path}: bytes must be a non-negative integer"
        raise ManifestError(message)
    fork = raw.get("fork")
    if fork not in FORKS:
        message = f"{path}: fork must be one of {', '.join(FORKS)}"
        raise ManifestError(message)
    return Entry(
        path=path,
        size=size,
        sha256=_digest(raw.get("sha256"), f"{path}: sha256"),
        fork=str(fork),
        patch=_patch(raw.get("patch"), path),
    )


def load_manifest(path: Path) -> Manifest:
    """Read and validate a withheld manifest.

    Parameters
    ----------
    path : pathlib.Path
        The ``withheld.json`` file.

    Returns
    -------
    Manifest
        The validated manifest.

    Raises
    ------
    MissingInputError
        If the file does not exist.
    ManifestError
        If the file is not valid JSON of the documented shape.
    """
    if not path.is_file():
        message = f"withheld manifest {path} is absent"
        raise MissingInputError(message)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        message = f"{path.name}: not valid JSON: {exc}"
        raise ManifestError(message) from exc
    if not isinstance(data, dict) or data.get("schema_version") != SCHEMA_VERSION:
        message = f"{path.name}: schema_version must be {SCHEMA_VERSION}"
        raise ManifestError(message)
    files = data.get("files")
    if not isinstance(files, list):
        message = f"{path.name}: files must be a list"
        raise ManifestError(message)
    entries = tuple(_entry(item) for item in typ.cast("list[object]", files))
    if len({entry.path for entry in entries}) != len(entries):
        message = f"{path.name}: a path is listed twice"
        raise ManifestError(message)
    return Manifest(reason=_text(data.get("reason"), "reason"), files=entries)


def _render_patch(patch: Patch | None) -> dict[str, str] | None:
    """Return the JSON object for a patch, or ``None``.

    Returns
    -------
    dict[str, str] | None
        The object, in manifest key order.
    """
    if patch is None:
        return None
    return {
        "path": patch.path,
        "format": PATCH_FORMAT,
        "base_sha256": patch.base_sha256,
        "patch_sha256": patch.patch_sha256,
        "result_sha256": patch.result_sha256,
    }


def render_manifest(manifest: Manifest) -> str:
    """Render a manifest in the canonical JSON layout.

    Parameters
    ----------
    manifest : Manifest
        The manifest to write.

    Returns
    -------
    str
        Two-space-indented JSON ending in one newline.
    """
    files = [
        {
            "path": entry.path,
            "bytes": entry.size,
            "sha256": entry.sha256,
            "fork": entry.fork,
            "patch": _render_patch(entry.patch),
        }
        for entry in manifest.files
    ]
    document = {
        "schema_version": SCHEMA_VERSION,
        "reason": manifest.reason,
        "files": files,
    }
    return json.dumps(document, indent=INDENT, ensure_ascii=False) + "\n"
