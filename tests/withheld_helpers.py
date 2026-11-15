"""Fixtures shared by the tests that need a withheld manifest and a Git tree."""

import dataclasses as dc
import hashlib
import json
import typing as typ

import bsdiff4
import check_withheld
from git_helpers import init_repo

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

FORK = b"withheld fork bytes " * 40
FORK_PATH = "evidence/inputs/fork.bin"
FORK_SIZE = len(FORK)


def digest(data: bytes) -> str:
    """Return the SHA-256 of ``data``.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def entry(
    path: str,
    data: bytes,
    patch: cabc.Mapping[str, str] | None = None,
    fork: str = "data",
) -> dict[str, object]:
    """Build one manifest entry for ``data`` stored at ``path``.

    Returns
    -------
    dict[str, object]
        The JSON object for the entry.
    """
    return {
        "path": path,
        "bytes": len(data),
        "sha256": digest(data),
        "fork": fork,
        "patch": dict(patch) if patch else None,
    }


def manifest_text(entries: list[dict[str, object]]) -> str:
    """Render a manifest holding ``entries`` in the canonical layout.

    Returns
    -------
    str
        The JSON text.
    """
    document = {"schema_version": 1, "reason": "test", "files": entries}
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


def seed_repo(root: Path, files: cabc.Mapping[str, str | bytes]) -> None:
    """Write ``files`` below ``root`` and commit them (ignored paths excluded).

    Parameters
    ----------
    root : pathlib.Path
        An existing empty directory.
    files : collections.abc.Mapping[str, str | bytes]
        Relative path to content; a ``.gitignore`` entry decides what is kept.
    """
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        data = content.encode("utf-8") if isinstance(content, str) else content
        target.write_bytes(data)
    init_repo(root)


CONTAINER_PATH = "evidence/inputs/container.bin"
CONTAINER = b"\x00" * 82 + FORK
PATCH = bsdiff4.diff(FORK, CONTAINER)
PATCH_PATH = CONTAINER_PATH + ".bsdiff"
IGNORE = f"{FORK_PATH}\n{CONTAINER_PATH}\n"


def patch_block(base: bytes = FORK) -> dict[str, str]:
    """Return the manifest's patch object for the container.

    Returns
    -------
    dict[str, str]
        The patch description, with ``base`` as the recorded base.
    """
    return {
        "path": PATCH_PATH,
        "format": "BSDIFF40",
        "base_sha256": digest(base),
        "patch_sha256": digest(PATCH),
        "result_sha256": digest(CONTAINER),
    }


@dc.dataclass(slots=True)
class Repo:
    """A seeded repository for one test.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    """

    root: Path

    def put(self, name: str, data: bytes) -> None:
        """Write an untracked file below the root."""
        target = self.root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


def build(
    root: Path,
    *,
    ignore: str = IGNORE,
    entries: list[dict[str, object]] | None = None,
    extra: dict[str, str | bytes] | None = None,
) -> Repo:
    """Create a committed repository with a manifest, a patch and an ignore file.

    Returns
    -------
    Repo
        The repository.
    """
    listed = entries or [
        entry(FORK_PATH, FORK, fork="resource"),
        entry(CONTAINER_PATH, CONTAINER, patch_block(), fork="container"),
    ]
    files: dict[str, str | bytes] = {
        ".gitignore": ignore,
        "evidence/withheld.json": manifest_text(listed),
        PATCH_PATH: PATCH,
        **(extra or {}),
    }
    seed_repo(root, files)
    return Repo(root)


GAP = "evidence/gap-remediation"
PREBOOT = "preboot-app/catalog-11183"
STOPPED = "native-ban-expiry-later-01/raw/post/stopped-hfs"
MOTHRA_RESOURCE = f"{GAP}/2026-11-14/{STOPPED}/server-rsrc.bin"
MOTHRA_CONTAINER = f"{GAP}/2026-11-12/batch-09/inputs/HLserver19.appledouble"
MOTHRA_WITHHELD = (
    ("data", "evidence/hotline-server-1.9/inputs/HLserver19.pef"),
    ("data", f"{GAP}/2026-11-13/native-ban-one-01/preparation/{PREBOOT}.data"),
    ("data", f"{GAP}/2026-11-13/native-runtime-recovery-01/{PREBOOT}.data"),
    ("data", f"{GAP}/2026-11-14/{STOPPED}/server-data.bin"),
    ("resource", f"{GAP}/2026-11-13/native-ban-one-01/preparation/{PREBOOT}.rsrc"),
    ("resource", f"{GAP}/2026-11-13/native-runtime-recovery-01/{PREBOOT}.rsrc"),
    ("resource", MOTHRA_RESOURCE),
    ("container", MOTHRA_CONTAINER),
)


def write_mothra_manifest(root: Path, mothra: Path) -> Path:
    """Write a withheld manifest for mothra's eight real paths below ``root``.

    Parameters
    ----------
    root : pathlib.Path
        An existing directory that receives ``evidence/withheld.json``.
    mothra : pathlib.Path
        The mothra checkout that holds the real files.

    Returns
    -------
    pathlib.Path
        The manifest.
    """
    request = check_withheld.ManifestRequest(
        root=root,
        source_root=mothra,
        reason="real-data control",
        specs=MOTHRA_WITHHELD,
        patch_bases={MOTHRA_CONTAINER: MOTHRA_RESOURCE},
    )
    check_withheld.write_manifest(request)
    return root / "evidence/withheld.json"
