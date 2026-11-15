"""Where an audit is read from and written to: the refresh itself."""

import dataclasses as dc
import datetime as dt
import hashlib
import typing as typ
from pathlib import Path

import audit_model as am
import markdown_model as mm
from audit_io import (
    RELEASE_DIRECTORY,
    Json,
    dump,
    git_output,
    read_json,
    relative,
    write_revision,
)
from section_map import RefreshRefusedError, load_section_map
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    import collections.abc as cabc

EXPECTED_GAPS = 87


@dc.dataclass(frozen=True, slots=True)
class Revision:
    """A written audit revision.

    Attributes
    ----------
    number : int
        The revision number.
    directory : pathlib.Path
        The revision directory.
    manifest : dict[str, typing.Any]
        The manifest as written.
    sections : dict[str, list[mm.Section]]
        The section inventory as written.
    register : dict[str, typing.Any]
        The register as written.
    """

    number: int
    directory: Path
    manifest: Json
    sections: am.Inventory
    register: am.Register


@dc.dataclass(slots=True)
class Workspace:
    """Where an audit is read from and written to.

    Attributes
    ----------
    root : pathlib.Path
        The register checkout: ``gap-register.json`` and the input documents.
    evidence_root : pathlib.Path | None
        Where earlier revisions are read from. ``None`` follows the register's
        own ``source_manifest`` and ``source_sections`` pointers.
    out_root : pathlib.Path | None
        The directory that receives ``protocol-gap-analysis/``; defaults to
        ``evidence`` below the checkout.
    expected_gaps : int
        How many gaps the register must hold.
    baseline : pathlib.Path | None
        A register that the current one must match in every protected field.
    clock : collections.abc.Callable[[], datetime.datetime]
        Supplies the capture time; injectable for tests.
    """

    root: Path
    evidence_root: Path | None = None
    out_root: Path | None = None
    expected_gaps: int = EXPECTED_GAPS
    baseline: Path | None = None
    clock: cabc.Callable[[], dt.datetime] = lambda: dt.datetime.now(dt.UTC)

    def _locate(self, pointer: str) -> Path:
        """Find a previous revision file from a register pointer.

        Parameters
        ----------
        pointer : str
            ``source_manifest`` or ``source_sections`` as recorded.

        Returns
        -------
        pathlib.Path
            The file's location.
        """
        path = self.root / pointer
        if self.evidence_root is None:
            return path
        parts = Path(pointer).parts
        return self.evidence_root.joinpath(*parts[parts.index(RELEASE_DIRECTORY) :])

    def _inputs(self, previous: am.Inventory, smap: am.SectionMap) -> list[str]:
        """Decide which documents are inputs of the new revision.

        Parameters
        ----------
        previous : dict[str, list[mm.Section]]
            The previous inventory.
        smap : am.SectionMap
            The reviewed map.

        Returns
        -------
        list[str]
            Document paths in manifest order, all of which exist.

        Raises
        ------
        MissingInputError
            If an expected document is absent and was not restructured away.
        """
        restructured = {path for path, _ in smap.sections}
        names: list[str] = []
        for path in previous:
            current = smap.files.get(path, path)
            if (self.root / current).is_file():
                names.append(current)
            elif path not in restructured:
                message = f"input document {current} is absent"
                raise MissingInputError(message)
        names += [path for path, _ in smap.sections.values()]
        names += [path for parts in smap.also.values() for path, _ in parts]
        unique = list(dict.fromkeys(names))
        missing = [name for name in unique if not (self.root / name).is_file()]
        if missing:
            message = f"mapped documents are absent: {', '.join(missing)}"
            raise MissingInputError(message)
        return unique

    def _verify_register(self, register: Json) -> None:
        """Refuse a register with the wrong gap count or a changed baseline.

        Parameters
        ----------
        register : dict[str, typing.Any]
            The register to verify.

        Raises
        ------
        RefreshRefusedError
            If the count is wrong or a protected field differs from the baseline.
        """
        count = len(register["gaps"])
        if count != self.expected_gaps:
            message = f"register holds {count} gaps, expected {self.expected_gaps}"
            raise RefreshRefusedError(message)
        if self.baseline is not None:
            changed = am.compare_registers(read_json(self.baseline), register)
            if changed:
                raise RefreshRefusedError("; ".join(changed))

    def _revision_directory(self, revision: int, today: dt.date) -> Path:
        """Name the new revision directory, refusing one that already exists.

        Parameters
        ----------
        revision : int
            The revision number.
        today : datetime.date
            The audit date.

        Returns
        -------
        pathlib.Path
            The directory, which does not yet exist.

        Raises
        ------
        RefreshRefusedError
            If the directory exists, because revisions are never overwritten.
        """
        out = (self.out_root or self.root / "evidence") / RELEASE_DIRECTORY
        directory = out / today.isoformat() / f"revision-{revision}"
        if directory.exists():
            message = (
                f"{directory.name} already exists at {directory}; never overwritten"
            )
            raise RefreshRefusedError(message)
        return directory

    def refresh(
        self, revision: int, *, today: dt.date, section_map: Path | None = None
    ) -> Revision:
        """Write a new audit revision and update the register to match it.

        Parameters
        ----------
        revision : int
            The new revision number.
        today : datetime.date
            The date directory and the register's ``last_updated``.
        section_map : pathlib.Path | None
            Reviewed correspondences for moved or restructured documents.

        Returns
        -------
        Revision
            What was written.
        """
        register = read_json(self.root / "gap-register.json")
        directory = self._revision_directory(revision, today)
        self._verify_register(register)
        previous = read_json(self._locate(register["source_sections"]))
        smap = load_section_map(section_map)
        texts = {n: (self.root / n).read_bytes() for n in self._inputs(previous, smap)}
        current = {n: mm.section_inventory(d.decode()) for n, d in texts.items()}
        mapping = am.build_mapping(previous, current, smap)
        updated = am.rewrite_register(
            register, previous, current, am.with_parts(mapping, smap)
        )
        updated["source_manifest"] = relative(directory / "manifest.json", self.root)
        updated["source_sections"] = relative(directory / "sections.json", self.root)
        updated["last_updated"] = today.isoformat()
        self._verify_register(updated)
        manifest = self._manifest(register, texts, directory)
        files = {f"inputs/{name}.txt": data for name, data in texts.items()}
        write_revision(
            directory,
            {**files, "manifest.json": dump(manifest), "sections.json": dump(current)},
        )
        (self.root / "gap-register.json").write_bytes(dump(updated))
        return Revision(revision, directory, manifest, current, updated)

    def _manifest(
        self, register: Json, texts: dict[str, bytes], directory: Path
    ) -> Json:
        """Build the new manifest, carrying forward the metadata unchanged.

        Parameters
        ----------
        register : dict[str, typing.Any]
            The register before the refresh, which points at the previous manifest.
        texts : dict[str, bytes]
            Current bytes of every input.
        directory : pathlib.Path
            The new revision directory.

        Returns
        -------
        dict[str, typing.Any]
            The previous manifest with the run's own keys replaced in place.
        """
        stamp = self.clock().isoformat()
        inputs = [
            {
                "path": name,
                "snapshot": relative(directory / "inputs" / f"{name}.txt", self.root),
                "sha256": hashlib.sha256(data).hexdigest(),
                "lines": len(data.decode().splitlines()),
            }
            for name, data in texts.items()
        ]
        manifest = dict(read_json(self._locate(register["source_manifest"])))
        manifest.update(
            captured_at_utc=stamp,
            source_git_head=git_output(self.root, "rev-parse", "HEAD"),
            source_worktree_status=git_output(self.root, "status", "--short"),
            inputs=inputs,
            updated_at_utc=stamp,
        )
        return manifest
