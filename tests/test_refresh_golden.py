"""The golden test: revision 89 is reproduced exactly, then the oracle accepts it.

The inputs come from the frozen snapshots that revision 89's manifest names, not
from the live documents, so later edits to the documents cannot disturb it.
"""

import dataclasses as dc
import datetime as dt
import importlib.util
import json
import shutil
import sys
import typing as typ
from pathlib import Path

import audit_model as am
import audit_workspace as aw
import refresh_audit as ra
from git_helpers import init_repo

if typ.TYPE_CHECKING:
    import types

REPO = Path(__file__).resolve().parents[1]
REVISION_89 = Path("evidence/protocol-gap-analysis/2026-11-15/revision-89")
NEW_REVISION = 90
GAPS = 87
SECTIONS = 543


def load_oracle(mothra: Path) -> types.ModuleType:
    """Load mothra's renderer, which holds the independent ``validate``.

    Bytecode is not written, because nothing may be written into mothra.

    Parameters
    ----------
    mothra : pathlib.Path
        The mothra checkout.

    Returns
    -------
    types.ModuleType
        The renderer module.

    Raises
    ------
    ImportError
        If the renderer cannot be loaded.
    """
    path = mothra / "scripts" / "render-protocol-gap-analysis.py"
    spec = importlib.util.spec_from_file_location("render_oracle", path)
    if spec is None or spec.loader is None:
        message = f"cannot load the renderer at {path}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules["render_oracle"] = module
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def arrange(base: Path, mothra: Path) -> tuple[Path, Path]:
    """Lay out the register checkout and the evidence the oracle expects.

    Parameters
    ----------
    base : pathlib.Path
        An empty temporary directory.
    mothra : pathlib.Path
        The real mothra checkout (read only).

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path]
        The register checkout and the temporary evidence directory.
    """
    root, evidence = base / "hotline-protocol-docs", base / "mothra" / "evidence"
    manifest = json.loads((mothra / REVISION_89 / "manifest.json").read_text())
    for item in manifest["inputs"]:
        snapshot = mothra / item["snapshot"].removeprefix("../mothra/")
        target = root / item["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(snapshot, target)
    shutil.copyfile(REPO / "gap-register.json", root / "gap-register.json")
    previous = evidence.parent / REVISION_89
    previous.mkdir(parents=True)
    for name in ("manifest.json", "sections.json"):
        shutil.copyfile(mothra / REVISION_89 / name, previous / name)
    (evidence / "hotline-server-1.9").symlink_to(mothra / "evidence/hotline-server-1.9")
    init_repo(root)
    return root, evidence


def assert_register_preserved(
    before: dict[str, typ.Any], after: dict[str, typ.Any]
) -> None:
    """Check obligations (b) and (c): only the pointers differ from the original.

    Parameters
    ----------
    before : dict[str, typ.Any]
        The register before the refresh.
    after : dict[str, typ.Any]
        The register after it.
    """
    old_gaps, new_gaps = before["gaps"], after["gaps"]
    assert [g["sources"] for g in new_gaps] == [g["sources"] for g in old_gaps], "(b)"
    assert after["review_coverage"] == before["review_coverage"], "(b) coverage"
    assert len(new_gaps) == GAPS, "gap count"
    assert len(after["review_coverage"]) == SECTIONS, "coverage count"
    assert am.compare_registers(before, after) == [], "(c) protected fields"
    changed = {k for k in after if after[k] != before[k]}
    assert changed == {"source_manifest", "source_sections"}, changed
    assert after["last_updated"] == "2026-11-15", "last_updated"


@dc.dataclass(frozen=True, slots=True)
class Refreshed:
    """The outcome of refreshing the revision 89 inputs.

    Attributes
    ----------
    root : pathlib.Path
        The register checkout.
    directory : pathlib.Path
        The new revision directory.
    before : dict[str, typing.Any]
        The register before the refresh.
    after : dict[str, typing.Any]
        The register after the refresh.
    """

    root: Path
    directory: Path
    before: dict[str, typ.Any]
    after: dict[str, typ.Any]


def refresh_revision_89(base: Path, mothra: Path) -> Refreshed:
    """Refresh the unchanged revision 89 inputs into revision 90.

    Parameters
    ----------
    base : pathlib.Path
        An empty temporary directory.
    mothra : pathlib.Path
        The real mothra checkout (read only).

    Returns
    -------
    Refreshed
        The checkout, the new directory and the registers either side.
    """
    root, evidence = arrange(base, mothra)
    before = json.loads((root / "gap-register.json").read_text())
    assert "revision-89" in before["source_manifest"], "register is not at revision 89"
    workspace = aw.Workspace(
        root,
        evidence_root=evidence,
        out_root=evidence,
        clock=lambda: dt.datetime(2026, 11, 15, 12, 0, tzinfo=dt.UTC),
    )
    revision = workspace.refresh(NEW_REVISION, today=dt.date(2026, 11, 15))
    after = json.loads((root / "gap-register.json").read_text())
    return Refreshed(root, revision.directory, before, after)


def test_unchanged_inputs_reproduce_revision_89_and_satisfy_the_oracle(
    tmp_path: Path, mothra: Path
) -> None:
    """Sections are identical, gap content is untouched, and ``validate`` passes."""
    result = refresh_revision_89(tmp_path, mothra)
    old = mothra / REVISION_89 / "sections.json"
    assert (result.directory / "sections.json").read_bytes() == old.read_bytes(), "(a)"
    assert_register_preserved(result.before, result.after)
    load_oracle(mothra).validate(tmp_path / "mothra", result.root, result.after)
    manifest = json.loads((result.directory / "manifest.json").read_text())
    snapshots = [item["snapshot"] for item in manifest["inputs"]]
    assert all("revision-90/inputs/" in name for name in snapshots), "fresh snapshots"
    original = REPO / "gap-register.json"
    refreshed = result.root / "gap-register.json"
    code = ra.main(["compare", str(original), str(refreshed)])
    assert code == 0, "compare found protected changes"
