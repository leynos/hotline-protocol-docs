"""Tests for the audit refresh tool (obligation INV-AUDIT)."""

import copy
import json
import typing as typ

import audit_helpers as ah
import audit_workspace as aw
import pytest
import refresh_audit as ra
import section_map as sm
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from pathlib import Path

REVISION = 2


def refresh(
    world: ah.World,
    *,
    baseline: Path | None = None,
    section_map: Path | None = None,
) -> aw.Revision:
    """Run a refresh of the test world with the fixed clock.

    Parameters
    ----------
    world : audit_helpers.World
        The layout to refresh.
    baseline : pathlib.Path | None
        A register that the current one must match in every protected field.
    section_map : pathlib.Path | None
        The section map file.

    Returns
    -------
    refresh_audit.Revision
        The written revision.
    """
    workspace = aw.Workspace(
        world.root,
        evidence_root=world.evidence,
        out_root=world.evidence,
        expected_gaps=2,
        baseline=baseline,
        clock=lambda: ah.NOW,
    )
    return workspace.refresh(REVISION, today=ah.TODAY, section_map=section_map)


def revision_dir(world: ah.World) -> Path:
    """Return where revision 2 is written.

    Parameters
    ----------
    world : audit_helpers.World
        The layout.

    Returns
    -------
    pathlib.Path
        The revision directory.
    """
    return world.evidence / "protocol-gap-analysis" / "2026-11-15" / "revision-2"


def test_unchanged_inputs_reproduce_the_register_and_sections(tmp_path: Path) -> None:
    """Refreshing unchanged inputs changes only the pointers and the date."""
    world = ah.build_world(tmp_path)
    before = ah.read_json(world.register)
    old_sections = ah.read_json(
        world.evidence / "protocol-gap-analysis/2026-11-14/revision-1/sections.json"
    )
    refresh(world)
    after = ah.read_json(world.register)
    assert ah.read_json(revision_dir(world) / "sections.json") == old_sections, (
        "sections"
    )
    assert after["gaps"] == before["gaps"], "gaps changed"
    assert after["review_coverage"] == before["review_coverage"], "coverage changed"
    assert after["last_updated"] == "2026-11-15", after["last_updated"]
    assert after["source_manifest"].endswith("2026-11-15/revision-2/manifest.json"), (
        after
    )
    assert after["source_manifest"].startswith("../mothra/evidence/"), after


def test_manifest_snapshots_sums_and_clock(tmp_path: Path) -> None:
    """Every input is snapshotted afresh, hashed, and stamped from the clock."""
    world = ah.build_world(tmp_path)
    refresh(world)
    manifest = ah.read_json(revision_dir(world) / "manifest.json")
    assert manifest["captured_at_utc"] == ah.NOW.isoformat(), "captured"
    assert manifest["updated_at_utc"] == ah.NOW.isoformat(), "updated"
    assert len(manifest["source_git_head"]) == 40, manifest["source_git_head"]
    assert manifest["independent_review"] == {"scope": "carried forward unchanged"}, (
        "carry"
    )
    assert manifest["method"] == "Original method text.", "method carried"
    first = manifest["inputs"][0]
    assert first["snapshot"].endswith("revision-2/inputs/a.md.txt"), first
    assert (revision_dir(world) / "inputs/a.md.txt").read_bytes() == (
        world.root / "a.md"
    ).read_bytes(), "snapshot bytes"
    sums = (revision_dir(world) / "SHA256SUMS").read_text().splitlines()
    assert len(sums) == 4, sums
    assert sums[0].endswith(
        "evidence/protocol-gap-analysis/2026-11-15/revision-2/inputs/a.md.txt"
    ), sums


def test_a_shifted_line_range_moves_numbers_but_not_anchors(tmp_path: Path) -> None:
    """A blank prose line shifts line ranges; anchors and headings stay put."""
    world = ah.build_world(tmp_path)
    (world.root / "a.md").write_text(ah.ALPHA.replace("intro\n", "intro\n\nextra\n"))
    before = ah.read_json(world.register)
    refresh(world)
    after = ah.read_json(world.register)
    old, new = before["gaps"][1]["sources"][0], after["gaps"][1]["sources"][0]
    assert new["line_start"] == old["line_start"] + 2, (old, new)
    assert new["anchor"] == old["anchor"], "anchor moved"
    assert list(new) == list(old), "key order changed"
    assert after["gaps"][0]["sources"][0]["line_end"] == old["line_start"] + 1, (
        "range end"
    )


def test_a_relocated_path_is_followed_through_the_map(tmp_path: Path) -> None:
    """A moved document is found at its new path and every record follows."""
    world = ah.build_world(tmp_path)
    (world.root / "docs").mkdir()
    (world.root / "a.md").rename(world.root / "docs" / "a.md")
    smap = tmp_path / "map.json"
    smap.write_text('{"files": {"a.md": "docs/a.md"}}')
    refresh(world, section_map=smap)
    register = ah.read_json(world.register)
    paths = {s["path"] for g in register["gaps"] for s in g["sources"]}
    assert paths == {"docs/a.md", "b.md"}, paths
    assert {e["path"] for e in register["review_coverage"]} == paths, "coverage paths"
    assert (revision_dir(world) / "inputs/docs/a.md.txt").is_file(), "nested snapshot"


def test_a_many_to_one_mapping_merges_coverage(tmp_path: Path) -> None:
    """Two old sections mapped to one new section merge their coverage rows."""
    world = ah.build_world(tmp_path)
    (world.root / "b.md").unlink()
    (world.root / "c.md").write_text("# Merged\n\ntext\n")
    smap = tmp_path / "map.json"
    smap.write_text(
        '{"sections": [{"old": ["b.md", 1], "new": ["c.md", 1]},'
        ' {"old": ["b.md", 2], "new": ["c.md", 1]}]}'
    )
    refresh(world, section_map=smap)
    register = ah.read_json(world.register)
    merged = [e for e in register["review_coverage"] if e["path"] == "c.md"]
    assert len(merged) == 1, merged
    assert merged[0]["heading"] == "Merged", merged
    assert merged[0]["related_gap_ids"] == ["GAP-001", "GAP-002"], merged
    assert len(register["review_coverage"]) == 3, "coverage rows"
    assert [s["path"] for s in register["gaps"][1]["sources"]] == ["a.md", "c.md"], (
        "sources"
    )


def snapshot_of(world: ah.World) -> dict[str, bytes]:
    """Capture the bytes of every file under the test layout.

    Parameters
    ----------
    world : audit_helpers.World
        The layout.

    Returns
    -------
    dict[str, bytes]
        Content per path, ignoring the Git directory.
    """
    base = world.root.parent
    return {
        str(path): path.read_bytes()
        for path in base.rglob("*")
        if path.is_file() and ".git" not in path.parts
    }


def test_a_heading_inserted_without_a_map_entry_is_refused(tmp_path: Path) -> None:
    """The negative control: refusal names the document and writes nothing."""
    world = ah.build_world(tmp_path)
    (world.root / "a.md").write_text(ah.ALPHA + "\n## Inserted\n")
    before = snapshot_of(world)
    with pytest.raises(sm.RefreshRefusedError, match=r"a\.md"):
        refresh(world)
    assert snapshot_of(world) == before, "a refused refresh wrote files"


def test_a_changed_closure_criterion_is_detected_and_refused(tmp_path: Path) -> None:
    """The register must match the baseline in every protected field."""
    world = ah.build_world(tmp_path)
    baseline = tmp_path / "baseline.json"
    baseline.write_text(world.register.read_text())
    register = ah.read_json(world.register)
    register["gaps"][1]["closure_criteria"] = "Quietly reworded."
    ah.write_json(world.register, register)
    before = snapshot_of(world)
    with pytest.raises(sm.RefreshRefusedError, match=r"GAP-002.*closure_criteria"):
        refresh(world, baseline=baseline)
    assert snapshot_of(world) == before, "a refused refresh wrote files"


def test_wrong_gap_count_is_refused(tmp_path: Path) -> None:
    """The register must hold exactly the expected number of gaps."""
    world = ah.build_world(tmp_path)
    workspace = aw.Workspace(
        world.root,
        evidence_root=world.evidence,
        out_root=world.evidence,
        expected_gaps=3,
    )
    with pytest.raises(sm.RefreshRefusedError, match="3"):
        workspace.refresh(REVISION, today=ah.TODAY)


def test_an_existing_revision_directory_is_never_overwritten(tmp_path: Path) -> None:
    """A second refresh into the same revision is refused."""
    world = ah.build_world(tmp_path)
    refresh(world)
    with pytest.raises(sm.RefreshRefusedError, match="revision-2"):
        refresh(world)


def test_compare_summary_line(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The comparison prints the count of gaps and changed protected fields."""
    world = ah.build_world(tmp_path)
    other = tmp_path / "other.json"
    register = ah.read_json(world.register)
    other.write_text(json.dumps(copy.deepcopy(register)))
    args = ["compare", str(world.register), str(other), "--expected-gaps", "2"]
    assert ra.main(args) == EXIT_OK, "identical registers"
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == "2 gaps, 0 protected fields changed", last
    register["gaps"][0]["status"] = "Resolved"
    other.write_text(json.dumps(register))
    assert ra.main(args) == EXIT_FINDINGS, "changed status"
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == "2 gaps, 1 protected fields changed", last


def test_cli_exit_codes(tmp_path: Path) -> None:
    """Missing inputs exit 2; a refusal exits 1; success exits 0."""
    world = ah.build_world(tmp_path)
    common = [
        "refresh", "--root", str(world.root), "--evidence-root", str(world.evidence),
        "--out-root", str(world.evidence), "--revision", "2", "--expected-gaps", "2",
        "--today", "2026-11-15",
    ]  # fmt: skip
    missing = ["refresh", "--root", str(tmp_path / "none"), "--revision", "2"]
    assert ra.main(missing) == EXIT_MISSING, "absent root"
    (world.root / "a.md").write_text(ah.ALPHA + "\n## Inserted\n")
    assert ra.main(common) == EXIT_FINDINGS, "refusal"
    (world.root / "a.md").write_text(ah.ALPHA)
    assert ra.main(common) == EXIT_OK, "success"
    assert ra.main(common) == EXIT_FINDINGS, "second run refused"


def test_a_reason_records_the_revision_as_a_local_corpus(tmp_path: Path) -> None:
    """With ``--reason`` the new revision is appended to the local-corpora record."""
    world = ah.build_world(tmp_path)
    record = world.evidence / "local-corpora.json"
    earlier = {"path": "evidence/earlier", "reason": "Kept."}
    ah.write_json(record, {"schema_version": 1, "corpora": [earlier]})
    arguments = [
        "refresh", "--root", str(world.root), "--evidence-root", str(world.evidence),
        "--out-root", str(world.evidence), "--revision", "2", "--expected-gaps", "2",
        "--today", "2026-11-15", "--reason", "Cut for the test.",
    ]  # fmt: skip
    assert ra.main(arguments) == EXIT_OK, "refresh succeeds"
    listed = ah.read_json(record)["corpora"]
    relative = revision_dir(world).relative_to(world.evidence.parent).as_posix()
    expected = [earlier, {"path": relative, "reason": "Cut for the test."}]
    assert listed == expected, listed
    assert record.read_text().endswith("}\n"), "canonical layout"


def test_without_a_reason_the_local_corpora_record_is_untouched(tmp_path: Path) -> None:
    """A refresh that gives no reason leaves the record's bytes alone."""
    world = ah.build_world(tmp_path)
    record = world.evidence / "local-corpora.json"
    ah.write_json(record, {"schema_version": 1, "corpora": []})
    before = record.read_bytes()
    refresh(world)
    assert record.read_bytes() == before, "record unchanged"
