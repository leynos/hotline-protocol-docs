#!/usr/bin/env python3
"""Validate the documentation gap register and render its Markdown report."""

import argparse
import hashlib
import json
import os
import re
import textwrap
from collections import Counter
from pathlib import Path
from typing import TypedDict


class Section(TypedDict):
    heading: str
    level: int
    line_start: int
    line_end: int
    anchor: str


def paragraph(text: str) -> str:
    return textwrap.fill(text, width=78, break_long_words=False, break_on_hyphens=False)


def bullet(label: str, text: str) -> str:
    return textwrap.fill(
        f"- **{label}:** {text}",
        width=78,
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def gap_links(identifiers: list[str]) -> str:
    return ", ".join(f"[{item}](#{item.lower()})" for item in identifiers)


def section_inventory(text: str) -> list[Section]:
    sections: list[Section] = []
    fence = None
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker[1][0]
            fence = None if fence == token else token
            continue
        if fence:
            continue
        heading = re.match(r"^(#{1,6}) (.+)$", line)
        if heading:
            title = heading[2]
            if sections:
                sections[-1]["line_end"] = number - 1
            sections.append(
                {
                    "heading": title,
                    "level": len(heading[1]),
                    "line_start": number,
                    "line_end": len(lines),
                    "anchor": re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-"),
                }
            )
    return sections


MOTHRA_PREFIX = "../mothra/"


def mothra_checkout() -> Path:
    """Locate the general toolset checkout that a few links still point at."""
    if "MOTHRA_ROOT" in os.environ:
        return Path(os.environ["MOTHRA_ROOT"])
    root = Path(__file__).resolve().parent.parent
    for candidate in (root.parent / "mothra", root.parent.parent / "mothra"):
        if candidate.is_dir():
            return candidate
    return root.parent / "mothra"


def check_links(path: Path, text: str) -> int:
    links = re.findall(r"\]\(([^)\s]+)\)", text)
    links += re.findall(r"^\[[^\]]+\]: (\S+)", text, re.MULTILINE)
    for link in links:
        if "://" in link:
            continue
        relative, _, fragment = link.partition("#")
        target = (path.parent / relative).resolve() if relative else path.resolve()
        if relative.startswith(MOTHRA_PREFIX):
            # Guides that remain in the general toolset; see mothra_checkout().
            target = mothra_checkout() / relative.removeprefix(MOTHRA_PREFIX)
        if not target.exists() and target != path.resolve():
            raise ValueError(f"Broken link in {path.name}: {link}")
        if fragment and target.suffix == ".md":
            content = text if target == path.resolve() else target.read_text()
            anchors = {section["anchor"] for section in section_inventory(content)}
            if fragment not in anchors:
                raise ValueError(f"Broken anchor in {path.name}: {link}")
    return len(links)


def validate(root: Path, directory: Path, register: dict) -> dict:
    if register["schema_version"] != 1:
        raise ValueError("Unsupported gap-register schema version")
    manifest = json.loads((directory / register["source_manifest"]).read_text())
    sections = json.loads((directory / register["source_sections"]).read_text())
    for item in manifest["inputs"]:
        snapshot = directory / item["snapshot"]
        expected = item["sha256"]
        for path in (snapshot, directory / item["path"]):
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError(f"Audit input changed; refresh the review: {path}")
        if section_inventory(snapshot.read_text()) != sections[item["path"]]:
            raise ValueError(f"Section inventory differs from source: {snapshot}")
    known_sources = {
        (path, item["heading"], item["line_start"], item["line_end"])
        for path, items in sections.items()
        for item in items
    }
    ledger = json.loads((root / "evidence/hotline-server-1.9/claims.json").read_text())
    ledger_ids = {item["id"] for item in ledger["claims"]}
    gaps = register["gaps"]
    identifiers = {gap["id"] for gap in gaps}
    if len(identifiers) != len(gaps):
        raise ValueError("Duplicate gap ID")
    for gap in gaps:
        if not re.fullmatch(r"GAP-\d{3}", gap["id"]):
            raise ValueError(f"Invalid gap ID: {gap['id']}")
        if gap["priority"] not in {"P0", "P1", "P2"}:
            raise ValueError(f"Invalid priority: {gap['id']}")
        if gap["kind"] not in {
            "Missing",
            "Ambiguous",
            "Unanswered",
            "Evidence",
            "Decision",
        }:
            raise ValueError(f"Invalid kind: {gap['id']}")
        if gap["status"] not in {"Open", "Investigating", "Resolved", "Deferred"}:
            raise ValueError(f"Invalid status: {gap['id']}")
        for key in (
            "title",
            "question",
            "implementation_impact",
            "closure_criteria",
            "owner",
        ):
            if not gap[key].strip():
                raise ValueError(f"Empty {key}: {gap['id']}")
        if gap["status"] in {"Resolved", "Deferred"} and (
            not gap["resolution"] or not gap["resolution"].get("evidence")
        ):
            raise ValueError(f"Disposition needs evidence: {gap['id']}")
        if not set(gap["depends_on"]) <= identifiers - {gap["id"]}:
            raise ValueError(f"Invalid dependency: {gap['id']}")
        if not set(gap["related_ledger_entries"]) <= ledger_ids:
            raise ValueError(f"Unknown ledger entry: {gap['id']}")
        if not gap["sources"]:
            raise ValueError(f"Missing source location: {gap['id']}")
        for source in gap["sources"]:
            key = (
                source["path"],
                source["heading"],
                source["line_start"],
                source["line_end"],
            )
            if key not in known_sources:
                raise ValueError(f"Invalid source location: {gap['id']}")
            expected = next(
                item
                for item in sections[source["path"]]
                if item["line_start"] == source["line_start"]
            )
            if source["anchor"] != expected["anchor"]:
                raise ValueError(f"Invalid source anchor: {gap['id']}")
        for address in gap["investigation_leads"]:
            path = root / "evidence/hotline-server-1.9/queries" / f"D-{address}.c"
            if not path.is_file():
                raise ValueError(f"Missing investigation lead: {gap['id']} {address}")

    graph = {item["id"]: item["depends_on"] for item in gaps}
    checked = set()

    def visit(identifier: str, active: set[str]) -> None:
        if identifier in active:
            raise ValueError(f"Dependency cycle: {identifier}")
        if identifier in checked:
            return
        for dependency in graph[identifier]:
            visit(dependency, active | {identifier})
        checked.add(identifier)

    for identifier in graph:
        visit(identifier, set())
    covered = set()
    for item in register["review_coverage"]:
        key = (item["path"], item["heading"], item["line_start"], item["line_end"])
        if key in covered or key not in known_sources:
            raise ValueError("Invalid or duplicate review coverage entry")
        covered.add(key)
        if not set(item["related_gap_ids"]) <= identifiers:
            raise ValueError("Coverage references an unknown gap")
    if covered != known_sources:
        raise ValueError("The review coverage does not cover every input section")
    return manifest


def render(register: dict, manifest: dict) -> str:
    gaps = register["gaps"]
    priority = Counter(item["priority"] for item in gaps)
    kinds = Counter(item["kind"] for item in gaps)
    statuses = Counter(item["status"] for item in gaps)
    lines = [
        "# Hotline 1.9 protocol documentation gap analysis",
        "",
        paragraph(
            f"Reviewed on {register['last_updated']}: the corrected protocol guide, "
            "compatibility matrix and correction map. This register tracks gaps in "
            "the specification after the validity-ledger corrections. It does not "
            "reopen corrected findings or claim to resolve the remaining unknowns."
        ),
        "",
        paragraph(
            f"The sweep records **{len(gaps)} gaps** across "
            f"**{len(register['review_coverage'])} reviewed document sections**. "
            "These are documentation questions and proposed investigation priorities, "
            "not confirmed binary defects, security severity ratings or mxd test failures."
        ),
        "",
        "## Scope, evidence and status",
        "",
        paragraph(register["method"]),
        "",
        paragraph(
            "The corrected documents deliberately contain unresolved statements. "
            "Unanswered entries refine those into actionable questions. Missing and "
            "Ambiguous entries record omissions or under-specified requirements found "
            "by this sweep. Evidence entries need independent peer/runtime or mxd "
            "results; Decision entries need an explicit scope or compatibility policy."
        ),
        "",
        paragraph(
            "The prior oracle is the Mac PPC PEF data fork with SHA-256 "
            f"`{register['binary_sha256']}`. The "
            f"[validity ledger]({register['validity_ledger']}) and its hashed "
            "snapshots are unchanged. Listed Ghidra functions are investigation leads "
            "from that baseline. Dispositions cite subsequent evidence where available."
        ),
        "",
        paragraph(
            "The initial audit had all entries Open and unassigned. Deferred means a recorded "
            "scope/policy decision, not a solved protocol question. Resolved requires "
            "cited evidence, the corrected documentation and a checked closure criterion. "
            "A correction-map disposition or a function capture alone does not close a gap."
        ),
        "",
        "### Priority meanings",
        "",
        "| Priority | Meaning |",
        "| --- | --- |",
        "| P0 | Core codec, session/login or baseline-fixture work needed before claiming a usable core contract. |",
        "| P1 | Blocks completion of the named feature or a cross-cutting compatibility policy if that feature is in scope. |",
        "| P2 | Secondary operation semantics, evidence portability, peer coverage or project QA that still needs a recorded decision/result. |",
        "",
        paragraph(
            "These priorities are recommendations. GAP-001 and GAP-086 must establish "
            "the actual supported subset and release criteria; this audit does not "
            "invent mxd roadmap commitments. Client window rendering, tracker behaviour "
            "and HTTP tunnelling remain outside the stated wire-guide scope and are "
            "not counted as missing mandatory functionality."
        ),
        "",
        "### Counts",
        "",
        "| Dimension | Counts |",
        "| --- | --- |",
        f"| Priority | {', '.join(f'{key}: {priority[key]}' for key in sorted(priority))} |",
        f"| Kind | {', '.join(f'{key}: {kinds[key]}' for key in sorted(kinds))} |",
        f"| Status | {', '.join(f'{key}: {statuses[key]}' for key in sorted(statuses))} |",
        "",
        "## Suggested investigation order",
        "",
        paragraph(
            "Begin with core field schemas, framing/error/ID rules, nonempty-password "
            "encoding and the complete login state machine (GAP-002–GAP-025). Build "
            "provenanced native session fixtures alongside that work (GAP-084). "
            "Then complete presence/permission/message contracts, followed by the "
            "in-scope file, transfer, news and administration schemas. Peer-corpus "
            "identification (GAP-080) can proceed independently. Further mxd "
            "validation (GAP-085) remains on hold; its findings and resumption "
            "instructions are retained in mxd-validation.md. Dependency links "
            "identify shared prerequisite "
            "artefacts; they do not imply the unknown question has already been answered."
        ),
        "",
        "## Input provenance",
        "",
        paragraph(
            f"Audit captured at `{manifest['captured_at_utc']}`. The source checkout "
            f"has Git HEAD `{manifest['source_git_head']}`. The audit manifest records "
            "its worktree status. The hashes below identify the actual reviewed worktree "
            "contents; HEAD alone does not. Source line ranges in entries refer to "
            "the frozen snapshots, while section links point to the current documents."
        ),
        "",
        "| Reviewed input | SHA-256 | Frozen copy |",
        "| --- | --- | --- |",
    ]
    for item in manifest["inputs"]:
        lines.append(
            f"| [{item['path']}]({item['path']}) | `{item['sha256']}` | "
            f"[Snapshot]({item['snapshot']}) |"
        )
    lines.extend(
        [
            "",
            paragraph(
                f"[Audit manifest]({register['source_manifest']}); "
                "[machine-readable register](gap-register.json). No field or "
                "behaviour is silently made normative by being listed as a question."
            ),
            "",
            "## Gap index",
            "",
            "| ID | Priority | Kind | Area | Question | Status |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for gap in gaps:
        lines.append(
            f"| [{gap['id']}](#{gap['id'].lower()}) | {gap['priority']} | "
            f"{gap['kind']} | {gap['area']} | {gap['title']} | {gap['status']} |"
        )
    for area in dict.fromkeys(item["area"] for item in gaps):
        lines.extend(["", f"## {area}", ""])
        for gap in (item for item in gaps if item["area"] == area):
            sources = "; ".join(
                f"[{s['path']} — {s['heading']}]({s['path']}#{s['anchor']}) "
                f"(snapshot lines {s['line_start']}–{s['line_end']})"
                for s in gap["sources"]
            )
            related = ", ".join(gap["related_ledger_entries"]) or "No prior entry"
            leads = (
                ", ".join(
                    f"[{address}](evidence/hotline-server-1.9/queries/D-{address}.c)"
                    for address in gap["investigation_leads"]
                )
                or "Needs peer/source/project evidence or an explicit policy decision."
            )
            lines.extend(
                [
                    f"### {gap['id']}",
                    "",
                    f"#### {gap['title']}",
                    "",
                    bullet(
                        "Tracking",
                        f"{gap['priority']}; {gap['kind']}; {gap['status']}; owner: {gap['owner']}.",
                    ),
                    bullet("Sources", sources),
                    bullet("Question", gap["question"]),
                    bullet("Implementation impact", gap["implementation_impact"]),
                    bullet("Close when", gap["closure_criteria"]),
                    bullet("Prior ledger entries", related),
                    bullet("Investigation leads", leads),
                    bullet(
                        "Depends on",
                        gap_links(gap["depends_on"]) or "No prerequisite recorded.",
                    ),
                ]
            )
            if gap["resolution"]:
                for key, value in gap["resolution"].items():
                    if key == "evidence":
                        detail = "; ".join(value)
                    elif isinstance(value, str):
                        detail = value
                    else:
                        detail = json.dumps(value, ensure_ascii=False)
                    lines.append(bullet(key.replace("_", " ").capitalize(), detail))
            lines.append("")
    lines.extend(
        [
            "## Sweep coverage",
            "",
            paragraph(
                "Every heading/text block in the listed input documents was reviewed. "
                "Parent-section rows include gaps in their child sections. A section "
                "without a new local gap is associated with the applicable shared "
                "schema/fixture question. This table records documentation coverage, "
                "not exhaustive coverage of binary paths, clients or packet inputs."
            ),
            "",
            "| Document | Section | Snapshot lines | Related gaps |",
            "| --- | --- | --- | --- |",
        ]
    )
    for item in register["review_coverage"]:
        related = item["related_gap_ids"]
        display = (
            gap_links(related)
            if len(related) <= 8
            else f"{len(related)} gaps; see section-specific rows and JSON register"
        )
        lines.append(
            f"| {item['path']} | [{item['heading']}]({item['path']}#{item['anchor']}) | "
            f"{item['line_start']}–{item['line_end']} | {display} |"
        )
    lines.extend(
        [
            "",
            "## Maintaining this analysis",
            "",
            paragraph(
                "Edit gap-register.json as the canonical register and regenerate this "
                "report with the command below. Keep IDs stable: add new entries, "
                "cross-link overlaps and retain resolved/deferred records rather than "
                "renumbering or deleting them. Assign an owner and record evidence as "
                "work progresses; do not automatically close an entry because its "
                "containing document was rewritten."
            ),
            "",
            paragraph(
                "For Resolved, record resolution.evidence with exact binary/client "
                "hashes or repository revisions, queries/captures/test outputs, the "
                "updated document section and the checked closure outcome. For Deferred, "
                "record the scope decision, rationale and revisit condition under "
                "resolution.evidence; it remains an unanswered protocol question. "
                "Update last_updated when changing the register."
            ),
            "",
            paragraph(
                "When an audited source changes, preserve the old dated snapshots, "
                "capture a new source manifest/section inventory and refresh affected "
                "source ranges and coverage after review. The check deliberately "
                "rejects source drift rather than silently moving historical references. "
                "The baseline validity ledger and its original snapshots remain immutable."
            ),
            "",
            "From the repository root:",
            "",
            "```sh",
            "python3 scripts/render-protocol-gap-analysis.py",
            "python3 scripts/render-protocol-gap-analysis.py --check",
            "make audit-check",
            "```",
            "",
            "The check validates snapshot/current-source hashes, references, IDs,",
            "dependency acyclicity, section coverage and generated-report consistency.",
        ]
    )
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check without writing")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    directory = root
    register = json.loads((directory / "gap-register.json").read_text())
    manifest = validate(root, directory, register)
    generated = render(register, manifest)
    target = directory / "gap-analysis.md"
    checked_links = check_links(target, generated)
    for item in manifest["inputs"]:
        path = directory / item["path"]
        checked_links += check_links(path, path.read_text())
    if args.check:
        if target.read_text() != generated:
            raise ValueError("Generated gap analysis is stale; run without --check")
    else:
        target.write_text(generated)
    print(
        f"Validated {len(register['gaps'])} gaps and "
        f"{len(register['review_coverage'])} reviewed sections; "
        f"checked {checked_links} local link references"
    )


if __name__ == "__main__":
    main()
