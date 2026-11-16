"""Assemble the generated gap analysis report, section by section.

The sections are concatenated in document order. Their text is the report's
text, so each helper returns its lines exactly as the single-function
renderer did.
"""

import re
import typing as typ
from collections import Counter

from gap_analysis_entries import area_sections, sweep_coverage
from gap_analysis_text import paragraph


def overview(register: dict[str, typ.Any]) -> list[str]:
    """Render the title, the scope and status, and the counts.

    Parameters
    ----------
    register : dict[str, typ.Any]
        The parsed ``gap-register.json``.

    Returns
    -------
    list[str]
        The Markdown lines from the title down to the counts table.
    """
    gaps = register["gaps"]
    priority = Counter(item["priority"] for item in gaps)
    kinds = Counter(item["kind"] for item in gaps)
    statuses = Counter(item["status"] for item in gaps)
    return [
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
            "not confirmed binary defects, security severity ratings or mxd test "
            "failures."
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
            "The initial audit had all entries Open and unassigned. Deferred means a "
            "recorded scope/policy decision, not a solved protocol question. Resolved "
            "requires cited evidence, the corrected documentation and a checked "
            "closure criterion. A correction-map disposition or a function capture "
            "alone does not close a gap."
        ),
        "",
        "### Priority meanings",
        "",
        "| Priority | Meaning |",
        "| --- | --- |",
        (
            "| P0 | Core codec, session/login or baseline-fixture work needed before "
            "claiming a usable core contract. |"
        ),
        (
            "| P1 | Blocks completion of the named feature or a cross-cutting "
            "compatibility policy if that feature is in scope. |"
        ),
        (
            "| P2 | Secondary operation semantics, evidence portability, peer "
            "coverage or project QA that still needs a recorded decision/result. |"
        ),
        "",
        paragraph(
            "These priorities are recommendations. GAP-001 and GAP-086 must establish "
            "the actual supported subset and release criteria; this audit does not "
            "invent mxd roadmap commitments. Client window rendering, tracker "
            "behaviour and HTTP tunnelling remain outside the stated wire-guide "
            "scope and are not counted as missing mandatory functionality."
        ),
        "",
        "### Counts",
        "",
        "| Dimension | Counts |",
        "| --- | --- |",
        (
            "| Priority | "
            f"{', '.join(f'{key}: {priority[key]}' for key in sorted(priority))} |"
        ),
        (f"| Kind | {', '.join(f'{key}: {kinds[key]}' for key in sorted(kinds))} |"),
        (
            "| Status | "
            f"{', '.join(f'{key}: {statuses[key]}' for key in sorted(statuses))} |"
        ),
    ]


def investigation_order() -> list[str]:
    """Render the suggested investigation order.

    Returns
    -------
    list[str]
        The Markdown lines of the section, with a leading blank line.
    """
    return [
        "",
        "## Suggested investigation order",
        "",
        paragraph(
            "Begin with core field schemas, framing/error/ID rules, nonempty-password "
            "encoding and the complete login state machine "
            "(GAP-002\N{EN DASH}GAP-025). Build provenanced native session fixtures "
            "alongside that work (GAP-084). "
            "Then complete presence/permission/message contracts, followed by the "
            "in-scope file, transfer, news and administration schemas. Peer-corpus "
            "identification (GAP-080) can proceed independently. Further mxd "
            "validation (GAP-085) remains on hold; its findings and resumption "
            "instructions are retained in mxd-validation.md. Dependency links "
            "identify shared prerequisite "
            "artefacts; they do not imply the unknown question has already been "
            "answered."
        ),
        "",
    ]


def provenance(manifest: dict[str, typ.Any]) -> list[str]:
    """Render the input provenance section and its table of reviewed inputs.

    Parameters
    ----------
    manifest : dict[str, typ.Any]
        The parsed audit manifest.

    Returns
    -------
    list[str]
        The Markdown lines of the section and its table.
    """
    lines = [
        "## Input provenance",
        "",
        paragraph(
            f"Audit captured at `{manifest['captured_at_utc']}`. The source checkout "
            f"has Git HEAD `{manifest['source_git_head']}`. The audit manifest records "
            "its worktree status. The hashes below identify the actual reviewed "
            "worktree contents; HEAD alone does not. Source line ranges in entries "
            "refer to the frozen snapshots, while section links point to the current "
            "documents."
        ),
        "",
        "| Reviewed input | SHA-256 | Frozen copy |",
        "| --- | --- | --- |",
    ]
    lines.extend(
        f"| [{item['path']}]({item['path']}) | `{item['sha256']}` | "
        f"[Snapshot]({item['snapshot']}) |"
        for item in manifest["inputs"]
    )
    return lines


def index(register: dict[str, typ.Any]) -> list[str]:
    """Render the link to the audit manifest and the gap index table.

    Parameters
    ----------
    register : dict[str, typ.Any]
        The parsed ``gap-register.json``.

    Returns
    -------
    list[str]
        The Markdown lines from the manifest link to the end of the index table.
    """
    gaps = register["gaps"]
    lines = [
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
    lines.extend(
        f"| [{gap['id']}](#{gap['id'].lower()}) | {gap['priority']} | "
        f"{gap['kind']} | {gap['area']} | {gap['title']} | {gap['status']} |"
        for gap in gaps
    )
    return lines


def maintenance() -> list[str]:
    """Render the maintenance section and the commands that regenerate the report.

    Returns
    -------
    list[str]
        The Markdown lines of the final section.
    """
    return [
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


def render(register: dict[str, typ.Any], manifest: dict[str, typ.Any]) -> str:
    """Render the complete Markdown gap analysis report.

    Parameters
    ----------
    register : dict[str, typ.Any]
        The parsed ``gap-register.json``.
    manifest : dict[str, typ.Any]
        The parsed audit manifest.

    Returns
    -------
    str
        The report, with runs of blank lines collapsed and one final newline.
    """
    lines = [
        *overview(register),
        *investigation_order(),
        *provenance(manifest),
        *index(register),
        *area_sections(register["gaps"]),
        *sweep_coverage(register),
        *maintenance(),
    ]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).rstrip() + "\n"
