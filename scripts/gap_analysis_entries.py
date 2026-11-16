"""Render the per-gap entries and the sweep coverage table of the report."""

import json
import typing as typ

from gap_analysis_text import bullet, gap_links, paragraph

# A gap with more related sections than this is summarised rather than listed.
MAX_LISTED_GAPS = 8


def gap_entry(gap: dict[str, typ.Any]) -> list[str]:
    """Render the heading and the bullets of one gap.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.

    Returns
    -------
    list[str]
        The Markdown lines of the entry, without the trailing blank line.
    """
    sources = "; ".join(
        f"[{s['path']} — {s['heading']}]({s['path']}#{s['anchor']}) "
        f"(snapshot lines {s['line_start']}\N{EN DASH}{s['line_end']})"
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
    lines = [
        f"### {gap['id']}",
        "",
        f"#### {gap['title']}",
        "",
        bullet(
            "Tracking",
            f"{gap['priority']}; {gap['kind']}; "
            f"{gap['status']}; owner: {gap['owner']}.",
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
    if gap["resolution"]:
        for key, value in gap["resolution"].items():
            if key == "evidence":
                detail = "; ".join(value)
            elif isinstance(value, str):
                detail = value
            else:
                detail = json.dumps(value, ensure_ascii=False)
            lines.append(bullet(key.replace("_", " ").capitalize(), detail))
    return lines


def area_sections(gaps: list[dict[str, typ.Any]]) -> list[str]:
    """Render one heading per area, each followed by its gap entries.

    Parameters
    ----------
    gaps : list[dict[str, typ.Any]]
        The register's ``gaps`` list.

    Returns
    -------
    list[str]
        The Markdown lines, in the order the areas first appear.
    """
    lines: list[str] = []
    for area in dict.fromkeys(item["area"] for item in gaps):
        lines.extend(["", f"## {area}", ""])
        for gap in (item for item in gaps if item["area"] == area):
            lines.extend(gap_entry(gap))
            lines.append("")
    return lines


def sweep_coverage(register: dict[str, typ.Any]) -> list[str]:
    """Render the sweep coverage table, one row per reviewed section.

    Parameters
    ----------
    register : dict[str, typ.Any]
        The parsed ``gap-register.json``.

    Returns
    -------
    list[str]
        The Markdown lines of the section and its table.
    """
    lines = [
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
    for item in register["review_coverage"]:
        related = item["related_gap_ids"]
        display = (
            gap_links(related)
            if len(related) <= MAX_LISTED_GAPS
            else f"{len(related)} gaps; see section-specific rows and JSON register"
        )
        lines.append(
            f"| {item['path']} | "
            f"[{item['heading']}]({item['path']}#{item['anchor']}) | "
            f"{item['line_start']}\N{EN DASH}{item['line_end']} | {display} |"
        )
    return lines
