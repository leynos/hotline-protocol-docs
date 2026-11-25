"""Test the GAP-011 preferences verifiers and their Makefile wiring.

Run the immutable
``evidence/gap-remediation/2026-11-24/receive-limit-preferences-01/verify.jq``
and ``evidence/gap-remediation/2026-11-24/post-session-preferences-01/verify.jq``
programs on retained records and single-change copies. The stopped-session
checks also use the retained
``evidence/gap-remediation/2026-11-13/receive-limit-origin-01/11-selected-consumer.json``
loader record. Extract the GAP-011 lines from the root Makefile's
``evidence-verify`` target and show that either changed corpus makes that
target fail. The falsified cases guard predicate behaviour beyond the
successful outputs recorded in ``tests/goldens/verifiers.json``.
"""

import json
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # tests execute fixed jq commands without a shell
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "evidence/gap-remediation/2026-11-24/receive-limit-preferences-01"
STOPPED = ROOT / "evidence/gap-remediation/2026-11-24/post-session-preferences-01"
LOADER = (
    ROOT
    / "evidence/gap-remediation/2026-11-13/receive-limit-origin-01"
    / "11-selected-consumer.json"
)


def jq_path() -> str:
    """Resolve the jq executable required by the evidence gate.

    Returns
    -------
    str
        Absolute executable path.
    """
    executable = shutil.which("jq")
    assert executable is not None, "jq is required by evidence-verify"
    return executable


def run_static(
    queries: Path, verifier: Path = STATIC / "verify.jq"
) -> subprocess.CompletedProcess[str]:
    """Run the seven-record verifier on a copied query directory.

    Parameters
    ----------
    queries : pathlib.Path
        Directory of query records.
    verifier : pathlib.Path
        jq program to execute.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Exit status and decoded output.
    """
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed jq argv, no shell
        [
            jq_path(),
            "-se",
            "-f",
            str(verifier),
            *map(str, sorted(queries.glob("*.json"))),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def run_stopped(
    summary: Path,
    verifier: Path = STOPPED / "verify.jq",
    corpus: Path = STOPPED,
    loader: Path = LOADER,
) -> subprocess.CompletedProcess[str]:
    """Run the stopped-disk verifier on a copied fork summary.

    Parameters
    ----------
    summary : pathlib.Path
        JSON summary to verify.
    verifier : pathlib.Path
        jq program to execute.
    corpus : pathlib.Path
        Directory containing the retained text inputs or their copies.
    loader : pathlib.Path
        Retained loader query or its copy.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Exit status and decoded output.
    """
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed jq argv, no shell
        [
            jq_path(),
            "-e",
            "-f",
            str(verifier),
            "--rawfile",
            "stat",
            str(corpus / "catalogue-record.txt"),
            "--rawfile",
            "application",
            str(corpus / "application-directory.txt"),
            "--rawfile",
            "staged",
            str(corpus / "staged-directory.txt"),
            "--slurpfile",
            "loader",
            str(loader),
            str(summary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def evidence_target_recipes(makefile: Path) -> list[str]:
    """Read recipe lines from the repository evidence target.

    Parameters
    ----------
    makefile : pathlib.Path
        Repository Makefile whose target wiring is under test.

    Returns
    -------
    list[str]
        Recipe lines in their original order.
    """
    lines = makefile.read_text().splitlines()
    start = next(
        index for index, line in enumerate(lines) if line.startswith("evidence-verify:")
    )
    recipes: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("\t"):
            recipes.append(line)
        elif line and not line.startswith("#"):
            break
    return recipes


def gap011_make_recipes(makefile: Path) -> list[str]:
    """Select the two GAP-011 jq recipes from the real evidence target.

    Parameters
    ----------
    makefile : pathlib.Path
        Repository Makefile whose target wiring is under test.

    Returns
    -------
    list[str]
        The exact jq recipe lines in their original order.
    """
    corpus_names = (STATIC.name, STOPPED.name)
    selected = [
        line
        for line in evidence_target_recipes(makefile)
        if any(f"/{name}; jq " in line for name in corpus_names)
    ]
    assert len(selected) == 2, "both GAP-011 jq recipes must remain in the target"
    assert all(
        sum(f"/{name}; jq " in line for line in selected) == 1 for name in corpus_names
    ), "each GAP-011 corpus must have exactly one jq recipe"
    return selected


@pytest.mark.parametrize(
    ("query", "field", "replacement"),
    [
        ("preferences-callers", "total", 2),
        ("preferences-input-name", "hex", "05 4e 6f 50 72 66"),
    ],
)
def test_static_verifier_rejects_falsified_queries(
    tmp_path: Path, query: str, field: str, replacement: int | str
) -> None:
    """A false caller count or input name must fail the actual jq recipe."""
    queries = tmp_path / "queries"
    queries.mkdir()
    for original in (STATIC / "queries").glob("*.json"):
        document = json.loads(original.read_text())
        if original.stem == query:
            document["result"]["structuredContent"][field] = replacement
        (queries / original.name).write_text(json.dumps(document))
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("format_word", 3),
        ("format_word", 4),
        ("bytes", 95),
        ("bytes", 120),
        ("sha256", "0" * 64),
    ],
)
def test_stopped_verifier_rejects_falsified_summary(
    tmp_path: Path, field: str, replacement: int | str
) -> None:
    """Exact format, size and digest checks reject independently false claims."""
    summary = json.loads((STOPPED / "fork-summary.json").read_text())
    summary[field] = replacement
    candidate = tmp_path / "fork-summary.json"
    candidate.write_text(json.dumps(summary))
    result = run_stopped(candidate)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_original_records_pass_both_verifiers(tmp_path: Path) -> None:
    """The falsification checks use working verifiers and valid baselines."""
    summary = tmp_path / "fork-summary.json"
    summary.write_bytes((STOPPED / "fork-summary.json").read_bytes())
    static = run_static(STATIC / "queries")
    stopped = run_stopped(summary)
    assert static.returncode == 0, static
    assert stopped.returncode == 0, stopped


@pytest.mark.parametrize("change", ["missing", "extra"], ids=["missing", "extra"])
def test_static_verifier_requires_exactly_seven_queries(
    tmp_path: Path, change: str
) -> None:
    """A missing or extra record breaks the seven-query trace."""
    queries = tmp_path / "queries"
    shutil.copytree(STATIC / "queries", queries)
    if change == "missing":
        (queries / "startup-arguments.json").unlink()
    else:
        shutil.copyfile(
            queries / "startup-arguments.json", queries / "extra-query.json"
        )
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def falsify_static_query(queries: Path, mutation: tuple[str, str, str, str]) -> None:
    """Change one named field in a copied query record.

    Parameters
    ----------
    queries : pathlib.Path
        Temporary query directory.
    mutation : tuple[str, str, str, str]
        Query name, field, original fragment, and replacement fragment.
    """
    query, field, original, replacement = mutation
    record = queries / f"{query}.json"
    document = json.loads(record.read_text())
    result_fields = document["result"]["structuredContent"]
    value = (
        result_fields["items"][0][field] if field == "from" else result_fields[field]
    )
    assert original in value, "fixture no longer contains the guarded observation"
    if field == "from":
        result_fields["items"][0][field] = value.replace(original, replacement)
    else:
        result_fields[field] = value.replace(original, replacement)
    record.write_text(json.dumps(document))


@pytest.mark.parametrize(
    "mutation",
    [
        ("preferences-callers", "from", "10000b9c", "10000b9d"),
        ("preferences-input-name", "hex", "05 50 72 65 66 73", "05 4e 6f 50 72 66"),
        (
            "following-input-name",
            "hex",
            "06 42 61 6e 6e 65 64 ",
            "06 42 61 6e 6e 65 65 ",
        ),
        (
            "post-preferences",
            "code",
            "FUN_1000a070(param_1,&local_20)",
            "FUN_1000a071(param_1,&local_20)",
        ),
        (
            "following-helper",
            "code",
            "FUN_1002af80(0xfffffffe,0,0x100902ed,0,0)",
            "FUN_1002af80(0xfffffffe,0,0x100902ee,0,0)",
        ),
    ],
    ids=["caller-address", "prefs-name", "banned-name", "post-call", "helper-call"],
)
def test_static_verifier_rejects_falsified_predicates(
    tmp_path: Path, mutation: tuple[str, str, str, str]
) -> None:
    """Every named query constraint rejects a single changed observation."""
    queries = tmp_path / "queries"
    shutil.copytree(STATIC / "queries", queries)
    falsify_static_query(queries, mutation)
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_static_verifier_rejects_changed_call_instruction(tmp_path: Path) -> None:
    """The startup call window must retain its recorded call instruction."""
    queries = tmp_path / "queries"
    shutil.copytree(STATIC / "queries", queries)
    record = queries / "call-window.json"
    document = json.loads(record.read_text())
    items = document["result"]["structuredContent"]["items"]
    instruction = next(item for item in items if item["address"] == "10000b9c")
    assert instruction["instruction"] == "bl 0x10008fd0", "unexpected call fixture"
    instruction["instruction"] = "bl 0x10008fd4"
    record.write_text(json.dumps(document))
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_stopped_verifier_rejects_false_outer_guard(tmp_path: Path) -> None:
    """The observed file must pass the loader's outer size and format guard."""
    summary = json.loads((STOPPED / "fork-summary.json").read_text())
    summary["passes_outer_loader_guard"] = False
    candidate = tmp_path / "fork-summary.json"
    candidate.write_text(json.dumps(summary))
    result = run_stopped(candidate)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("name", "original", "replacement"),
    [
        ("catalogue-record.txt", "Allocated", "Unallocated"),
        ("application-directory.txt", "-/r 11198:\tPrefs", "-/r 11198:\tPreft"),
        ("application-directory.txt", "d/d 11193:\tNews", "-/r 11193:\tBanned"),
        ("staged-directory.txt", "Agreement.txt", "Prefs"),
    ],
    ids=["allocation", "application-prefs", "application-banned", "staged-prefs"],
)
def test_stopped_verifier_rejects_changed_directory_records(
    tmp_path: Path, name: str, original: str, replacement: str
) -> None:
    """Catalogue and directory listings constrain the retained file claim."""
    corpus = tmp_path / "post-session"
    shutil.copytree(STOPPED, corpus)
    record = corpus / name
    content = record.read_text()
    assert original in content, "fixture no longer contains the guarded observation"
    record.write_text(content.replace(original, replacement, 1))
    result = run_stopped(corpus / "fork-summary.json", corpus=corpus)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize("corpus", ["stopped", "static"], ids=["stopped", "static"])
def test_make_evidence_verify_rejects_mutated_corpus(
    tmp_path: Path, corpus: str
) -> None:
    """The repository Make target stops at either falsified jq recipe."""
    target = tmp_path / "evidence/gap-remediation/2026-11-24"
    target.mkdir(parents=True)
    shutil.copytree(STATIC, target / STATIC.name)
    shutil.copytree(STOPPED, target / STOPPED.name)
    loader = tmp_path / LOADER.relative_to(ROOT)
    loader.parent.mkdir(parents=True)
    shutil.copyfile(LOADER, loader)
    if corpus == "stopped":
        record = target / STOPPED.name / "fork-summary.json"
        document = json.loads(record.read_text())
        document["format_word"] = 3
    else:
        record = target / STATIC.name / "queries/preferences-callers.json"
        document = json.loads(record.read_text())
        document["result"]["structuredContent"]["total"] = 2
    record.write_text(json.dumps(document))
    make = shutil.which("make")
    assert make is not None, "make is required by the repository gate"
    focused_makefile = tmp_path / "Makefile"
    focused_makefile.write_text(
        "evidence-verify:\n" + "\n".join(gap011_make_recipes(ROOT / "Makefile")) + "\n"
    )
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed Make target, no shell
        [make, "--no-print-directory", "-f", str(focused_makefile), "evidence-verify"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0, result
    assert "false\n" in result.stdout, result
