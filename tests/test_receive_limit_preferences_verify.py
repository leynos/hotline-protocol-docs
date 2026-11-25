"""Exercise both GAP-011 evidence verifiers against falsified source records."""

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
    summary: Path, verifier: Path = STOPPED / "verify.jq"
) -> subprocess.CompletedProcess[str]:
    """Run the stopped-disk verifier on a copied fork summary.

    Parameters
    ----------
    summary : pathlib.Path
        JSON summary to verify.
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
            "-e",
            "-f",
            str(verifier),
            "--rawfile",
            "stat",
            str(STOPPED / "catalogue-record.txt"),
            "--rawfile",
            "application",
            str(STOPPED / "application-directory.txt"),
            "--rawfile",
            "staged",
            str(STOPPED / "staged-directory.txt"),
            "--slurpfile",
            "loader",
            str(LOADER),
            str(summary),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


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
    [("format_word", 3), ("bytes", 95), ("sha256", "0" * 64)],
)
def test_stopped_verifier_rejects_falsified_summary(
    tmp_path: Path, field: str, replacement: int | str
) -> None:
    """The format, size and file digest each constrain stopped-disk claims."""
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
