"""Check the gate transcripts and retained unit of the login-extras corpus."""

import json
import re
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

UNIT = "mxd-c11-full-20261113-1922.service"
INVOCATION = "892ffaf601ef444c9d0e421f760e795b"
COUNTS = (
    (565, 565, 0),
    (569, 569, 0),
    (551, 551, 0),
    (3, 3, 0),
    (69, 69, 1),
    (8, 8, 0),
    (7, 7, 0),
)
FOCUSED = {
    "focused-final-router": 12,
    "focused-final-bdd": (6, 9),
    "focused-policy": 18,
    "focused-config": 5,
    "focused-cli": 4,
}
EXITS = (
    "check-fmt-final",
    "lint-4",
    "markdown",
    "focused-final-router",
    "focused-final-bdd",
    "focused-policy",
    "focused-config",
    "focused-cli",
)
CONTROLLED_THREADS = 2  # the test threads that the controlled full gate fixes


def refuse(message: str) -> typ.Never:
    """Refuse the evidence with a ValueError that carries ``message``.

    Parameters
    ----------
    message : str
        The reason the evidence is refused.

    Raises
    ------
    ValueError
        Always, with ``message``.
    """
    raise ValueError(message)


def properties(path: Path) -> dict[str, str]:
    """Parse retained systemd property lines without querying the current host.

    Parameters
    ----------
    path : pathlib.Path
        The retained property file.

    Returns
    -------
    dict[str, str]
        The property names and their values, as recorded.
    """
    return dict(line.split("=", 1) for line in path.read_text().splitlines())


def check_exit_codes(evidence: Path) -> None:
    """Check that every scoped gate recorded a zero exit.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    for name in EXITS:
        if (evidence / f"{name}.exit").read_text().strip() != "0":
            refuse(f"scoped gate exit differs: {name}")


def check_focused_counts(evidence: Path) -> None:
    """Check the pass count of each focused test log.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    for name, count in FOCUSED.items():
        summaries = re.findall(
            r"test result: ok\. (\d+) passed; 0 failed;",
            (evidence / f"{name}.log").read_text(),
        )
        expected = (count,) if isinstance(count, int) else count
        if tuple(map(int, summaries)) != expected:
            refuse(f"focused test count differs: {name}")


def check_transcripts(evidence: Path) -> None:
    """Check the format, lint and Markdown gate transcripts.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    fmt = (evidence / "check-fmt-final.log").read_text()
    lint = (evidence / "lint-4.log").read_text()
    markdown = (evidence / "markdown.log").read_text()
    if "cargo fmt --all -- --check" not in fmt or "files left unchanged" not in fmt:
        refuse("format gate transcript differs")
    if "cargo clippy" not in lint or "whitaker --all" not in lint:
        refuse("lint gate transcript differs")
    if (
        "Summary: 0 error(s)" not in markdown
        or "All diagrams validated successfully" not in markdown
    ):
        refuse("Markdown gate transcript differs")


def check_full_script(evidence: Path) -> None:
    """Check that the controlled full-gate script sets the required environment.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    script = (evidence / "full/run-full.sh").read_text()
    required = (
        "export CARGO_NET_OFFLINE=true",
        "export CARGO_BUILD_JOBS=1",
        "export NEXTEST_TEST_THREADS=2",
        'export PG_EMBED_ROOT="$base/root"',
        "export PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install",
        "unset PG_DATA_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS",
        "test-rstest-bdd-ui: export CARGO_TARGET_DIR :=",
        "--no-print-directory",
        ' test > "$base/full.log"',
    )
    if not all(value in script for value in required):
        refuse("controlled full-gate command or environment differs")


def check_full_log(evidence: Path) -> None:
    """Check the seven nextest profile summaries and the doctest summaries.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    full = (evidence / "full/full.log").read_text()
    counts = tuple(
        tuple(map(int, row))
        for row in re.findall(
            r"Summary \[.*?\] (\d+) tests run: (\d+) passed, (\d+) skipped", full
        )
    )
    if counts != COUNTS:
        refuse("seven nextest profile summaries differ")
    if (
        "test result: ok. 7 passed; 0 failed; 0 ignored" not in full
        or "test result: ok. 5 passed; 0 failed; 4 ignored" not in full
    ):
        refuse("doctest summaries differ")


def check_unit(evidence: Path) -> None:
    """Check the retained unit identity, its final state and the terminal process.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    initial = properties(evidence / "full/unit-initial-props.txt")
    final = properties(evidence / "full/unit-final-props.txt")
    terminal = properties(evidence / "full/terminal-mainpid.txt")
    for props in (initial, final, terminal):
        if props.get("Id") != UNIT or props.get("InvocationID") != INVOCATION:
            refuse("retained unit identity differs")
    if not all(
        final.get(key) == value
        for key, value in {
            "ActiveState": "active",
            "SubState": "exited",
            "Type": "oneshot",
            "TimeoutStartUSec": "40min",
            "TimeoutStopUSec": "30s",
            "RemainAfterExit": "yes",
            "Result": "success",
            "ExecMainCode": "1",
            "ExecMainStatus": "0",
        }.items()
    ):
        refuse("retained unit-derived exit differs")
    if not all(
        terminal.get(key) == value
        for key, value in {
            "MainPID": "0",
            "Result": "success",
            "ExecMainStatus": "0",
        }.items()
    ):
        refuse("retained terminal process state differs")


def check_full_exit_and_manifest(evidence: Path) -> None:
    """Check the full-gate exit status and the manifest's unit and thread count.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    if (evidence / "full/full.exit").read_text().strip() != "0":
        refuse("full gate script exit differs")
    manifest = json.loads((evidence / "manifest.json").read_text())
    if manifest.get("full_unit") != UNIT or manifest.get("invocation_id") != INVOCATION:
        refuse("manifest unit or controlled thread count differs")
    if manifest.get("controlled_test_threads") != CONTROLLED_THREADS:
        refuse("manifest unit or controlled thread count differs")


def gate_contract(evidence: Path) -> None:
    """Read gate exits, profile counts, doctests, and retained unit identity.

    Parameters
    ----------
    evidence : pathlib.Path
        The corpus directory.
    """
    check_exit_codes(evidence)
    check_focused_counts(evidence)
    check_transcripts(evidence)
    check_full_script(evidence)
    check_full_log(evidence)
    check_unit(evidence)
    check_full_exit_and_manifest(evidence)
