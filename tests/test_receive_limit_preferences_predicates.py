"""Falsify the remaining GAP-011 jq predicates on temporary evidence copies.

Use the retained verifiers and loader record through the shared offline
helpers in ``test_receive_limit_preferences_verify``. Keep image, call-window,
loader-text, catalogue and guard-boundary checks independently observable.
"""

import json
import re
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # fixed jq argv, no shell
import typing as typ

import pytest
from test_receive_limit_preferences_verify import (
    LOADER,
    STATIC,
    STOPPED,
    jq_path,
    run_static,
    run_stopped,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def copied_queries(tmp_path: Path) -> Path:
    """Copy the seven retained query records into a disposable directory.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Isolated pytest directory.

    Returns
    -------
    pathlib.Path
        Copied query directory.
    """
    queries = tmp_path / "queries"
    shutil.copytree(STATIC / "queries", queries)
    return queries


def change_query_field(
    record: Path, path: tuple[str, ...], *, replacement: int | str | bool
) -> None:
    """Set one scalar field in a copied query record.

    Parameters
    ----------
    record : pathlib.Path
        Copied JSON record to change.
    path : tuple[str, ...]
        Keys leading to the scalar.
    replacement : int | str | bool
        Falsified observation.
    """
    document = json.loads(record.read_text())
    node = document
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = replacement
    record.write_text(json.dumps(document))


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("name", "OtherServer.pef"),
        ("function_count", 1839),
        ("language_id", "PowerPC:LE:32:default"),
        ("sha256", "0" * 64),
    ],
    ids=["image-name", "function-count", "language", "image-digest"],
)
def test_static_verifier_rejects_changed_image_identity(
    tmp_path: Path, field: str, replacement: int | str
) -> None:
    """Each recorded program identity field constrains every query."""
    queries = copied_queries(tmp_path)
    change_query_field(
        queries / "startup-arguments.json", ("program", field), replacement=replacement
    )
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_static_verifier_rejects_query_error(tmp_path: Path) -> None:
    """An otherwise matching query marked as failed cannot support the trace."""
    queries = copied_queries(tmp_path)
    change_query_field(
        queries / "startup-arguments.json", ("result", "isError"), replacement=True
    )
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_static_verifier_rejects_more_callers(tmp_path: Path) -> None:
    """The caller enumeration must report that it is complete."""
    queries = copied_queries(tmp_path)
    change_query_field(
        queries / "preferences-callers.json",
        ("result", "structuredContent", "has_more"),
        replacement=True,
    )
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


def test_static_verifier_rejects_duplicate_query_id(tmp_path: Path) -> None:
    """Seven records still fail when a required query is duplicated."""
    queries = copied_queries(tmp_path)
    change_query_field(
        queries / "startup-arguments.json",
        ("query", "id"),
        replacement="preferences-callers",
    )
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("address", "replacement"),
    [
        ("10000b94", "addi r4,r31,0xd9"),
        ("10000b98", "addi r5,r31,0x45"),
        ("10000ba8", "bl 0x1000a464"),
    ],
    ids=["second-argument", "third-argument", "following-call"],
)
def test_static_verifier_rejects_other_call_window_changes(
    tmp_path: Path, address: str, replacement: str
) -> None:
    """Each remaining startup instruction is independently required."""
    queries = copied_queries(tmp_path)
    record = queries / "call-window.json"
    document = json.loads(record.read_text())
    items = document["result"]["structuredContent"]["items"]
    instruction = next(item for item in items if item["address"] == address)
    instruction["instruction"] = replacement
    record.write_text(json.dumps(document))
    result = run_static(queries)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("(0x5f < uVar4)", "(0x60 < uVar4)"),
        (
            "local_2020 == 4 || (local_2020 == 5)",
            "local_2020 == 4 || (local_2020 == 6)",
        ),
    ],
    ids=["size-check", "format-check"],
)
def test_stopped_verifier_rejects_changed_loader_fragment(
    tmp_path: Path, original: str, replacement: str
) -> None:
    """Both retained decompiler fragments constrain the loader claim."""
    loader = json.loads(LOADER.read_text())
    response = json.loads(loader["result"]["content"][0]["text"])
    assert original in response["code"], "loader fixture lacks guarded fragment"
    response["code"] = response["code"].replace(original, replacement, 1)
    loader["result"]["content"][0]["text"] = json.dumps(response)
    copied_loader = tmp_path / "11-selected-consumer.json"
    copied_loader.write_text(json.dumps(loader))
    result = run_stopped(STOPPED / "fork-summary.json", loader=copied_loader)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        ("File Path: /Hotline19/Prefs", "File Path: /Hotline19/Preft"),
        ("Catalog Record: 11198", "Catalog Record: 11199"),
        ("Size:\t119", "Size:\t118"),
        ("Resource fork size:\t0", "Resource fork size:\t1"),
    ],
    ids=["path", "catalogue-id", "data-size", "resource-size"],
)
def test_stopped_verifier_rejects_changed_catalogue_fields(
    tmp_path: Path, original: str, replacement: str
) -> None:
    """Each remaining catalogue field must match the retained observation."""
    corpus = tmp_path / "post-session"
    shutil.copytree(STOPPED, corpus)
    record = corpus / "catalogue-record.txt"
    content = record.read_text()
    assert original in content, "catalogue fixture lacks guarded field"
    record.write_text(content.replace(original, replacement, 1))
    result = run_stopped(corpus / "fork-summary.json", corpus=corpus)
    assert (result.returncode, result.stdout) == (1, "false\n"), result


@pytest.mark.parametrize(
    ("size", "format_word", "expected_exit"),
    [(95, 5, 1), (96, 5, 0), (119, 4, 0), (96, 3, 1)],
    ids=["at-limit", "past-limit", "accepted-format-four", "wrong-format"],
)
def test_outer_loader_guard_boundaries(
    size: int, format_word: int, expected_exit: int
) -> None:
    """Evaluate the verifier's own guard expression at its exact boundaries."""
    source = (STOPPED / "verify.jq").read_text()
    match = re.search(r"\.passes_outer_loader_guard == \(([^\n]+)\)", source)
    assert match is not None, "verifier no longer records a loader guard"
    result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed jq argv, no shell
        [jq_path(), "-e", match.group(1)],
        input=json.dumps({"bytes": size, "format_word": format_word}),
        capture_output=True,
        text=True,
        check=False,
    )
    assert (result.returncode, result.stdout) == (
        expected_exit,
        "true\n" if expected_exit == 0 else "false\n",
    ), result
