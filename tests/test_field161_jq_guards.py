"""Falsify every retained field-161 jq assertion on copied JSON records."""

import json
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # fixed local jq argv without a shell
import typing as typ
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-24/field161-readers-01"
QUERY_IDS = (
    "constructor-caller",
    "constructor-refs",
    "field161-load",
    "field161-width",
    "login-builder-refs",
)
DIGEST = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"


@pytest.fixture
def copied(tmp_path: Path) -> Path:
    """Copy the retained jq inputs without needing the withheld PEF.

    Returns
    -------
    pathlib.Path
        Disposable corpus directory.
    """
    target = tmp_path / "field161-readers-01"
    shutil.copytree(CORPUS, target)
    return target


def record(copied: Path, name: str) -> dict[str, typ.Any]:
    """Read a copied JSON record.

    Returns
    -------
    dict[str, typing.Any]
        Parsed record.
    """
    return json.loads((copied / name).read_text())


def save(copied: Path, name: str, value: dict[str, typ.Any]) -> None:
    """Write only one falsified copied JSON record."""
    (copied / name).write_text(json.dumps(value, indent=2) + "\n")


def verify(
    copied: Path, names: tuple[str, ...] = QUERY_IDS
) -> subprocess.CompletedProcess[str]:
    """Run the real retained jq verifier on copied records.

    Returns
    -------
    subprocess.CompletedProcess[str]
        jq verdict and diagnostics.
    """
    executable = shutil.which("jq")
    assert executable is not None, "jq is needed for retained verifier tests"
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed jq argv, no shell
        [
            executable,
            "-se",
            "--slurpfile",
            "scan",
            str(copied / "read-candidates.json"),
            "-f",
            str(copied / "verify.jq"),
            *(str(copied / "queries" / f"{name}.json") for name in names),
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def assert_rejected(copied: Path) -> None:
    """Require a false jq verdict rather than a command or parse error."""
    result = verify(copied)
    assert result.returncode == 1, result
    assert result.stdout.strip() == "false", result
    assert not result.stderr, result


def test_retained_query_records_pass_jq(copied: Path) -> None:
    """The copied five-record baseline satisfies the retained verifier."""
    result = verify(copied)
    assert result.returncode == 0, result
    assert result.stdout.strip() == "true", result


def test_jq_rejects_missing_query_record(copied: Path) -> None:
    """The verifier requires all five query records."""
    result = verify(copied, QUERY_IDS[:-1])
    assert result.returncode == 1, result
    assert result.stdout.strip() == "false", result


def test_jq_rejects_duplicate_query_id(copied: Path) -> None:
    """A duplicate query ID cannot satisfy the unique-record lookup."""
    path = "queries/field161-width.json"
    document = record(copied, path)
    document["query"]["id"] = "field161-load"
    save(copied, path, document)
    result = verify(copied)
    assert result.returncode != 0, result


@pytest.mark.parametrize("name", QUERY_IDS)
@pytest.mark.parametrize(
    ("field", "wrong"),
    [
        ("name", "different.pef"),
        ("language_id", "PowerPC:LE:32:default"),
        ("function_count", 1841),
        ("sha256", "0" * 64),
    ],
)
def test_each_program_identity_field_rejects(
    copied: Path, name: str, field: str, wrong: object
) -> None:
    """Every query record carries its own checked program identity."""
    path = f"queries/{name}.json"
    document = record(copied, path)
    assert document["program"][field] != wrong, "mutation must change one value"
    document["program"][field] = wrong
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize("name", QUERY_IDS)
def test_each_query_error_flag_rejects(copied: Path, name: str) -> None:
    """An error response cannot stand in for any retained query result."""
    path = f"queries/{name}.json"
    document = record(copied, path)
    assert document["result"]["isError"] is False, "retained result must succeed"
    document["result"]["isError"] = True
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize("change", ["input_sha256", "section_bytes", "candidates"])
def test_each_scanner_claim_rejects(copied: Path, change: str) -> None:
    """The saved scanner digest, extent, and candidate set are checked."""
    document = record(copied, "read-candidates.json")
    wrong = {"input_sha256": "0" * 64, "section_bytes": 558873, "candidates": []}
    assert document[change] != wrong[change], "mutation must change one claim"
    document[change] = wrong[change]
    save(copied, "read-candidates.json", document)
    assert_rejected(copied)


@pytest.mark.parametrize("address", ["10011c3c", "10011c44", "10011c48"])
@pytest.mark.parametrize("change", ["address", "instruction"])
def test_each_load_instruction_rejects(copied: Path, address: str, change: str) -> None:
    """Each address-specific load-site instruction is independently checked."""
    path = "queries/field161-load.json"
    document = record(copied, path)
    items = document["result"]["structuredContent"]["items"]
    matches = [item for item in items if item["address"] == address]
    assert len(matches) == 1, "the retained address must occur once"
    matches[0][change] = "00000000" if change == "address" else "nop"
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize(
    "fragment", ["param_3 & 0xffff0000", "local_10,2)", "local_c,4)"]
)
def test_each_width_fragment_rejects(copied: Path, fragment: str) -> None:
    """Each saved width-code fragment is independently required."""
    path = "queries/field161-width.json"
    document = record(copied, path)
    content = document["result"]["structuredContent"]
    assert fragment in content["code"], "retained fragment must occur"
    content["code"] = content["code"].replace(fragment, "missing", 1)
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize("name", ["constructor-refs", "login-builder-refs"])
@pytest.mark.parametrize("field", ["total", "has_more", "from"])
def test_each_reference_claim_rejects(copied: Path, name: str, field: str) -> None:
    """Each reference count, continuation flag, and caller is checked."""
    path = f"queries/{name}.json"
    document = record(copied, path)
    content = document["result"]["structuredContent"]
    match field:
        case "from":
            content["items"][0]["from"] = "00000000"
        case "total":
            content["total"] = 2
        case _:
            content["has_more"] = True
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize(
    "fragment", ["FUN_10000160(iVar1)", "_DAT_10096074 = iVar1", "FUN_100007b0(iVar1)"]
)
def test_each_constructor_caller_fragment_rejects(copied: Path, fragment: str) -> None:
    """Each saved constructor call or store fragment is checked."""
    path = "queries/constructor-caller.json"
    document = record(copied, path)
    content = document["result"]["structuredContent"]
    assert fragment in content["code"], "retained fragment must occur"
    content["code"] = content["code"].replace(fragment, "missing", 1)
    save(copied, path, document)
    assert_rejected(copied)


@pytest.mark.parametrize(
    ("literal", "replacement"), [(DIGEST, "0" * 64), ("== 558872", "== 558873")]
)
def test_changed_jq_expectation_rejects(
    copied: Path, literal: str, replacement: str
) -> None:
    """A changed expected digest or section size fails against saved inputs."""
    path = copied / "verify.jq"
    source = path.read_text()
    assert source.count(literal) == 1, "only one verifier expectation changes"
    path.write_text(source.replace(literal, replacement, 1))
    assert_rejected(copied)
