"""Test the retained field-161 scanner and its offline Make recipe.

The archived ``discover-reads.py.as-run.txt`` is executed unchanged against
synthetic PEF sections. The repository recipe is tested with copied records;
no native program, Ghidra session, or protocol peer is started.
"""

import json
import runpy
import shutil
import struct
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # fixed local Make command without a shell
import typing as typ
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path("evidence/gap-remediation/2026-11-24/field161-readers-01")
IMAGE = Path("evidence/hotline-server-1.9/inputs/HLserver19.pef")
DIGEST = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"


def synthetic_image(words: list[int]) -> bytes:
    """Make a minimal PEF image with one initialized code section.

    Parameters
    ----------
    words : list[int]
        PowerPC instructions to place in the section.

    Returns
    -------
    bytes
        Synthetic input accepted by the archived section parser.
    """
    start = 0x80
    packed = 4 * len(words)
    image = bytearray(start + packed)
    struct.pack_into(
        ">iIIIIIBBBB", image, 40, 0, 0x11C3C, 0, packed, packed, start, 0, 0, 0, 0
    )
    for index, word in enumerate(words):
        struct.pack_into(">I", image, start + index * 4, word)
    return bytes(image)


def instruction(
    opcode: int, displacement: int, register: int = 5, base: int = 29
) -> int:
    """Encode the fields used by the archived read classifier.

    Parameters
    ----------
    opcode : int
        Primary PowerPC opcode.
    displacement : int
        Signed sixteen-bit displacement.
    register : int
        Destination register.
    base : int
        Base register.

    Returns
    -------
    int
        Encoded instruction word.
    """
    return opcode << 26 | register << 21 | base << 16 | displacement & 0xFFFF


def scan(
    image: bytes, capsys: pytest.CaptureFixture[str], digest: str = DIGEST
) -> dict[str, typ.Any]:
    """Execute the immutable scanner on the supplied synthetic bytes.

    Parameters
    ----------
    image : bytes
        Test PEF image.
    capsys : pytest.CaptureFixture[str]
        Captured scanner output.
    digest : str
        Digest returned by the synthetic hash fixture.

    Returns
    -------
    dict[str, typ.Any]
        Scanner report.
    """
    with (
        mock.patch.object(Path, "read_bytes", return_value=image),
        mock.patch(
            "hashlib.sha256", return_value=SimpleNamespace(hexdigest=lambda: digest)
        ),
    ):
        runpy.run_path(str(ROOT / CORPUS / "discover-reads.py.as-run.txt"))
    return json.loads(capsys.readouterr().out)


@pytest.mark.parametrize(
    ("opcode", "register", "width"),
    [
        (32, 5, 4),
        (33, 5, 4),
        (34, 5, 1),
        (35, 5, 1),
        (40, 5, 2),
        (41, 5, 2),
        (42, 5, 2),
        (43, 5, 2),
        (46, 31, 4),
        (46, 24, 32),
        (48, 5, 4),
        (49, 5, 4),
        (50, 5, 8),
        (51, 5, 8),
    ],
)
def test_direct_read_widths(
    opcode: int, register: int, width: int, capsys: pytest.CaptureFixture[str]
) -> None:
    """Every supported load opcode reports its actual width at field 161."""
    report = scan(synthetic_image([instruction(opcode, 0x41C, register)]), capsys)
    expected = {
        "address": "10011c3c",
        "opcode": opcode,
        "base_register": 29,
        "displacement": 1052,
        "read_width": width,
    }
    assert report["candidates"] == [expected], report


@pytest.mark.parametrize(
    "case",
    [
        (34, 0x41B, 5, 29, 0),
        (32, 0x41B, 5, 29, 1),
        (34, 0x41F, 5, 29, 1),
        (32, 0x420, 5, 29, 0),
        (46, 0x400, 31, 29, 0),
        (46, 0x400, 24, 29, 1),
        (14, 0x41C, 5, 0, 0),
        (14, 0x41C, 5, 29, 1),
        (14, 0x41F, 5, 29, 1),
        (14, 0x420, 5, 29, 0),
        (13, 0x41C, 5, 29, 0),
    ],
)
def test_overlap_and_address_formation(
    case: tuple[int, int, int, int, int],
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Boundary overlap, lmw width, and nonzero-base addi are classified."""
    opcode, displacement, register, base, expected = case
    report = scan(
        synthetic_image([instruction(opcode, displacement, register, base)]), capsys
    )
    rows = report["candidates"]
    assert isinstance(rows, list), report
    assert len(rows) == expected, report
    if expected:
        assert rows[0]["opcode"] == opcode, report


def test_scanner_rejects_wrong_image_digest(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The archived scanner refuses a different PEF identity before parsing."""
    image = synthetic_image([instruction(32, 0x41C)])
    with pytest.raises(AssertionError):
        scan(image, capsys, digest="0" * 64)


@pytest.mark.parametrize(
    "edits",
    [
        [(64, ">B", 1)],
        [(52, ">I", 8)],
        [(60, ">I", 0x1000)],
        [(52, ">I", 2), (56, ">I", 2)],
    ],
    ids=[
        "non-code-section",
        "unpacked-mismatch",
        "section-out-of-bounds",
        "unaligned-code",
    ],
)
def test_scanner_rejects_malformed_section(
    edits: list[tuple[int, str, int]], capsys: pytest.CaptureFixture[str]
) -> None:
    """Each PEF section guard independently rejects malformed metadata."""
    image = bytearray(synthetic_image([instruction(32, 0x41C)]))
    for offset, packing, value in edits:
        struct.pack_into(packing, image, offset, value)
    with pytest.raises(AssertionError):
        scan(bytes(image), capsys)


def copied_make_recipe(tmp_path: Path) -> Path:
    """Copy the archived inputs and select the repository's exact recipe.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Isolated Make root.

    Returns
    -------
    pathlib.Path
        Focused Makefile containing the unmodified recipe line.
    """
    if not (ROOT / IMAGE).is_file():
        pytest.skip("withheld PEF input is not materialized in this checkout")
    corpus = tmp_path / CORPUS
    corpus.parent.mkdir(parents=True)
    shutil.copytree(ROOT / CORPUS, corpus)
    image_copy = tmp_path / IMAGE
    image_copy.parent.mkdir(parents=True)
    image_copy.symlink_to(ROOT / IMAGE)
    marker = f"/{CORPUS.name}; python3 "
    recipes = [
        line
        for line in (ROOT / "Makefile").read_text().splitlines()
        if line.startswith("\t") and marker in line
    ]
    assert len(recipes) == 1, "field161 recipe must remain in evidence-verify"
    makefile = tmp_path / "Makefile"
    makefile.write_text("evidence-verify:\n" + recipes[0] + "\n")
    return makefile


def run_make(tmp_path: Path, makefile: Path) -> subprocess.CompletedProcess[str]:
    """Execute the focused Make target and capture its result.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Isolated working directory.
    makefile : pathlib.Path
        Makefile containing the real recipe.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Exit status and output.
    """
    executable = shutil.which("make")
    assert executable is not None, "make is required by evidence-verify"
    return subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed Make argv, no shell
        [executable, "--no-print-directory", "-f", str(makefile), "evidence-verify"],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )


def test_make_recipe_accepts_retained_evidence(tmp_path: Path) -> None:
    """The original scanner output and query records pass the exact recipe."""
    result = run_make(tmp_path, copied_make_recipe(tmp_path))
    assert result.returncode == 0, result
    assert result.stdout.endswith("true\n"), result


@pytest.mark.parametrize("mutation", ["candidate", "query"])
def test_make_recipe_rejects_falsified_copy(tmp_path: Path, mutation: str) -> None:
    """The exact Make recipe rejects false scanner or query evidence."""
    makefile = copied_make_recipe(tmp_path)
    if mutation == "candidate":
        candidate = tmp_path / CORPUS / "read-candidates.json"
        original = candidate.read_text()
        document = json.loads(original)
        assert len(document["candidates"]) == 1, document
        assert json.dumps(document, indent=2) + "\n" == original, (
            "no-op serialization must preserve the retained scanner bytes"
        )
        document["candidates"] = []
        candidate.write_text(json.dumps(document, indent=2) + "\n")
    else:
        query = tmp_path / CORPUS / "queries/field161-load.json"
        document = json.loads(query.read_text())
        assert document["program"]["name"] == "HLserver19.pef", document
        document["program"]["name"] = "different.pef"
        query.write_text(json.dumps(document))
    result = run_make(tmp_path, makefile)
    assert result.returncode != 0, result
    assert "differ" in result.stdout or "false" in result.stdout, result
