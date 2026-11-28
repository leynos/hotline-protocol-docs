"""Exercise the retained Classic label jq gate on copied offline evidence.

The tests run the exact ``evidence-verify`` recipe from the root Makefile.
Each changed input is a temporary copy; the checksum-pinned Java extractor,
recorded locations, and jq program remain untouched.
"""

import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # fixed local Make command without a shell
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CORPUS = Path("evidence/gap-remediation/2026-11-24/classic-privilege-labels-01")
SEGMENT = Path(
    "evidence/gap-remediation/2026-11-14/classic-privilege-discovery-01/raw/segments.json"
)
ANCHOR = Path(
    "evidence/gap-remediation/2026-11-14/classic-privilege-followups-01/classic-privilege-xrefs-01/raw/class-bytes.json"
)


def copied_gate(tmp_path: Path) -> Path:
    """Copy every input of the retained recipe into an isolated Make root.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Temporary root for the copied records.

    Returns
    -------
    pathlib.Path
        Makefile containing the original recipe line.
    """
    for relative in (CORPUS, SEGMENT, ANCHOR):
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copyfile(source, target)
    marker = f"/{CORPUS.name}; jq "
    recipes = [
        line
        for line in (ROOT / "Makefile").read_text().splitlines()
        if line.startswith("\t") and marker in line
    ]
    assert len(recipes) == 1, "Classic label recipe must remain in evidence-verify"
    makefile = tmp_path / "Makefile"
    makefile.write_text("evidence-verify:\n" + recipes[0] + "\n")
    return makefile


def run_gate(tmp_path: Path, makefile: Path) -> subprocess.CompletedProcess[str]:
    """Run the selected repository recipe under Make.

    Parameters
    ----------
    tmp_path : pathlib.Path
        Isolated working directory.
    makefile : pathlib.Path
        Makefile with the exact selected recipe.

    Returns
    -------
    subprocess.CompletedProcess[str]
        Captured exit status and output.
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


def test_retained_classic_label_recipe_passes(tmp_path: Path) -> None:
    """All archived inputs satisfy the actual evidence recipe."""
    result = run_gate(tmp_path, copied_gate(tmp_path))
    assert result.returncode == 0, result
    assert result.stdout.endswith("true\n"), result


@pytest.mark.parametrize(
    ("relative", "old", "new"),
    [
        (
            CORPUS / "locations.txt",
            "input 7f286e3f8941c226",
            "input 8f286e3f8941c226",
        ),
        (
            CORPUS / "locations.txt",
            "previous-byte=11 length=17",
            "previous-byte=10 length=17",
        ),
        (
            CORPUS / "locations.txt",
            "previous-byte=14 length=20",
            "previous-byte=14 length=19",
        ),
        (
            CORPUS / "locations.txt",
            "Can Disconnect Users text=1014c6ef previous-byte=14 length=20",
            "Can Disconnect Users text=1014c6ef previous-byte=13 length=20",
        ),
        (
            CORPUS / "locations.txt",
            "section sha256 54007ccb",
            "section sha256 64007ccb",
        ),
        (
            CORPUS / "locations.txt",
            "CMyAdminEditUserWin text=1014fef8",
            "CMyAdminEditUserWin text=1014fef9",
        ),
        (
            CORPUS / "locations.txt",
            "Can Disconnect Users text=1014fd7b previous-byte=14 length=20",
            "",
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"loaded_text_address": "1014c725"',
            '"loaded_text_address": "1014c726"',
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"packed_text_offset": "14d33c"',
            '"packed_text_offset": "14d33d"',
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"packed_text_offset": "14f9b4"',
            '"packed_text_offset": "14f9b5"',
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"packed_text_offset": "14d306"',
            '"packed_text_offset": "14d307"',
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"packed_text_offset": "14f97e"',
            '"packed_text_offset": "14f97f"',
        ),
        (
            CORPUS / "length-byte-crosscheck.json",
            '"loaded_length_address": "1014c724"',
            '"loaded_length_address": "1014c725"',
        ),
        (
            CORPUS / "manifest.json",
            '"unpacked_size": 149225',
            '"unpacked_size": 149224',
        ),
        (SEGMENT, '"end": "10159ef8"', '"end": "10159ef7"'),
        (SEGMENT, '"start": "10135810"', '"start": "10135811"'),
        (
            ANCHOR,
            '"structuredContent": {\n      "address": "1014fef8"',
            '"structuredContent": {\n      "address": "1014fef9"',
        ),
        (ANCHOR, '"ascii": "CMyAdminEditUserWin', '"ascii": "CMyAdminEditUserWix'),
    ],
    ids=[
        "input-hash",
        "prefix",
        "pascal-length",
        "disconnect-prefix",
        "section-hash",
        "class-location",
        "label-count",
        "text-address",
        "packed-text-first-send",
        "packed-text-second-send",
        "packed-text-first-disconnect",
        "packed-text-second-disconnect",
        "length-address",
        "section-size",
        "segment-end",
        "segment-start",
        "anchor-address",
        "class-anchor",
    ],
)
def test_classic_label_recipe_rejects_single_false_observation(
    tmp_path: Path, relative: Path, old: str, new: str
) -> None:
    """Each independent source constraint rejects a one-field false record."""
    makefile = copied_gate(tmp_path)
    candidate = tmp_path / relative
    content = candidate.read_text()
    assert old in content, "guarded observation changed in the archive"
    candidate.write_text(content.replace(old, new, 1))
    result = run_gate(tmp_path, makefile)
    assert result.returncode != 0, result
    assert "false\n" in result.stdout, result
