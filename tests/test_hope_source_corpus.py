"""Test that the HOPE source corpus still matches its recorded archives.

The server files of ``hope-source-01`` are snapshots of RCS archives, recorded
in the same manifest form as the first SynHX snapshot. The inherited extraction
script checks that form, so these tests run its checks on the new directory.
"""

import hashlib
import json
from pathlib import Path

import pytest
from script_loading import load_script

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-16/hope-source-01"

pytestmark = pytest.mark.skipif(
    not CORPUS.is_dir(), reason="the evidence tree is not present"
)


def test_server_snapshots_match_their_archives(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Each server snapshot is the recorded revision of its saved archive."""
    extract = load_script(
        ROOT / "scripts/extract-synhxd-evidence.py", "extract_synhxd_evidence"
    )
    extract.verify_snapshots(CORPUS / "server-source")
    printed = capsys.readouterr().out.splitlines()
    records = json.loads((CORPUS / "server-source/manifest.json").read_text("utf-8"))
    assert len(printed) == len(records) > 0, "expected one line per record"


def test_client_snapshots_match_their_recorded_hashes() -> None:
    """Each client snapshot has the hash that the manifest records for it."""
    manifest = json.loads((CORPUS / "manifest.json").read_text("utf-8"))
    inputs = manifest["client"]["inputs"]
    assert inputs, "expected client inputs"
    for entry in inputs:
        data = (CORPUS / entry["snapshot"]).read_bytes()
        assert hashlib.sha256(data).hexdigest() == entry["sha256"], entry["path"]


def test_the_digest_code_is_the_same_for_server_and_client() -> None:
    """The document describes one digest, cipher and compression source."""
    for name in ("hmac.c", "cipher.c", "compress.c", "rand.c"):
        server = (CORPUS / "server-source" / name).read_bytes()
        client = (CORPUS / "client-source" / f"{name}.txt").read_bytes()
        assert server == client, name
