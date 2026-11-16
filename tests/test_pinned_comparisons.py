"""Check that each verifier compares a script's pinned bytes, not its live bytes.

Decision D29: a verifier that hashed a live script now asks ``pinned_source``
for the file at its pinned commit. Two things follow, and each is tested here
on the real retained corpora. A script can change without turning the verifier
red, and a wrong record or a commit that lacks the file turns it red with the
helper's domain error, so the comparison cannot pass by accident.
"""

import dataclasses as dc
import importlib.util
import json
import typing as typ
from pathlib import Path

import pinned_source
import pytest
import verify_native_settings_corpus
import verify_native_settings_persistence
import verify_native_transfer_repeat
import verify_native_ui_focus

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
GAP = ROOT / "evidence/gap-remediation"
ROOT_COMMIT = "e9f57158ac82fd0749743fc22e9a728a6356a471"  # holds no script at all
CORPUS_LAYOUT = {
    "transfer_repeat": GAP / "2026-11-14/native-transfer-repeat-01",
    "ui_focus": GAP / "2026-11-14/native-ui-focus-01",
    "settings_corpus": GAP / "2026-11-13/native-settings-01",
    "settings_persistence": GAP / "2026-11-14/native-settings-persistence-01",
}


def load_baseline_verifier() -> types.ModuleType:
    """Load ``verify-baseline-evidence.py``, whose name is not importable.

    Returns
    -------
    types.ModuleType
        The module.
    """
    spec = importlib.util.spec_from_file_location(
        "verify_baseline_evidence", SCRIPTS / "verify-baseline-evidence.py"
    )
    assert spec is not None, "expected spec is not None"
    assert spec.loader is not None, "expected spec.loader is not None"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@dc.dataclass(frozen=True, slots=True)
class Site:
    """One verifier that compares a pinned script.

    Attributes
    ----------
    name : str
        The label of the case.
    run : collections.abc.Callable[[], object]
        Runs the comparison on the retained corpus.
    pinned : str
        The pinned script that the comparison reads.
    """

    name: str
    run: cabc.Callable[[], object]
    pinned: str


SITES = [
    Site(
        "transfer_repeat",
        lambda: verify_native_transfer_repeat.verify(CORPUS_LAYOUT["transfer_repeat"]),
        "protocol_capture.py",
    ),
    Site(
        "ui_focus",
        lambda: verify_native_ui_focus.verify(CORPUS_LAYOUT["ui_focus"]),
        "protocol_capture.py",
    ),
    Site(
        "settings_corpus",
        lambda: verify_native_settings_corpus.verify(CORPUS_LAYOUT["settings_corpus"]),
        "native_settings_cases.py",
    ),
    Site(
        "settings_persistence",
        lambda: verify_native_settings_persistence.source_identity(
            CORPUS_LAYOUT["settings_persistence"]
        ),
        "native_control_readiness.py",
    ),
    Site(
        "baseline_evidence",
        lambda: load_baseline_verifier().verify(ROOT),
        "capture-ghidra-evidence.py",
    ),
]


def use_record(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, pinned: str, **changes: str
) -> None:
    """Make the verifiers read a copy of the record with one entry changed.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        Replaces the cached pins of the helper.
    tmp_path : pathlib.Path
        Where the altered record is written.
    pinned : str
        The file name of the entry to change.
    **changes : str
        The entry fields to overwrite.
    """
    document = json.loads(pinned_source.RECORD.read_text(encoding="utf-8"))
    for entry in document["sources"]:
        if entry["path"].endswith(f"/{pinned}"):
            entry.update(changes)
    record = tmp_path / "record.json"
    record.write_text(json.dumps(document), encoding="utf-8")
    pins = pinned_source.Pins(record, ROOT)
    monkeypatch.setattr(pinned_source, "default_pins", lambda: pins)


def ids(sites: cabc.Sequence[Site]) -> list[str]:
    """Name each case after its site.

    Returns
    -------
    list[str]
        The labels.
    """
    return [site.name for site in sites]


class PinnedComparisonTests:
    """Each comparison passes on the corpus and reads Git, not the live file."""

    @pytest.mark.parametrize("site", SITES, ids=ids(SITES))
    def test_the_comparison_passes_on_the_retained_corpus(self, site: Site) -> None:
        """The record and the corpus agree, so the verifier raises nothing."""
        site.run()

    @pytest.mark.parametrize("site", SITES, ids=ids(SITES))
    def test_a_wrong_recorded_hash_fails_the_verifier(
        self, site: Site, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A record whose hash is wrong is refused with a mismatch error."""
        use_record(monkeypatch, tmp_path, site.pinned, sha256="0" * 64)
        with pytest.raises(pinned_source.SourceMismatchError, match="record says"):
            site.run()

    @pytest.mark.parametrize("site", SITES, ids=ids(SITES))
    def test_a_commit_without_the_file_fails_the_verifier(
        self, site: Site, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """A pinned commit that lacks the script is refused with a path error."""
        use_record(monkeypatch, tmp_path, site.pinned, commit=ROOT_COMMIT)
        with pytest.raises(pinned_source.SourcePathError, match="does not contain"):
            site.run()
