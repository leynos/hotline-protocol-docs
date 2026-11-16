"""Test how the persistence verifier reads the sources that a planner recorded.

A directory of plans made before decision D31 holds ``source-code-sha256.json``;
one made after it holds ``source-code-identity.json``, the path and digest of each
module of the runner's set. The verifier checks either against the sources that
the corpus retained. The corpora here are synthetic; no capture is run.
"""

import hashlib
import json
import typing as typ

import pytest
import verify_native_settings_persistence_sources as sources

if typ.TYPE_CHECKING:
    from pathlib import Path

PHASE = 2  # every name of a synthetic corpus is looked up under ``source/a48``
MODULES = {
    "native_settings_persistence.py": b"runner\n",
    "native_settings_persistence_gates.py": b"gates\n",
}


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def corpus_with(tmp_path: Path, record: str, content: object) -> Path:
    """Write a corpus whose second phase holds one record of its sources.

    Returns
    -------
    pathlib.Path
        The corpus directory.
    """
    plans = tmp_path / f"phase{PHASE}/plans"
    plans.mkdir(parents=True)
    (plans / "source-hashes.json").write_text(json.dumps({}))
    (plans / record).write_text(json.dumps(content))
    retained = tmp_path / "source/a48"
    retained.mkdir(parents=True)
    for name, data in MODULES.items():
        (retained / name).write_bytes(data)
    return tmp_path


def identity_record() -> dict[str, typ.Any]:
    """Build the record that a planner writes after decision D31.

    Returns
    -------
    dict[str, typing.Any]
        The schema version and the path and digest of each module.
    """
    return {
        "schema_version": 1,
        "files": [
            {"path": f"scripts/{name}", "sha256": sha(data)}
            for name, data in MODULES.items()
        ],
    }


class SourcePinTests:
    """The digests of the scripts that a phase's planner recorded."""

    def test_the_record_of_the_earlier_form_is_read(self, tmp_path: Path) -> None:
        """A digest for each of the scripts that it names."""
        legacy = {name: sha(data) for name, data in MODULES.items()}
        corpus = corpus_with(tmp_path, "source-code-sha256.json", legacy)
        assert sources.planned_sources(corpus / f"phase{PHASE}") == legacy, legacy
        sources.phase_pins(corpus, PHASE)

    def test_the_identity_record_gives_the_same_digests_by_name(
        self, tmp_path: Path
    ) -> None:
        """The path is reduced to the file name that the corpus retains."""
        corpus = corpus_with(tmp_path, "source-code-identity.json", identity_record())
        planned = sources.planned_sources(corpus / f"phase{PHASE}")
        assert planned == {name: sha(data) for name, data in MODULES.items()}, planned
        sources.phase_pins(corpus, PHASE)

    def test_a_changed_retained_source_is_refused_by_name(self, tmp_path: Path) -> None:
        """The retained copy must be the one that was recorded."""
        corpus = corpus_with(tmp_path, "source-code-identity.json", identity_record())
        (corpus / "source/a48/native_settings_persistence_gates.py").write_bytes(b"x")
        message = r"^Phase 2 source pin differs: native_settings_persistence_gates\.py$"
        with pytest.raises(ValueError, match=message):
            sources.phase_pins(corpus, PHASE)

    def test_the_earlier_record_is_preferred_when_both_are_present(
        self, tmp_path: Path
    ) -> None:
        """A directory that holds both is read as the earlier form."""
        legacy = {
            "native_settings_persistence.py": sha(
                MODULES["native_settings_persistence.py"]
            )
        }
        corpus = corpus_with(tmp_path, "source-code-sha256.json", legacy)
        record = tmp_path / f"phase{PHASE}/plans/source-code-identity.json"
        record.write_text(json.dumps({"files": []}))
        assert sources.planned_sources(corpus / f"phase{PHASE}") == legacy, legacy

    def test_a_directory_with_neither_record_is_a_file_error(
        self, tmp_path: Path
    ) -> None:
        """The earlier record is read, as it always was, and is missing."""
        corpus = corpus_with(tmp_path, "unrelated.json", {})
        with pytest.raises(FileNotFoundError):
            sources.planned_sources(corpus / f"phase{PHASE}")
