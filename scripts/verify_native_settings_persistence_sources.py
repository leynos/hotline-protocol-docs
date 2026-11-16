"""Check the inventory and the source identities of the persistence corpus."""

from pathlib import Path

from pinned_source import pinned_bytes
from protocol_capture import digest
from verify_native_settings_persistence_core import (
    A46_SOURCES,
    A48_SOURCES,
    PHASES,
    Json,
    read_json,
    require,
)

SCHEMA_VERSION = 1
CORPUS_NAME = "native-settings-persistence-01"
SHARED_SOURCES = (
    "native_control_readiness.py",
    "native_ban_control_cases.py",
    "pcap_tcp.py",
    "protocol_capture.py",
)


def manifest_identity(manifest: Json) -> None:
    """Check the manifest's schema, corpus, scope and lock deviation.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The corpus manifest.
    """
    require(manifest["schema_version"] == SCHEMA_VERSION, "Corpus schema differs")
    require(manifest["corpus"] == CORPUS_NAME, "Wrong corpus")
    require(
        manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised",
        "Control-only scope differs",
    )
    require(
        "did not hold canonical oracle.lock"
        in manifest["phase2_oracle_lock_deviation"],
        "A48 lock deviation missing",
    )


def file_inventory(corpus: Path, manifest: Json) -> None:
    """Check the files on disk against the manifest and ``SHA256SUMS``.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    """
    actual = {str(p.relative_to(corpus)) for p in corpus.rglob("*") if p.is_file()}
    declared = set(manifest["files"])
    require(
        actual == declared | {"manifest.json", "SHA256SUMS"},
        "Corpus file inventory differs",
    )
    for name, record in manifest["files"].items():
        path = corpus / name
        require(
            path.is_file() and path.stat().st_size == record["bytes"],
            f"Corpus size differs: {name}",
        )
        require(
            digest(path.read_bytes()) == record["sha256"],
            f"Corpus hash differs: {name}",
        )
    lines = (corpus / "SHA256SUMS").read_text().splitlines()
    expected = {
        f"{digest((corpus / name).read_bytes())}  {name}"
        for name in declared | {"manifest.json"}
    }
    require(
        set(lines) == expected and len(lines) == len(expected), "SHA256SUMS differs"
    )


def inventory(corpus: Path) -> Json:
    """Check the corpus manifest, its files and their checksum list.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The manifest.
    """
    manifest = read_json(corpus / "manifest.json")
    manifest_identity(manifest)
    file_inventory(corpus, manifest)
    return manifest


def recorded_sources(corpus: Path) -> None:
    """Check the retained A46 and A48 sources against their recorded digests.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    for phase, expected in (("a46", A46_SOURCES), ("a48", A48_SOURCES)):
        for name, value in expected.items():
            require(
                digest((corpus / "source" / phase / name).read_bytes()) == value,
                f"{phase} source differs: {name}",
            )


def shared_sources(corpus: Path) -> None:
    """Check the shared sources of the A48 run against their pinned bytes.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    for name in SHARED_SOURCES:
        require(
            digest((corpus / "source/a48" / name).read_bytes())
            == digest(pinned_bytes(name)),
            f"Shared verifier source differs: {name}",
        )


def planned_sources(directory: Path) -> Json:
    """Read the digest of each script that a phase's planner recorded.

    A directory of plans made before decision D31 holds ``source-code-sha256.json``,
    a digest for each of four scripts. One made after it holds
    ``source-code-identity.json``, the path and digest of each module of the
    runner's set, and a name that follows from each path gives the same shape.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.

    Returns
    -------
    dict[str, typing.Any]
        The digest of each script, by file name.
    """
    legacy = directory / "plans/source-code-sha256.json"
    identity = directory / "plans/source-code-identity.json"
    if not legacy.exists() and identity.exists():
        return {
            Path(item["path"]).name: item["sha256"]
            for item in read_json(identity)["files"]
        }
    return read_json(legacy)


def phase_pins(corpus: Path, phase: int) -> None:
    """Check the source and plan digests that one phase's planner recorded.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    phase : int
        The phase number, 1 or 2.
    """
    directory = corpus / f"phase{phase}"
    planned = planned_sources(directory)
    for name, value in planned.items():
        source = (
            corpus
            / "source"
            / ("a46" if phase == 1 and name in A46_SOURCES else "a48")
            / name
        )
        require(
            digest(source.read_bytes()) == value,
            f"Phase {phase} source pin differs: {name}",
        )
    plan_hashes = read_json(directory / "plans/source-hashes.json")
    for case, value in plan_hashes.items():
        require(
            digest((directory / "plans" / f"{case}.json").read_bytes()) == value,
            f"Phase {phase} plan pin differs: {case}",
        )


def source_identity(corpus: Path) -> None:
    """Check every source and plan identity that the corpus records.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    recorded_sources(corpus)
    shared_sources(corpus)
    for phase in PHASES:
        phase_pins(corpus, phase)
