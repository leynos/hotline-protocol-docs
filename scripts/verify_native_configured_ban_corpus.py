"""Check the inventory, the failed first boot and the preboot assets of the corpus."""

from pcap_tcp import read_packets
from verify_native_configured_ban_constants import (
    ADMIN,
    BASE,
    CASES,
    CONTROLLER,
    DATA,
    EMPTY_PCAP_BYTES,
    LOW,
    MAX_CORPUS_FILES,
    MAX_PCAP_BYTES,
    MAX_SOURCE_BYTES,
    ORIGINAL_USER_COUNT,
    PHASES,
    PREFS,
    ROM,
    RSRC,
    SCHEMA,
)
from verify_native_configured_ban_support import Path, need, read, sha


def inventory(corpus: Path) -> dict:
    """Check the manifest, the file inventory, the hashes and the size bounds.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed manifest.
    """
    manifest = read(corpus / "manifest.json")
    need(
        corpus.name == SCHEMA
        and manifest["schema"] == SCHEMA
        and manifest["profile"] == "control-only"
        and manifest["full_file_baseline"] == "not_exercised"
        and manifest["failed_full_A7"] == ["C35", "C45", "C50"]
        and manifest["source_heads"]["protocol"]
        == "91f8e0a8c4bbeba719d008ee569f7427737a6cd4"
        and manifest["source_sha256"]
        == {"cases": CASES, "controller": CONTROLLER, "data": DATA, "rsrc": RSRC},
        "Corpus profile or source identity differs",
    )
    files = manifest["files"]
    actual = {
        str(path.relative_to(corpus))
        for path in corpus.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    need(actual == set(files), "Corpus inventory differs")
    for name, expected in files.items():
        need(sha(corpus / name) == expected, f"Corpus SHA differs: {name}")
    need(
        (corpus / "SHA256SUMS").read_text().splitlines()
        == [f"{value}  {name}" for name, value in sorted(files.items())],
        "SHA256SUMS differs",
    )
    need(
        sha(corpus / "sources/protocol/native_configured_ban_cases.py") == CASES
        and sha(corpus / "sources/protocol/native_configured_ban_control.py")
        == CONTROLLER,
        "Controller source snapshot differs",
    )
    need(
        len(files) <= MAX_CORPUS_FILES
        and sum(
            (corpus / name).stat().st_size
            for name in files
            if not name.endswith(".pcap")
        )
        <= MAX_SOURCE_BYTES
        and sum(
            (corpus / name).stat().st_size for name in files if name.endswith(".pcap")
        )
        <= MAX_PCAP_BYTES,
        "Corpus size bound exceeded",
    )
    return manifest


def failed_c65(corpus: Path) -> None:
    """Check the retained record of the failed first boot, which proves no contact.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    root = corpus / "native-configured-apply-c65"
    failure = read(root / "terminal.json")
    need(
        failure["owned_runtime_fd_processes"] == []
        and failure["guest_pcap_present"] is False
        and failure["working_disk_open"] is False
        and failure["host_primary_pcap_size"] == EMPTY_PCAP_BYTES
        and failure["display114_socket_present"] is False,
        "C65 failed-boot status differs",
    )
    need(not read_packets(root / "primary-syn.pcap"), "C65 primary SYN differs")
    need(
        "0 packets dropped by kernel" in (root / "host-recorder.log").read_text()
        and "status=1/FAILURE" in (root / "sheep-journal.log").read_text()
        and "Result=success" in (root / "system-units-terminal.txt").read_text()
        and "ActiveState=inactive" in (root / "user-units-terminal.txt").read_text(),
        "C65 failure or cleanup record differs",
    )
    note = (corpus / "c65-launch-failure-operator-note.md").read_text()
    need(
        "FileExistsError" in note
        and "not a native-server protocol observation" in note,
        "C65 operator failure classification missing",
    )


def preboot(corpus: Path) -> None:
    """Check the immutable preboot assets and the two-account state before the boot.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    asset = corpus / "assets"
    proof, hfs, source = (
        read(asset / name)
        for name in ("asset-proof.json", "preflight.json", "assets.json")
    )
    need(
        all(
            proof[name]["sha256"] == BASE
            for name in ("source_base", "prepared_base", "prepared_working")
        )
        and all(proof[name]["sha256"] == ROM for name in ("source_rom", "prepared_rom"))
        and source["base_disk_sha256"] == BASE
        and source["rom_sha256"] == ROM
        and hfs["app"]["app_data"]["sha256"] == DATA
        and hfs["app"]["app_rsrc"]["sha256"] == RSRC
        and hfs["app"]["prefs"] == {"catalog": "11202", "size": 175, "sha256": PREFS}
        and hfs["app"]["admin"]["sha256"] == ADMIN
        and hfs["app"]["fixture_low"]["sha256"] == LOW
        and hfs["original_user_count"] == ORIGINAL_USER_COUNT
        and hfs["banned_absent"] is True
        and hfs["owned_account_absent"] is True,
        "Immutable preboot assets or two-account state differ",
    )
    need(
        all(value == "free-at-preparation" for value in proof["ports"].values())
        and proof["display114_socket_absent"] is True
        and "Hotline19/Banned" not in "\n".join(hfs["catalog_entries"]),
        "Preboot port or Banned state differs",
    )
    old = read(asset / "plans-prepared/source-hashes.json")
    need(set(old) == set(PHASES), "Prepared plan inventory differs")
    for name in PHASES:
        plan = asset / "plans-prepared" / f"{name}.json"
        need(sha(plan) == old[name], "Original prepared plan SHA differs")
        need(
            read(plan)["environment"]["emulator_pid"] is None,
            "Prepared plan unexpectedly live",
        )
