"""Shared constants, checks and readers of the focus-event verifier."""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path


PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
DRIVER_SHA = "2fba0972f4d9a8e3845c4204dce150dd7c90da0e19a9e5720d5289e2c94faf01"
PREFIX_SHA = "b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c"
OBSERVER_SHA = "4a39d24fbc68f492558deacb4794829d145e7cc100bab0acb8945f5497d4b3d4"
AS_PREPARED_SHA = "deec49121248489d2eed9a2a2c63cdbc2422d3026147bb3cbce74b6fbe76018a"
APP_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
EXE_SHA = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
ROM_SHA = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
BASE_SHA = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
DOWNLOAD_BYTES = 98_304  # the retained download prefix, in bytes
A7_STEPS = 29  # the steps of the original A7 plan
A7_ACTIONS = 21  # the actions A7 completed before its timeout
EMULATOR_PID = 2_055_952  # the emulator process that the lab owned
DATA_PORT = 15_751  # the emulated data connection's port
PCAP_HEADER_BYTES = 24  # the bytes of a capture that holds no packet
PLATEAU_SECONDS = 5  # the quiet time before the focus click
OBSERVE_SECONDS = 10  # the observation time after the click returned
ACTIVATED_GOLD = 278  # gold pixels in the activated Log title
STOP_EXIT_ANOMALY = 5  # the unit stop that exited with status five
PNG_WIDTH = 1024
PNG_HEIGHT = 768
PNG_CHANNELS = 3  # red, green and blue, eight bits each
PNG_STRIDE = PNG_WIDTH * PNG_CHANNELS
FILTER_SUB = 1  # PNG filter types, by their numbers in the format
FILTER_UP = 2
FILTER_AVERAGE = 3
FILTER_PAETH = 4
GOLD_RED_MIN = 200  # thresholds that call a pixel gold
GOLD_GREEN_MIN = 130
GOLD_BLUE_MAX = 80
TITLE_BOX = (220, 35, 300, 46)  # the Log title, as x0, y0, x1, y1
PACKET_VIEWS = (
    ("guest", "10.0.2.2", "10.0.2.15", 5501, "lab-guest.pcap"),
    ("namespace", "127.0.0.1", "127.0.0.1", DATA_PORT, "lab-namespace.pcap"),
)


def require(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the public check shape
    reason: str,
) -> None:
    """Keep checks active even when Python runs with optimization enabled.

    Raises
    ------
    ValueError
        With ``reason``, when ``ok`` is false.
    """
    if not ok:
        message = reason
        raise ValueError(message)


def sha(path: Path) -> str:
    """Return the SHA-256 of a file's bytes.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict[str, typ.Any]:
    """Read a JSON document from a file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text(encoding="utf-8"))


def inventory(corpus: Path) -> None:
    """Check the corpus manifest, its file hashes and its source provenance.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-ui-focus-01", "Corpus schema differs")
    files = manifest["files"]
    actual = {
        str(p.relative_to(corpus))
        for p in corpus.rglob("*")
        if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        require(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    lines = [f"{digest}  {name}" for name, digest in sorted(files.items())]
    sums = (corpus / "SHA256SUMS").read_text(encoding="utf-8")
    require(sums.splitlines() == lines, "SHA list differs")
    provenance = load(corpus / "source-provenance.json")
    require(provenance["schema"] == manifest["schema"], "Provenance schema differs")
    require(
        set(provenance["sources"]) == set(files) - {"source-provenance.json"},
        "Source set differs",
    )
    for name, record in provenance["sources"].items():
        path = corpus / name
        require(
            sha(path) == record["sha256"] and path.stat().st_size == record["bytes"],
            f"Source differs: {name}",
        )
