"""Checksum-refreshed semantic controls for the frozen native path case."""

import hashlib
import json
import os
import shutil
import tempfile
import typing as typ
import unittest
from pathlib import Path

import pytest
import verify_native_path_fields as target
from native_plan import packet, payload
from protocol_capture import decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = Path(os.environ.get("MOTHRA_PATH_FIELD_CORPUS", target.CORPUS))


def read(corpus: Path, name: str) -> dict:
    """Load one JSON file of a corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    name : str
        The file name, relative to the corpus.

    Returns
    -------
    dict
        The parsed JSON value.
    """
    return json.loads((corpus / name).read_text())


def write(corpus: Path, name: str, value: object) -> None:
    """Write one JSON file of a corpus with a trailing newline.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    name : str
        The file name, relative to the corpus.
    value : object
        The JSON value to write.
    """
    (corpus / name).write_text(json.dumps(value, indent=2) + "\n")


def alter(corpus: Path, name: str, change: cabc.Callable[[dict], object]) -> None:
    """Apply a change to one JSON file of a corpus and write it back.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    name : str
        The file name, relative to the corpus.
    change : cabc.Callable[[dict], object]
        The change, which mutates the parsed value in place.
    """
    value = read(corpus, name)
    change(value)
    write(corpus, name, value)


def rechecksum(corpus: Path) -> None:
    """Refresh the manifest digests and the SHA256SUMS file of a corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory whose checksums are refreshed.
    """
    manifest = read(corpus, "manifest.json")
    manifest["files"] = {
        name: hashlib.sha256((corpus / name).read_bytes()).hexdigest()
        for name in manifest["files"]
    }
    write(corpus, "manifest.json", manifest)
    expected = {
        **manifest["files"],
        "manifest.json": target.sha(corpus / "manifest.json"),
    }
    (corpus / "SHA256SUMS").write_text(
        "\n".join(
            f"{digest}  {target.PREFIX}{name}"
            for name, digest in sorted(expected.items())
        )
        + "\n"
    )


def flip_byte(corpus: Path, name: str) -> None:
    """Flip the last bit of one corpus file.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    name : str
        The file name, relative to the corpus.
    """
    path = corpus / name
    raw = bytearray(path.read_bytes())
    raw[-1] ^= 1
    path.write_bytes(raw)


def change_pcap_payload(corpus: Path, name: str) -> None:
    """Rewrite the first TRTPHOTL marker of one PCAP file to TRTPHOTM.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    name : str
        The PCAP file name, relative to the corpus.
    """
    path = corpus / name
    raw = path.read_bytes()
    assert b"TRTPHOTL" in raw, "the handshake is in the capture"
    path.write_bytes(raw.replace(b"TRTPHOTL", b"TRTPHOTM", 1))


def consistent_report_change(corpus: Path) -> None:
    """Forge report frame/event/stream together, leaving independent PCAP raw."""
    path = "raw/epoch/coordinator/report.json"
    report = read(corpus, path)
    frame = report["frames"][-1]
    old = frame["raw_hex"]
    record = bytes(16) + (1).to_bytes(4, "big") + b"x"
    new = packet(0, frame["id"], payload([(200, record)]), reply=1)
    frame.update(decode_frame(bytes.fromhex(new)))
    frame["raw_hex"] = new
    changed = [
        e for e in report["events"] if e["event"] == "receive" and old in e["hex"]
    ]
    assert len(changed) == 1, "one receive event holds the text"
    changed[0]["hex"] = changed[0]["hex"].replace(old, new)
    report["streams"]["main"]["received_hex"] = report["streams"]["main"][
        "received_hex"
    ].replace(old, new)
    view = next(v for v in report["views"] if v["label"] == "final-barrier")
    view["fields"] = frame["fields"]
    view["names"] = ["78"]
    write(corpus, path, report)


def bad_report(corpus: Path, change: cabc.Callable[[dict], object]) -> None:
    """Alter the coordinator report of a corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    change : cabc.Callable[[dict], object]
        The change, which mutates the parsed report in place.
    """
    alter(corpus, "raw/epoch/coordinator/report.json", change)


def bad_result(corpus: Path, change: cabc.Callable[[list], object]) -> None:
    """Alter the result list of the coordinator report of a corpus.

    Parameters
    ----------
    corpus : Path
        The corpus directory.
    change : cabc.Callable[[list], object]
        The change, which mutates the parsed result list in place.
    """
    bad_report(corpus, lambda report: change(report["results"]))


class PathPublicationTests(unittest.TestCase):
    """Check the frozen native path case and its refreshed-checksum faults."""

    def test_frozen_case_replays(self) -> None:
        """Replay the frozen case and expect a pass."""
        assert target.verify(CORPUS)["status"] == "PASS", "frozen case passes"

    def test_symlinked_corpus_content_rejected(self) -> None:
        """Reject a corpus whose content is a symlink into the frozen case."""
        for name in ("derived/flows.json", "raw/epoch/sources"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp:
                case = Path(temp) / "corpus"
                shutil.copytree(CORPUS, case)
                path = case / name
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                path.symlink_to(CORPUS / name)
                rechecksum(case)
                with pytest.raises(ValueError, match="Corpus symlink"):
                    target.verify(case)

    def test_consistent_source_forgery_cannot_execute(self) -> None:
        """Keep a consistently forged dependency from executing."""
        with tempfile.TemporaryDirectory() as temp:
            case = Path(temp) / "corpus"
            shutil.copytree(CORPUS, case)
            sentinel = Path(temp) / "executed"
            name = "protocol_capture.py"
            altered = (
                (case / "raw/epoch/sources" / name).read_text()
                + "\nfrom pathlib import Path as _Path\n"
                + f"_Path({str(sentinel)!r}).touch()\n"
            )
            for root in (
                "raw/epoch/sources",
                "raw/preparation/proposed-sources",
            ):
                (case / root / name).write_text(altered)
            digest = target.sha(case / "raw/epoch/sources" / name)
            for path, key in (
                ("raw/epoch/source-freeze.json", "hashes"),
                ("raw/preparation/proposed-source-closure.json", "hashes"),
            ):
                alter(
                    case,
                    path,
                    lambda value, key=key: value[key].__setitem__(name, digest),
                )
            approval = case / "raw/preparation/approved-source-closure.sha256"
            approval.write_text(
                approval.read_text().replace(
                    next(
                        line
                        for line in approval.read_text().splitlines()
                        if line.endswith("scripts/" + name)
                    ).split()[0],
                    digest,
                )
            )
            rechecksum(case)
            with pytest.raises(ValueError, match="Trusted source approval"):
                target.verify(case)
            assert not sentinel.exists(), "Altered dependency executed"

    def test_checksum_refreshed_semantic_faults(self) -> None:
        """Reject each checksum-refreshed semantic fault with its own reason."""
        faults = (
            (
                "result-status",
                lambda c: bad_result(c, lambda r: r[0].__setitem__("status", 1)),
                "status",
            ),
            (
                "news-selection",
                lambda c: bad_result(
                    c, lambda r: r[6].__setitem__("selected_parent", "empty")
                ),
                "selected",
            ),
            (
                "foreign-view",
                lambda c: bad_report(
                    c,
                    lambda r: next(
                        v for v in r["views"] if v["label"] == "after-view-0-H"
                    )["names"].append("666f726569676e"),
                ),
                "View",
            ),
            (
                "type-view",
                lambda c: bad_report(
                    c,
                    lambda r: next(
                        v for v in r["views"] if v["label"] == "after-view-0-H"
                    )["types"].__setitem__("7030", "5445585400000000"),
                ),
                "View",
            ),
            (
                "false-eof",
                lambda c: bad_report(
                    c, lambda r: r["terminals"].__setitem__("main", "rst")
                ),
                "Case count/status/tail",
            ),
            (
                "tail",
                lambda c: bad_report(
                    c, lambda r: r["unparsed_hex"].__setitem__("main", "00")
                ),
                "Case count/status/tail",
            ),
            (
                "action-time",
                lambda c: bad_report(
                    c,
                    lambda r: r["actions"][7].__setitem__(
                        "elapsed_ns", r["actions"][7]["elapsed_ns"] + 10**10
                    ),
                ),
                "time bracket",
            ),
            (
                "frame-time",
                lambda c: bad_report(
                    c,
                    lambda r: r["frames"][0].__setitem__(
                        "arrival_elapsed_ns",
                        r["frames"][0]["arrival_elapsed_ns"] + 10**10,
                    ),
                ),
                "bracket",
            ),
            (
                "source-copy",
                lambda c: flip_byte(
                    c, "raw/epoch/sources/native_path_fields_control.py"
                ),
                "Approved frozen byte",
            ),
            (
                "pin-missing",
                lambda c: (
                    c / "raw/preparation/approved-source-closure.sha256"
                ).write_text(
                    (c / "raw/preparation/approved-source-closure.sha256")
                    .read_text()
                    .splitlines()[0]
                    + "\n"
                ),
                "Trusted source approval",
            ),
            (
                "stopped-marker",
                lambda c: alter(
                    c,
                    "derived/stopped-marker-catalogue.json",
                    lambda r: r["entries"].pop(),
                ),
                "Stopped marker",
            ),
            (
                "stopped-fork",
                lambda c: alter(
                    c,
                    "raw/epoch/stopped-hfs-summary.json",
                    lambda r: r["results"]["icat-admin"].__setitem__(
                        "sha256", "0" * 64
                    ),
                ),
                "fork",
            ),
            (
                "deadline",
                lambda c: alter(
                    c,
                    "raw/epoch/capture-ready.json",
                    lambda r: r.__setitem__(
                        "deadline_utc", "2026-11-15T00:00:00+00:00"
                    ),
                ),
                "Runtime/receipt",
            ),
            (
                "host-pcap",
                lambda c: flip_byte(c, "raw/epoch/primary-syn.pcap"),
                "capture receipt",
            ),
            (
                "guest-pcap",
                lambda c: change_pcap_payload(c, "raw/epoch/lab-guest.pcap"),
                "Conflicting TCP",
            ),
            (
                "namespace-pcap",
                lambda c: change_pcap_payload(c, "raw/epoch/lab-namespace.pcap"),
                "PCAP/report",
            ),
            ("report-vs-pcap", consistent_report_change, "PCAP/report"),
        )
        for label, fault, reason in faults:
            with (
                self.subTest(label=label),
                tempfile.TemporaryDirectory() as temp,
            ):
                case = Path(temp) / "corpus"
                shutil.copytree(CORPUS, case)
                fault(case)
                rechecksum(case)
                with pytest.raises(ValueError, match=reason):
                    target.verify(case)


if __name__ == "__main__":
    unittest.main()
