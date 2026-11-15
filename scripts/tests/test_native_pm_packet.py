"""Checksum-updated faults for the bounded A29 PM corpus."""

import copy
import hashlib
import json
import typing as typ
from pathlib import Path

import pytest
from verify_native_pm_packet import verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-pm-01"
)
PM_ACTION = 33
FIELD_USER_ID = 103
FIELD_OPTIONS = 113
FIELD_QUOTE = 214
EXPECTED_RECEIVES = 2
TRUNCATED_STEPS = 18
FIELD_HEADER_BYTES = 4
COUNT_WORD_BYTES = 2


def sha(data: bytes) -> str:
    """Return the SHA-256 of ``data`` as hexadecimal.

    Returns
    -------
    str
        The digest.
    """
    return hashlib.sha256(data).hexdigest()


def rebuild_streams(report: dict[str, typ.Any]) -> None:
    """Recompute the per-connection streams from the retained events."""
    streams: dict[str, dict[str, str]] = {}
    for event in report["events"]:
        name = event["connection"]
        if not name:
            continue
        saved = streams.setdefault(name, {"sent_hex": "", "received_hex": ""})
        match event["event"]:
            case "send":
                saved["sent_hex"] += event["hex"]
            case "receive":
                saved["received_hex"] += event["hex"]
    report["streams"] = streams


def change_field(
    report: dict[str, typ.Any], action: int, field_id: int, new_value: bytes
) -> None:
    """Replace one field value of a frame, keeping its width.

    Raises
    ------
    ValueError
        If the field is absent, the width changes or the reads differ.
    """
    frame = next(f for f in report["frames"] if f["action"] == action)
    payload = bytearray.fromhex(frame["payload_hex"])
    offset = COUNT_WORD_BYTES
    for field in frame["fields"]:
        identifier = int.from_bytes(payload[offset : offset + 2], "big")
        size = int.from_bytes(payload[offset + 2 : offset + FIELD_HEADER_BYTES], "big")
        if identifier == field_id:
            if len(new_value) != size:
                message = "Test mutation must preserve field width"
                raise ValueError(message)
            start = offset + FIELD_HEADER_BYTES
            payload[start : start + size] = new_value
            field["hex"] = new_value.hex()
            break
        offset += FIELD_HEADER_BYTES + size
    else:
        message = "Test field absent"
        raise ValueError(message)
    frame["payload_hex"] = payload.hex()
    receives = [
        e for e in report["events"] if e["action"] == action and e["event"] == "receive"
    ]
    if len(receives) != EXPECTED_RECEIVES:
        message = "Expected header and one payload read"
        raise ValueError(message)
    receives[1]["hex"] = payload.hex()
    rebuild_streams(report)


class Corpus:
    """A symlinked copy of the PM corpus whose files can be replaced and resealed."""

    def __init__(self, root: Path) -> None:
        """Link every manifest file below ``root``."""
        self.root = root
        self.manifest = json.loads((BATCH / "manifest.json").read_text())
        for path in self.manifest["files"]:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(BATCH / path)

    def replace(self, path: str, data: bytes) -> None:
        """Swap one linked file for new bytes and record their digest."""
        target = self.root / path
        target.unlink()
        target.write_bytes(data)
        self.manifest["files"][path] = sha(data)

    def seal(self) -> None:
        """Rewrite the manifest and the checksum list to match the files."""
        data = (json.dumps(self.manifest, indent=2) + "\n").encode()
        (self.root / "manifest.json").write_bytes(data)
        checks = {**self.manifest["files"], "manifest.json": sha(data)}
        (self.root / "SHA256SUMS").write_text(
            "".join(f"{value}  {path}\n" for path, value in sorted(checks.items()))
        )

    def report(self) -> dict[str, typ.Any]:
        """Copy the retained observe report.

        Returns
        -------
        dict[str, typing.Any]
            A private copy that a test may alter.
        """
        return copy.deepcopy(json.loads((BATCH / "observe/report.json").read_text()))

    def replace_capture(self, which: str, report: dict[str, typ.Any]) -> None:
        """Replace the observe report and rebuild its checksum inventory."""
        self.replace(
            f"{which}/report.json", (json.dumps(report, indent=2) + "\n").encode()
        )
        checks = {
            "plan.json": sha((self.root / which / "plan.json").read_bytes()),
            "report.json": self.manifest["files"][f"{which}/report.json"],
        }
        self.replace(
            f"{which}/checksums.sha256",
            "".join(f"{v}  {k}\n" for k, v in checks.items()).encode(),
        )


@pytest.fixture
def corpus(tmp_path: Path) -> Corpus:
    """Link the PM corpus below a scratch directory.

    Returns
    -------
    Corpus
        The linked corpus.
    """
    return Corpus(tmp_path)


class PMPacketTests:
    """Resealed alterations of the PM corpus must still be rejected."""

    def test_original_corpus(self, corpus: Corpus) -> None:
        """The unaltered corpus verifies."""
        corpus.seal()
        assert verify(corpus.root)["status"] == "verified-bounded-native-pm", (
            "expected the corpus to verify"
        )

    def test_rehashed_wrong_uid_option_and_quote(self, corpus: Corpus) -> None:
        """A wrong UID, option or quote in a resealed report is rejected."""
        for action, field, value in [
            (PM_ACTION, FIELD_USER_ID, b"\0\x2d"),
            (PM_ACTION, FIELD_OPTIONS, b"\0\x02"),
            (PM_ACTION, FIELD_QUOTE, b"quote-b26"),
        ]:
            report = corpus.report()
            change_field(report, action, field, value)
            corpus.replace_capture("observe", report)
            corpus.seal()
            with pytest.raises(
                ValueError, match=r"PM 104|PM routing|PM semantic|PM quoted"
            ):
                verify(corpus.root)

    def test_missing_delivery_rejected(self, corpus: Corpus) -> None:
        """Removing the delivery frames of one action is rejected."""
        report = corpus.report()
        report["frames"] = [f for f in report["frames"] if f["action"] != PM_ACTION]
        report["events"] = [e for e in report["events"] if e["action"] != PM_ACTION]
        rebuild_streams(report)
        corpus.replace_capture("observe", report)
        corpus.seal()
        with pytest.raises(ValueError, match=r"Completed frame read|Decoded frame"):
            verify(corpus.root)

    def test_packet_mismatch_rejected_after_rehash(self, corpus: Corpus) -> None:
        """A changed byte in the packet record is rejected after resealing."""
        raw = (BATCH / "host-after-observe.pcap").read_bytes()
        assert b"pm-a26-direct" in raw, "expected the text in the packet record"
        corpus.replace(
            "host-after-observe.pcap",
            raw.replace(b"pm-a26-direct", b"pm-a26-difect", 1),
        )
        corpus.seal()
        with pytest.raises(ValueError, match=r"TCP|packet reconciliation"):
            verify(corpus.root)

    def test_truncated_a7_rejected_after_rehash(self, corpus: Corpus) -> None:
        """A truncated postflight plan is rejected after resealing."""
        plan = json.loads((BATCH / "postflight/plan.json").read_text())
        plan["steps"] = plan["steps"][:TRUNCATED_STEPS]
        corpus.replace(
            "postflight/plan.json", (json.dumps(plan, indent=2) + "\n").encode()
        )
        checks = {
            "plan.json": corpus.manifest["files"]["postflight/plan.json"],
            "report.json": sha((corpus.root / "postflight/report.json").read_bytes()),
        }
        corpus.replace(
            "postflight/checksums.sha256",
            "".join(f"{v}  {k}\n" for k, v in checks.items()).encode(),
        )
        corpus.seal()
        with pytest.raises(
            ValueError, match=r"Source identity|Incomplete plan|plan differs"
        ):
            verify(corpus.root)
