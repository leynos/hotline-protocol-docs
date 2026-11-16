"""Fault controls for the frozen isolated option-two witness."""

import copy
import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path
from shutil import copytree

import native_control_readiness as gates
import pytest
from verify_native_ban_control import verify

type Report = dict[str, typ.Any]

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-ban-control-01"
)
CONNECTIONS = 6
BAN_CAPTURE = "case-c56/captures/ban"
BAN_REPORT = f"{BAN_CAPTURE}/report.json"
OPTION_ONE = "0001"  # the option of a plain disconnect, where a ban needs two


class NativeBanControlTest:
    """Fault controls for the frozen isolated option-two witness."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def report(self, phase: str) -> Report:
        """Load one phase's capture report from the frozen corpus.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json``.
        """
        path = CORPUS / f"case-c56/captures/{phase}/report.json"
        return json.loads(path.read_text())

    def test_frozen_corpus(self) -> None:
        """The frozen witness replays with its six connections."""
        assert verify(CORPUS)["connections"] == CONNECTIONS, "expected six sockets"

    def test_wrong_target_identity(self) -> None:
        """A changed target name is rejected by the target gate."""
        frames = copy.deepcopy(self.report("ban")["frames"])
        join = next(f for f in frames if f["type"] == 301)
        next(f for f in join["fields"] if f["id"] == 102)["hex"] = "78"
        with pytest.raises(ValueError, match="Target UID/name mismatch"):
            gates.target_gate(frames)

    def test_wrong_permanent_notice(self) -> None:
        """A changed permanent-ban notice is rejected by the outcome gate."""
        report = self.report("ban")
        notice = next(f for f in report["frames"] if f["type"] == 104)
        next(f for f in notice["fields"] if f["id"] == 101)["hex"] = "78"
        with pytest.raises(ValueError, match="Permanent notice differs"):
            gates.outcome(report)

    def test_target_must_close(self) -> None:
        """A target whose connection never closes is rejected."""
        report = self.report("ban")
        report["events"] = [
            e
            for e in report["events"]
            if (e["connection"], e["event"]) != ("target", "eof")
        ]
        with pytest.raises(ValueError, match="Target close missing"):
            gates.outcome(report)

    def test_post_ban_readback_required(self) -> None:
        """A missing post-ban readback is rejected."""
        report = self.report("ban")
        report["frames"] = [
            f for f in report["frames"] if not (f["is_reply"] and f["id"] == 42)
        ]
        with pytest.raises((ValueError, StopIteration)):
            gates.outcome(report)

    def test_fresh_login_107_required(self) -> None:
        """A probe without its fresh login is rejected."""
        report = self.report("probe")
        report["events"] = [
            e
            for e in report["events"]
            if not (e["event"] == "send" and e["hex"].startswith("0000006b"))
        ]
        with pytest.raises(ValueError, match="Fresh TRTP plus Login107 absent"):
            gates.probe(report)

    def mutate(self, relative: str, replacement: bytes, message: str) -> None:
        """Replace one file of a copy, rehash the copy and expect a rejection.

        Parameters
        ----------
        relative : str
            The corpus-relative name of the file to replace.
        replacement : bytes
            The new bytes.
        message : str
            A regular expression that the rejection message must match.
        """
        with tempfile.TemporaryDirectory() as temp:
            changed = Path(temp) / "corpus"
            copytree(CORPUS, changed)
            (changed / relative).write_bytes(replacement)
            manifest = json.loads((changed / "manifest.json").read_text())
            manifest["files"][relative] = hashlib.sha256(replacement).hexdigest()
            if relative.endswith("/captures/ban/report.json"):
                sums = f"{BAN_CAPTURE}/checksums.sha256"
                plan = hashlib.sha256(
                    (changed / BAN_CAPTURE / "plan.json").read_bytes()
                )
                (changed / sums).write_text(
                    f"{manifest['files'][relative]}  report.json\n"
                    f"{plan.hexdigest()}  plan.json\n"
                )
                manifest["files"][sums] = hashlib.sha256(
                    (changed / sums).read_bytes()
                ).hexdigest()
            (changed / "manifest.json").write_text(json.dumps(manifest))
            (changed / "SHA256SUMS").write_text(
                "".join(
                    f"{sha}  {name}\n"
                    for name, sha in sorted(manifest["files"].items())
                )
            )
            with pytest.raises(ValueError, match=message):
                verify(changed)

    def test_rehashed_boot_identity(self) -> None:
        """A changed emulator start time is rejected."""
        path = "boot-c55/readiness.json"
        value = json.loads((CORPUS / path).read_text())
        value["actual_emulator"]["starttime"] = "1"
        self.mutate(path, json.dumps(value).encode(), "Boot emulator identity differs")

    def test_rehashed_wrong_ban_option(self) -> None:
        """A ban sent with the wrong option is rejected."""
        value = json.loads((CORPUS / BAN_REPORT).read_text())
        request = next(
            e
            for e in value["events"]
            if e["event"] == "send" and e["hex"].startswith("0000006e")
        )
        original = request["hex"]
        request["hex"] = original[:-4] + OPTION_ONE
        main = value["streams"]["main"]
        main["sent_hex"] = main["sent_hex"].replace(original, request["hex"])
        self.mutate(
            BAN_REPORT,
            json.dumps(value).encode(),
            "Control-only request or one-ban scope differs",
        )

    def test_rehashed_packet_drop(self) -> None:
        """A packet drop in the namespace recorder's log is rejected."""
        path = "boot-c55/namespace-recorder.log"
        data = (
            (CORPUS / path)
            .read_bytes()
            .replace(b"0 packets dropped by kernel", b"1 packets dropped by kernel")
        )
        self.mutate(path, data, "namespace packet drops differ")

    def test_rehashed_cleanup(self) -> None:
        """An emulator that is not gone is rejected."""
        path = "case-c56/terminal.json"
        value = json.loads((CORPUS / path).read_text())
        value["actual_pid_gone"] = False
        self.mutate(path, json.dumps(value).encode(), "Terminal profile differs")

    def test_rehashed_persisted_bytes(self) -> None:
        """A changed persisted ban byte is rejected."""
        path = "case-c56/Banned.data.bin"
        data = bytearray((CORPUS / path).read_bytes())
        data[-1] ^= 1
        self.mutate(path, bytes(data), "Stopped persisted ban bytes")
