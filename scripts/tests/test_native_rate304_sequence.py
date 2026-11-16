"""Fault controls for the portable failed rate304 sequence witness."""

import contextlib
import hashlib
import json
import shutil
import sys
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import native_control_readiness
import pytest
from verify_native_rate304_sequence import CORPUS, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc


class Rate304SequenceTests:  # ruff: ignore[too-many-public-methods]  # pylint: disable=too-many-public-methods  # each test name is a golden key, so the class keeps all nineteen
    """Reject each fault that the failed rate304 sequence witness can carry."""

    @pytest.fixture(autouse=True)
    def setUp(self) -> cabc.Iterator[None]:
        """Copy the retained sequence corpus into a temporary directory.

        Yields
        ------
        None
            Control returns to the test once the copy exists.
        """
        with contextlib.ExitStack() as stack:
            temporary = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="rate304-sequence-")
            )
            self.corpus = Path(temporary) / CORPUS.name
            shutil.copytree(CORPUS, self.corpus)
            yield

    def refresh(self) -> None:
        """Recompute the manifest's file hashes and SHA256SUMS for the copy."""
        manifest_path = self.corpus / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest["files"] = files
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        prefix = "evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/"
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{digest}  {prefix}{name}\n" for name, digest in sorted(files.items())
            )
        )

    def change_json(
        self,
        name: str,
        mutate: cabc.Callable[[typ.Any], None],
    ) -> None:
        """Apply a mutation to one JSON file of the copy and refresh the hashes.

        Parameters
        ----------
        name : str
            The path of the JSON file, relative to the copy.
        mutate : cabc.Callable[[typ.Any], None]
            The change to make to the parsed JSON value.
        """
        path = self.corpus / name
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh()

    def rejected(self, pattern: str) -> None:
        """Expect the verifier to reject the copy with a matching message.

        Parameters
        ----------
        pattern : str
            The regular expression that the rejection message must match.
        """
        with pytest.raises(ValueError, match=pattern):
            verify(self.corpus)

    def test_baseline(self) -> None:
        """Accept the retained sequence corpus as it stands."""
        result = verify(self.corpus)
        assert result["status"] == "PASS", "the status differs"
        assert result["case_status"] == "failed", "the case status differs"
        assert len(result["flows"]) == 5, "the flow count differs"
        assert result["host_timing_ns"]["subject_quiet_ns"] >= 70_000_000_000, (
            "the subject quiet time is too short"
        )

    def test_frozen_imports_restore_on_pass_and_failure(self) -> None:
        """Restore the frozen imports, path and bytecode flag after a run."""
        original = sys.modules["native_control_readiness"]
        path, bytecode = sys.path.copy(), sys.dont_write_bytecode
        verify(self.corpus)
        assert sys.modules["native_control_readiness"] is original, "module replaced"
        with mock.patch("native_control_readiness.login_gate") as mocked:
            assert original.login_gate is mocked, "the patched gate is not visible"
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: d.__setitem__("status", "completed"),
        )
        self.rejected("Failed case status")
        assert sys.modules["native_control_readiness"] is original, "module replaced"
        assert original is native_control_readiness, "the module identity differs"
        assert sys.path == path, "the import path differs"
        assert sys.dont_write_bytecode == bytecode, "the bytecode flag differs"

    def test_missing_update_rejected(self) -> None:
        """Reject a coordinator report that lacks the paced 301 update."""

        def mutate(d: dict[str, typ.Any]) -> None:
            """Delete the paced 301 frame from the coordinator report."""
            index = next(
                i
                for i, f in enumerate(d["frames"])
                if f["connection"] == "paced" and f["type"] == 301
            )
            del d["frames"][index]

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw event/action/frame boundary|Received frame/tail|update301")

    def test_barrier_ack_rejected(self) -> None:
        """Reject a barrier acknowledgement that carries an error."""

        def mutate(d: dict[str, typ.Any]) -> None:
            """Mark the burst barrier acknowledgement as an error."""
            frame = next(
                f for f in d["frames"] if f["connection"] == "burst" and f["id"] == 4000
            )
            frame["error"] = 1

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|direct success")

    def test_quiet_bracket_rejected(self) -> None:
        """Reject a post-quiet action whose timestamp falls outside the bracket."""
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: next(
                a for a in d["actions"] if a["label"] == "paced-304-after-quiet"
            ).__setitem__("elapsed_ns", 10_000_000_000),
        )
        self.rejected("Action causal timestamp|host quiet bracket")

    def test_shifted_postquiet_action_times_rejected(self) -> None:
        """Reject post-quiet action times that were all shifted together."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Shift both post-quiet actions by one second."""
            for action in report["actions"]:
                if action["label"] in {
                    "paced-304-after-quiet",
                    "paced-500-after-quiet",
                }:
                    action["elapsed_ns"] += 1_000_000_000

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Action causal timestamp differs")

    def test_shifted_icon27_frame_arrival_rejected(self) -> None:
        """Reject an icon-27 observer frame whose arrival time was moved."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Move the arrival of the icon-27 observer frame earlier."""
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "observer"
                and f["type"] == 301
                and {item["id"]: item["hex"] for item in f["fields"]}.get(103) == "0003"
                and {item["id"]: item["hex"] for item in f["fields"]}.get(104) == "001b"
            )
            frame["arrival_elapsed_ns"] -= 500_000_000

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Frame causal timestamp differs")

    def test_terminal_label_rejected(self) -> None:
        """Reject a burst terminal label that names a reset."""
        self.change_json(
            "raw/epoch/coordinator/report.json",
            lambda d: d["terminals"].__setitem__("burst", "rst"),
        )
        self.rejected("Failed case status|Socket terminal")

    def test_probe_text_rejected(self) -> None:
        """Reject a probe frame that carries the temporary-ban text."""

        def mutate(d: dict[str, typ.Any]) -> None:
            """Replace the probe frame field with a permanent-ban text."""
            frame = next(f for f in d["frames"] if f["connection"] == "probe")
            frame["fields"][0]["hex"] = (
                b"You are permanently banned on this server.".hex()
            )

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|temporary-ban")

    def test_final_303_target_rejected(self) -> None:
        """Reject a final 303 whose target identifier was changed."""

        def mutate(d: dict[str, typ.Any]) -> None:
            """Change the target of the observer 303 action."""
            action = next(a for a in d["actions"] if a["label"] == "observer-303")
            action["hex"] = action["hex"][:-4] + "0001"

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("request schedule|Action/send|fieldless")

    def test_final_error_rejected(self) -> None:
        """Reject a final observer reply whose error was cleared."""

        def mutate(d: dict[str, typ.Any]) -> None:
            """Clear the error of the final observer reply."""
            frame = next(
                f
                for f in d["frames"]
                if f["connection"] == "observer" and f["id"] == 6004
            )
            frame["error"] = 0

        self.change_json("raw/epoch/coordinator/report.json", mutate)
        self.rejected("Raw frame decode|Final303")

    def test_approved_closure_source_rejected(self) -> None:
        """Reject a copy whose approved control source was appended to."""
        path = self.corpus / "raw/epoch/sources/native_rate304_control.py"
        path.write_bytes(path.read_bytes() + b"\n# forged\n")
        self.refresh()
        self.rejected("Frozen module|Approved source")

    def test_pcap_payload_rejected(self) -> None:
        """Reject a capture whose payload text was altered."""
        path = self.corpus / "raw/epoch/lab-guest.pcap"
        value = path.read_bytes()
        assert b"TRTPHOTL" in value, "the payload marker is absent"
        path.write_bytes(value.replace(b"TRTPHOTL", b"TRTPH0TL", 1))
        self.refresh()
        self.rejected("PCAP/Recorder|Conflicting TCP retransmission")

    def test_missing_guest_flow_rejected(self) -> None:
        """Reject a guest capture that is truncated to a bare header."""
        path = self.corpus / "raw/epoch/lab-guest.pcap"
        path.write_bytes(path.read_bytes()[:24])
        self.refresh()
        self.rejected("Capture packet inventory|Five SYN lifetimes")

    def test_primary_syn_rejected(self) -> None:
        """Reject a primary SYN capture that duplicates the namespace capture."""
        path = self.corpus / "raw/epoch/primary-syn.pcap"
        path.write_bytes((self.corpus / "raw/epoch/lab-namespace.pcap").read_bytes())
        self.refresh()
        self.rejected("Capture packet inventory|Primary-port")

    def test_drop_counter_rejected(self) -> None:
        """Reject a capture journal that reports a kernel packet drop."""
        path = self.corpus / "raw/epoch/capture-journal-terminal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packet dropped by kernel", 1
            )
        )
        self.refresh()
        self.rejected("Capture drops/counts")

    def test_stopped_fixture_byte_rejected(self) -> None:
        """Reject a stopped admin fixture whose one byte was flipped."""
        path = self.corpus / "raw/epoch/stopped-icat-admin.stdout"
        data = bytearray(path.read_bytes())
        data[100] ^= 1
        path.write_bytes(data)
        self.refresh()
        self.rejected("Stopped admin fork")

    def test_forced_retirement_label_rejected(self) -> None:
        """Reject a retirement whose label claims an orderly shutdown."""
        self.change_json(
            "raw/epoch/owned-pid-term.json",
            lambda d: d.__setitem__("action", "orderly OS shutdown"),
        )
        self.rejected("Forced retirement")

    def test_source_pin_extra_entry_rejected(self) -> None:
        """Reject a source pin that carries an extra forged entry."""
        path = self.corpus / "raw/preparation/approved-source-closure.sha256"
        path.write_text(path.read_text() + "0" * 64 + "  scripts/forged.py\n")
        self.refresh()
        self.rejected("Approved 35-module closure")
