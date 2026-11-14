"""Fault controls for the portable A46/A48 settings persistence witness."""

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from protocol_capture import digest
from verify_native_settings_persistence import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-settings-persistence-01"
)


def replace(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".fault")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def edit_json(path: Path, change) -> None:
    value = json.loads(path.read_text())
    change(value)
    replace(path, (json.dumps(value, indent=2) + "\n").encode())


def resign(corpus: Path) -> None:
    manifest = json.loads((corpus / "manifest.json").read_text())
    for name in manifest["files"]:
        path = corpus / name
        manifest["files"][name] = {
            "bytes": path.stat().st_size,
            "sha256": digest(path.read_bytes()),
        }
    replace(corpus / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    replace(
        corpus / "SHA256SUMS",
        "".join(
            f"{digest((corpus / name).read_bytes())}  {name}\n"
            for name in sorted(set(manifest["files"]) | {"manifest.json"})
        ).encode(),
    )


def nested_checksums(corpus: Path, phase: int) -> None:
    case = "phase1" if phase == 1 else "phase2"
    directory = corpus / f"phase{phase}" / case
    replace(
        directory / "checksums.sha256",
        "".join(
            f"{digest((directory / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        ).encode(),
    )


class PersistenceWitnessTests(unittest.TestCase):
    def test_complete_corpus(self) -> None:
        self.assertEqual(verify(CORPUS)["status"], "verified_control_only")

    def test_fault_controls(self) -> None:
        faults = {
            "legacy_count": "A46 legacy 64+2 count differs",
            "legacy_eof": "A46 legacy EOF actions differ",
            "legacy_frame": "Decoded frame mismatch",
            "old_source": "a46 source differs",
            "missing_a48_eof": "Owned socket EOFs differ",
            "fixed_login": "Prepared plan changed",
            "paired_pcap": "PCAP provenance differs",
            "stored_fork": "stored fork differs",
            "shutdown_cleanup": "User unit terminal state differs",
            "deadline": "Owned sockets/deadline differ",
            "drop": "Capture drops/primary zero differ",
            "missing_lock_deviation": "A48 lock deviation missing",
            "wrong_emulator": "Emulator identity differs",
            "wrong_shutdown_order": "Operator shutdown chronology differs",
        }
        for fault, expected in faults.items():
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                corpus = Path(temporary) / "corpus"
                shutil.copytree(CORPUS, corpus)
                first = corpus / "phase1/phase1/report.json"
                second = corpus / "phase2/phase2/report.json"
                if fault == "legacy_count":
                    edit_json(first, lambda data: data.update(completed_actions=65))
                    nested_checksums(corpus, 1)
                elif fault == "legacy_eof":

                    def wrong_eof(data):
                        next(
                            e
                            for e in data["events"]
                            if e["event"] == "eof" and e["action"] == 65
                        )["connection"] = "subject"

                    edit_json(first, wrong_eof)
                    nested_checksums(corpus, 1)
                elif fault == "legacy_frame":

                    def wrong_frame(data):
                        data["frames"][0]["type"] ^= 1

                    edit_json(first, wrong_frame)
                    nested_checksums(corpus, 1)
                elif fault == "old_source":
                    path = corpus / "source/a46/native_settings_persistence.py"
                    replace(path, path.read_bytes() + b"\n")
                elif fault == "missing_a48_eof":

                    def missing_eof(data):
                        data["events"] = [
                            e
                            for e in data["events"]
                            if not (e["event"] == "eof" and e["action"] == 27)
                        ]

                    edit_json(second, missing_eof)
                    nested_checksums(corpus, 2)
                elif fault == "fixed_login":

                    def wrong_login(data):
                        step = next(
                            s
                            for s in data["steps"]
                            if s["op"] == "send" and s["hex"].startswith("0000006b")
                        )
                        step["hex"] = step["hex"][:-2] + (
                            "00" if step["hex"][-2:] != "00" else "01"
                        )

                    plan_path = corpus / "phase2/phase2/plan.json"
                    edit_json(plan_path, wrong_login)
                    plan_digest = digest(plan_path.read_bytes())
                    edit_json(
                        second,
                        lambda data, value=plan_digest: data.update(plan_sha256=value),
                    )
                    nested_checksums(corpus, 2)
                    replace(corpus / "phase2/plans/phase2.json", plan_path.read_bytes())
                    edit_json(
                        corpus / "phase2/plans/source-hashes.json",
                        lambda data, value=plan_digest: data.update(phase2=value),
                    )
                elif fault == "paired_pcap":
                    path = corpus / "phase2/guest.pcap"
                    data = bytearray(path.read_bytes())
                    data[-1] ^= 1
                    replace(path, bytes(data))
                elif fault == "stored_fork":
                    path = corpus / "phase1/stopped-fork-11202.bin"
                    data = bytearray(path.read_bytes())
                    data[-1] ^= 1
                    replace(path, bytes(data))
                elif fault == "shutdown_cleanup":
                    path = corpus / "phase2/user-units-terminal.txt"
                    replace(
                        path, path.read_bytes().replace(b"MainPID=0", b"MainPID=1", 1)
                    )
                elif fault == "deadline":
                    replace(corpus / "phase2/deadline.txt", b"2026-11-14T04:00:00Z\n")
                elif fault == "drop":
                    path = corpus / "phase1/capture-journal.txt"
                    replace(
                        path,
                        path.read_bytes().replace(
                            b"0 packets dropped by kernel",
                            b"1 packets dropped by kernel",
                            1,
                        ),
                    )
                elif fault == "missing_lock_deviation":
                    edit_json(
                        corpus / "manifest.json",
                        lambda data: data.update(phase2_oracle_lock_deviation=""),
                    )
                elif fault == "wrong_emulator":
                    edit_json(
                        corpus / "phase2/emulator-identity.json",
                        lambda data: data.update(exe_sha256="0" * 64),
                    )
                elif fault == "wrong_shutdown_order":
                    edit_json(
                        corpus / "baseline/operator-timeline.json",
                        lambda data: data["phases"]["phase2"].update(
                            operator_pid_absent_by_utc="2026-11-14T04:06:00+00:00"
                        ),
                    )
                resign(corpus)
                with self.assertRaisesRegex(ValueError, re.escape(expected)):
                    verify(corpus)


if __name__ == "__main__":
    unittest.main()
