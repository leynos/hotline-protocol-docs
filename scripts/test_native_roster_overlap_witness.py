"""Fault controls for the frozen native roster overlap witness."""

import copy
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import verify_native_roster_overlap as witness


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RosterWitness(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / witness.SCHEMA
        shutil.copytree(witness.CORPUS, self.corpus)

    def refresh(self) -> None:
        files = {
            str(path.relative_to(self.corpus)): digest(path)
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"] = files
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{value}  {name}\n" for name, value in sorted(files.items()))
        )

    def mutate_json(self, name: str, change) -> None:
        path = self.corpus / name
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh()

    def rejected(self, reason: str) -> None:
        with self.assertRaisesRegex(ValueError, reason):
            witness.verify(self.corpus)

    def test_baseline(self) -> None:
        witness.verify(self.corpus)

    def test_wrong_dynamic_uid(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["frames"][11]["fields"][0].update(hex="0004"),
        )
        self.rejected("Rename 301 identity/icon differs")

    def test_wrong_initial_access_bitmap(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["frames"][1]["fields"][0].update(hex="00"),
        )
        self.rejected("a login/access differs")

    def test_torn_roster_pair(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["frames"][14]["fields"][1].update(
                hex="00030002001200094f72646572204e6577"
            ),
        )
        self.rejected("Roster icon/UID pair|Decoded drain frame")

    def test_unexpected_third_row(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["frames"][9]["fields"].append(
                copy.deepcopy(r["frames"][9]["fields"][1])
            ),
        )
        self.rejected("Duplicate roster UID")

    def test_missing_barrier_ack(self) -> None:
        self.mutate_json(
            "raw/results/report.json", lambda r: r["frames"][10].update(id=99)
        )
        self.rejected("Custom drain event/frame provenance differs")

    def test_operation_map_gap(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["operation_map"][4].update(event_range=[31, 32]),
        )
        self.rejected("Operation map bounds")

    def test_operation_order_drift(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["operation_map"][1].update(label="b304-rename"),
        )
        self.rejected("Operation map labels differ")

    def test_stream_event_mismatch(self) -> None:
        self.mutate_json(
            "raw/results/report.json",
            lambda r: r["streams"]["a"].update(
                sent_hex="00" + r["streams"]["a"]["sent_hex"]
            ),
        )
        self.rejected("Recorded TCP streams")

    def test_packet_pair_mutation(self) -> None:
        path = self.corpus / "raw/lab-guest.pcap"
        raw = bytearray(path.read_bytes())
        index = raw.find(bytes.fromhex("54525450484f544c"))
        self.assertGreater(index, 0)
        raw[index + 5] ^= 1
        path.write_bytes(raw)
        self.refresh()
        self.rejected("Conflicting TCP retransmission|paired bytes or tails")

    def test_wrong_namespace_identity(self) -> None:
        self.mutate_json(
            "raw/capture-ready.json",
            lambda r: r.update(emulator_netns="net:[4026531840]"),
        )
        self.rejected("Runtime/capture receipt identity")

    def test_parent_replay_path_history(self) -> None:
        self.mutate_json(
            "raw/parent-preflight.json",
            lambda r: r.update(overlap_socket_actions=1),
        )
        self.rejected("Parent readiness path correction differs")

    def test_deadline_drift(self) -> None:
        self.mutate_json(
            "raw/runtime-proof.json",
            lambda r: r.update(deadline_utc="2026-11-14T07:10:57.615913+00:00"),
        )
        self.rejected("Actual emulator or original-service identity")

    def test_changed_source_plan(self) -> None:
        self.mutate_json(
            "raw/roster-plan/plan.json",
            lambda r: r["overlap"].update(quiet_seconds=3.0),
        )
        path = self.corpus / "raw/roster-plan/plan.json"
        (path.parent / "source-hashes.json").write_text(
            json.dumps({"plan.json": digest(path)}, indent=2) + "\n"
        )
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["plan_sha256"] = digest(path)
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        self.refresh()
        self.rejected("Prepared overlap plan differs|Prepared source plan differs")

    def test_postflight_account_state(self) -> None:
        self.mutate_json(
            "raw/postflight/report.json",
            lambda r: r["frames"][3]["fields"].clear(),
        )
        report = self.corpus / "raw/postflight/report.json"
        checksums = self.corpus / "raw/postflight/checksums.sha256"
        checksums.write_text(
            "".join(
                f"{digest(report.parent / name)}  {name}\n"
                for name in ("plan.json", "report.json")
            )
        )
        self.refresh()
        self.rejected("Decoded frame mismatch")

    def test_stopped_account_fork_change(self) -> None:
        self.mutate_json(
            "raw/stopped-forks-corrected.json",
            lambda r: r["files"]["admin"].update(sha256="0" * 64),
        )
        self.rejected("Stopped named forks")

    def test_recorder_drop(self) -> None:
        path = self.corpus / "raw/c86-recorder-journal.log"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel", 1
            )
        )
        self.refresh()
        self.rejected("Capture drop or packet count differs")

    def test_retirement_lock_busy(self) -> None:
        self.mutate_json(
            "raw/terminal-network-lock.json",
            lambda r: r.update(lock_exit=1),
        )
        self.rejected("Post-retirement process, ports, image FD or lock differs")


if __name__ == "__main__":
    unittest.main()
