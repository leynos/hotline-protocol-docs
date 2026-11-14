"""Semantic fault controls for the frozen persisted-ban reload witness."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from shutil import copytree

from native_control_readiness import probe
from verify_native_ban_reload import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-ban-reload-01"
)
C56 = CORPUS.parent / "native-ban-control-01"


class NativeBanReloadTest(unittest.TestCase):
    def report(self) -> dict:
        return json.loads((CORPUS / "c61/probe-capture/report.json").read_text())

    def test_frozen_replay(self) -> None:
        self.assertEqual(verify(CORPUS)["login_error_bytes"], 42)

    def test_wrong_error_text(self) -> None:
        report = self.report()
        report["frames"][0]["fields"][0]["hex"] = "78"
        with self.assertRaisesRegex(ValueError, "Permanent login rejection differs"):
            probe(report)

    def test_missing_trtp_hello(self) -> None:
        report = self.report()
        sends = [e for e in report["events"] if e["event"] == "send"]
        sends[0]["hex"] = "00"
        with self.assertRaisesRegex(ValueError, "Fresh TRTP plus Login107 absent"):
            probe(report)

    def corrupt(self, change, reason: str) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            p = root / "native-ban-reload-01"
            copytree(CORPUS, p)
            copytree(C56, root / "native-ban-control-01")
            change(p)
            launch_file = p / "c61/probe-launch.json"
            launch = json.loads(launch_file.read_text())
            launch["asrun_sha256"] = hashlib.sha256(
                (p / "c61/probe-asrun.json").read_bytes()
            ).hexdigest()
            launch_file.write_text(json.dumps(launch))
            manifest = json.loads((p / "manifest.json").read_text())
            manifest["files"] = {
                str(path.relative_to(p)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in p.rglob("*")
                if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
            }
            (p / "manifest.json").write_text(json.dumps(manifest))
            (p / "SHA256SUMS").write_text(
                "".join(
                    f"{sha}  {name}\n"
                    for name, sha in sorted(manifest["files"].items())
                )
            )
            with self.assertRaisesRegex(ValueError, reason):
                verify(p)

    def edit_json(self, p: Path, name: str, edit) -> None:
        file = p / name
        value = json.loads(file.read_text())
        edit(value)
        file.write_text(json.dumps(value))

    def test_rehashed_emulator_identity(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/ui-ready.json",
                lambda x: x["actual_emulator"].update(starttime="1"),
            ),
            "Read-only UI boot identity differs",
        )

    def test_rehashed_read_only_ui_claim(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p, "c61/ui-observation.json", lambda x: x["ban_tab"].update(saved=True)
            ),
            "Read-only Ban UI row or Cancel claim differs",
        )

    def test_rehashed_target_vector(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/probe-asrun.json",
                lambda x: x["steps"][3].update(hex="0000006b00000002"),
            ),
            "Prepared/as-run one-probe vector differs",
        )

    def test_rehashed_extra_ban_request(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/probe-asrun.json",
                lambda x: x["steps"].insert(4, {"op": "send", "hex": "0000006e"}),
            ),
            "Prepared/as-run one-probe vector differs",
        )

    def test_rehashed_packet_byte_parity(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "packet-views.json",
                lambda x: x["views"]["guest"].update(received_hex="00"),
            ),
            "guest complete scoped TCP stream differs",
        )

    def test_rehashed_recorder_deadline(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/host-ready-preprobe.json",
                lambda x: x.update(deadline_utc="2026-11-14T04:00:00+00:00"),
            ),
            "host recorder identity or deadline differs",
        )

    def test_rehashed_packet_drop(self) -> None:
        def change(p: Path) -> None:
            path = p / "c61/namespace-recorder.log"
            path.write_bytes(
                path.read_bytes().replace(
                    b"0 packets dropped by kernel", b"1 packets dropped by kernel"
                )
            )

        self.corrupt(change, "namespace recorder count/drop differs")

    def test_rehashed_cleanup(self) -> None:
        self.corrupt(
            lambda p: self.edit_json(
                p, "c61/terminal.json", lambda x: x.update(actual_pid_gone=False)
            ),
            "Terminal profile, forced retirement or ban bytes differ",
        )

    def test_rehashed_ban_bytes(self) -> None:
        def change(p: Path) -> None:
            path = p / "c61/Banned-postprobe.data.bin"
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)

        self.corrupt(change, "Stored ban or account bytes differ")


if __name__ == "__main__":
    unittest.main()
