"""Fault controls for the portable B62 roster witness."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_classic_roster_subject_115 import verify

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01"
)


def rewrite_inventory(base: Path) -> None:
    root = base.parents[3]
    files = sorted(p for p in base.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    (base / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root)}\n"
            for p in files
        )
    )


def edit_json(base: Path, name: str, change) -> None:
    path = base / name
    data = json.loads(path.read_text())
    change(data)
    path.write_text(json.dumps(data, indent=2) + "\n")


class RosterSubjectEvidenceTests(unittest.TestCase):
    def test_frozen_replay(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["wire"]["roster_bytes"], [41, 60])
        self.assertEqual(result["ui"]["delivery_to_snapshot_seconds"], 0.927917)
        self.assertEqual(result["a7"]["actions_each"], 29)

    def test_semantic_faults(self) -> None:
        cases = (
            (
                "proxy source",
                lambda b: (b / "as-run/classic_login_proxy.py.txt").write_text(
                    "changed\n"
                ),
                "frozen source changed",
            ),
            (
                "parser source",
                lambda b: (b / "as-run/pcap_tcp.py.txt").write_text("changed\n"),
                "frozen source changed",
            ),
            (
                "wrong roster id in audit",
                lambda b: edit_json(
                    b,
                    "run/proxy/report.json",
                    lambda d: d["entries"][11].update(
                        raw_hex=d["entries"][11]["raw_hex"][:8]
                        + "00000004"
                        + d["entries"][11]["raw_hex"][16:]
                    ),
                ),
                "proxy audit/control bytes",
            ),
            (
                "wrong packed roster UID in audit",
                lambda b: edit_json(
                    b,
                    "run/proxy/report.json",
                    lambda d: d["entries"][11].update(
                        raw_hex=d["entries"][11]["raw_hex"].replace(
                            "004f019e", "0050019e"
                        ),
                        forwarded_hex=d["entries"][11]["forwarded_hex"].replace(
                            "004f019e", "0050019e"
                        ),
                    ),
                ),
                "proxy audit/control bytes",
            ),
            (
                "wrong data reference in audit",
                lambda b: edit_json(
                    b,
                    "run/proxy/report.json",
                    lambda d: d["entries"][13].update(
                        raw_hex="00" + d["entries"][13]["raw_hex"][2:],
                        forwarded_hex="00" + d["entries"][13]["forwarded_hex"][2:],
                    ),
                ),
                "proxy audit/data bytes",
            ),
            (
                "missing namespace view",
                lambda b: (b / "pcaps/namespace.pcap").unlink(),
                "four selected PCAPs",
            ),
            (
                "modified raw view bytes",
                lambda b: (b / "pcaps/host.pcap").write_bytes(
                    (b / "pcaps/host.pcap").read_bytes()[:-1] + b"\x00"
                ),
                "selected PCAP identity",
            ),
            (
                "early UI timestamp",
                lambda b: edit_json(
                    b,
                    "ui-timing.json",
                    lambda d: d.update(source_file_mtime_ns=1_794_629_905_000_000_000),
                ),
                "UI host mtime receipt",
            ),
            (
                "missing screenshot",
                lambda b: (b / "run/after-agree-1s.png").unlink(),
                "UI screenshot identity",
            ),
            (
                "invalid watchdog",
                lambda b: edit_json(
                    b,
                    "run/proxy/report.json",
                    lambda d: d["observation"].update(valid_30_seconds=False),
                ),
                "watchdog outcome",
            ),
            (
                "packet drops",
                lambda b: (b / "run/ns-capture-journal.txt").write_text(
                    (b / "run/ns-capture-journal.txt")
                    .read_text()
                    .replace(
                        "0 packets dropped by kernel", "1 packets dropped by kernel"
                    )
                ),
                "capture drop/owner",
            ),
            (
                "live owned unit",
                lambda b: (b / "run/units-terminal.txt").write_text(
                    (b / "run/units-terminal.txt")
                    .read_text()
                    .replace(
                        "Id=mothra-b62-oracle-lease.service\nActiveState=inactive",
                        "Id=mothra-b62-oracle-lease.service\nActiveState=active",
                    )
                ),
                "owned service cleanup",
            ),
            (
                "false lock busy claim",
                lambda b: edit_json(
                    b,
                    "lock-receipt.json",
                    lambda d: d.update(independent_flock_n_before_exit=0),
                ),
                "managed lock busy/free",
            ),
            (
                "wrong 115 in audit",
                lambda b: edit_json(
                    b,
                    "run/proxy/report.json",
                    lambda d: d["entries"][11].update(
                        forwarded_hex=d["entries"][11]["forwarded_hex"].replace(
                            "666978747572652d7375626a656374",
                            "666978747572652d7375626a656375",
                        )
                    ),
                ),
                "proxy audit/control bytes",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as tmp:
                base = (
                    Path(tmp)
                    / "mothra/evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01"
                )
                shutil.copytree(CORPUS, base)
                mutate(base)
                rewrite_inventory(base)
                with self.assertRaisesRegex(ValueError, expected):
                    verify(base)


if __name__ == "__main__":
    unittest.main()
