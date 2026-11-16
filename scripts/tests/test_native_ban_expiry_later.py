"""Fault controls for the frozen later temporary-ban epoch."""

import hashlib
import json
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from verify_native_ban_expiry_later import CORPUS, FIRST, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc


def write(path: Path, value: dict) -> None:
    """Write a JSON document with two-space indentation and a final newline.

    Parameters
    ----------
    path : Path
        The file to write.
    value : dict
        The document to serialize.
    """
    path.write_text(json.dumps(value, indent=2) + "\n")


def refresh(root: Path) -> None:
    """Re-freeze a mutated corpus so that only its semantics are tested.

    Parameters
    ----------
    root : Path
        The copied corpus to refresh in place.
    """
    for checksums in root.rglob("checksums.sha256"):
        names = [line.split("  ", 1)[1] for line in checksums.read_text().splitlines()]
        lines = []
        for name in names:
            digest = hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()
            lines.append(f"{digest}  {name}\n")
        checksums.write_text("".join(lines))
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"] = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    write(root / "manifest.json", manifest)
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(manifest["files"].items())
        )
    )


class NativeBanExpiryLaterTest:
    """Fault controls for the frozen later temporary-ban epoch."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def test_baseline_is_bounded(self) -> None:
        """The later epoch verifies only as a bounded, later-epoch witness."""
        result = verify(CORPUS, FIRST)
        assert result["status"] == "verified_later_epoch_only", "status differs"
        assert result["pre_window"] == "missed_no_probe", "pre-window differs"
        assert not result["exact_1800_boundary_proven"], "1800 boundary proven"
        expected_flows = {
            "post": (120, 389),
            "guard": (169, 496),
            "delete": (274, 645),
            "postflight": (231, 2759),
        }
        flows = {
            name: (flow["sent_bytes"], flow["received_bytes"])
            for name, flow in result["later_flows"].items()
        }
        assert flows == expected_flows, "later flow byte counts differ"

    def mutate(self, change: cabc.Callable[[Path], object], reason: str) -> None:
        """Change a copy of the corpus and check that verification rejects it.

        Parameters
        ----------
        change : collections.abc.Callable[[pathlib.Path], None]
            The change to apply to the copied corpus.
        reason : str
            A regular expression that the rejection message must match.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / CORPUS.name
            shutil.copytree(CORPUS, root)
            change(root)
            refresh(root)
            with pytest.raises((ValueError, KeyError), match=reason):
                verify(root, FIRST)

    def edit(self, path: str, change: cabc.Callable[[dict], None], reason: str) -> None:
        """Change one JSON document of a copied corpus and check the rejection.

        Parameters
        ----------
        path : str
            The document, relative to the corpus root.
        change : collections.abc.Callable[[dict], None]
            The change to apply to the parsed document.
        reason : str
            A regular expression that the rejection message must match.
        """

        def apply(root: Path) -> None:
            """Apply the change to the document of the copied corpus."""
            file = root / path
            data = json.loads(file.read_text())
            change(data)
            write(file, data)

        self.mutate(apply, reason)

    def test_forged_post_window(self) -> None:
        """A forged post-window timing gate is rejected."""
        self.edit(
            "raw/post/results/summary.json",
            lambda data: data["timing_gate"].update(host_elapsed_seconds=1800),
            "Post first lookup|timing",
        )

    def test_wrong_live_start_tick(self) -> None:
        """A live start tick that breaks continuity is rejected."""
        self.edit(
            "raw/post/capture-ready.json",
            lambda data: data.update(emulator_starttime="5983215"),
            "continuity",
        )

    def test_forged_pre_window(self) -> None:
        """A forged failed pre-window unit is rejected as a pre-socket failure."""
        self.mutate(
            lambda root: (root / "raw/pre/c80-failed-unit.txt").write_text(
                "Result=success\nExecMainStatus=0\n"
            ),
            "failed-before-socket",
        )

    def test_post_case_omission(self) -> None:
        """An omitted post case is rejected."""
        self.edit(
            "raw/post/results/summary.json",
            lambda data: data.update(cases={}),
            "Post first lookup",
        )

    def test_guard_wrong_owned_key(self) -> None:
        """A guard step that names a different owned key is rejected."""

        def change(data: dict) -> None:
            """Corrupt the owned key of the guard step."""
            step = data["steps"][7]
            assert step["op"] == "send", "guard step is not a send"
            assert step["hex"].endswith("65726f"), "owned key differs"
            step["hex"] = step["hex"][:-2] + "70"

        self.edit("raw/post/cleanup-guard-plan/plan.json", change, "guard source plan")

    def test_delete_plan_new_account(self) -> None:
        """A delete plan that adds a step is rejected."""
        self.edit(
            "raw/post/cleanup-delete-plan/plan.json",
            lambda data: data["steps"].append({"op": "close", "connection": "main"}),
            "delete/readback source plan",
        )

    def test_missing_postflight(self) -> None:
        """A postflight report that completes too few actions is rejected."""
        self.edit(
            "raw/post/postflight/report.json",
            lambda data: data.update(completed_actions=17),
            "Incomplete plan",
        )

    def test_packet_tail_corruption(self) -> None:
        """A corrupted packet tail is rejected even with a refreshed receipt."""

        def change(root: Path) -> None:
            """Corrupt the expiry marker and refresh the receipt digest."""
            path = root / "raw/post/lab-namespace.pcap"
            data = bytearray(path.read_bytes())
            offset = data.find(b"Expiry Zero")
            assert offset > 0, "expiry marker not found in the namespace capture"
            data[offset] ^= 1
            path.write_bytes(data)
            receipt = root / "raw/post/terminal.json"
            value = json.loads(receipt.read_text())
            value["namespace_pcap"]["sha256"] = hashlib.sha256(data).hexdigest()
            write(receipt, value)

        self.mutate(change, "paired TCP bytes|tail|flow")

    def test_clock_claim_changes(self) -> None:
        """A changed guest clock claim is rejected."""
        self.edit(
            "raw/post/clock-witness.json",
            lambda data: data["post_probe"].update(
                visible_guest_menubar_clock="Sat 6:00:00 AM"
            ),
            "Guest clock",
        )

    def test_capture_drop_is_rejected(self) -> None:
        """A kernel capture drop is rejected."""
        self.mutate(
            lambda root: (root / "raw/post/namespace-terminal-journal.log").write_text(
                "1 packets dropped by kernel\n"
            ),
            "capture drops",
        )

    def test_source_correction_changes(self) -> None:
        """A forged source correction is rejected."""
        self.mutate(
            lambda root: (
                root / "raw/post/sources/native_ban_expiry_control.py"
            ).write_text("# forged source\n"),
            "start-tick correction",
        )

    def test_allocated_trash_fingerprint_changes(self) -> None:
        """A changed allocated Trash fingerprint is rejected."""
        self.mutate(
            lambda root: (root / "raw/post/stopped-allocated-catalog.txt").write_text(
                "Banned\n"
            ),
            "Banned file|allocated Trash",
        )

    def test_fd_free_boundary_changes(self) -> None:
        """A changed file-descriptor-free boundary is rejected."""
        self.edit(
            "raw/post/stopped-read-gate.json",
            lambda data: data.update(image_fd_owners=[[774195, 6]]),
            "FD-free",
        )
