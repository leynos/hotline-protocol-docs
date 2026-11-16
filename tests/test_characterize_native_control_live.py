"""Characterize the live-host and plan gates of ``native_control_readiness``.

This is the state before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. No socket is
opened and no capture is run.
"""

import hashlib
import json
import os
import typing as typ
from pathlib import Path

import native_ban_control_cases as cases
import native_control_readiness as gates
import pytest
from native_ban_control_cases import A7_SHA

if typ.TYPE_CHECKING:
    from native_control_support import Report


def receipt_for(tmp_path: Path) -> Report:
    """Build a receipt that names this process as every watched process.

    Returns
    -------
    dict[str, typing.Any]
        A receipt that ``capture_gate`` accepts, once ``os.readlink`` answers.
    """
    pid = os.getpid()
    text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    stat = text.rsplit(") ", 1)[1].split()[19]
    magic = bytes.fromhex("d4c3b2a1")
    receipt: Report = {"primary_syn_count": 0, "ns_routes": []}
    for label in ("host", "namespace", "guest"):
        path = tmp_path / f"{label}.pcap"
        path.write_bytes(magic + bytes(20))
        receipt[f"{label}_pcap"] = str(path)
    for label in ("host", "namespace"):
        receipt[f"{label}_recorder_pid"] = pid
        receipt[f"{label}_recorder_starttime"] = stat
    receipt["emulator_pid"] = pid
    receipt["emulator_starttime"] = stat
    receipt["emulator_sha256"] = hashlib.sha256(
        Path(f"/proc/{pid}/exe").read_bytes()
    ).hexdigest()
    receipt["owned_working_image"] = "/image/working.dsk"
    receipt["emulator_netns"] = "net:[1]"
    return receipt


@pytest.fixture
def links(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the emulator's image descriptor and namespace link as the receipt says."""
    real = os.readlink

    def readlink(path: str | os.PathLike[str]) -> str:
        """Answer for the two links that the gate reads.

        Returns
        -------
        str
            The recorded image or namespace, or the real link.
        """
        text = os.fspath(path)
        if text.endswith("/fd/6"):
            return "/image/working.dsk"
        if text.endswith("/ns/net"):
            return "net:[1]"
        return real(path)

    monkeypatch.setattr(os, "readlink", readlink)


class CaptureGateTests:
    """The recorders and the emulator that the receipt names."""

    @pytest.mark.usefixtures("links")
    def test_a_receipt_of_live_processes_is_accepted(self, tmp_path: Path) -> None:
        """The running test stands for the recorders and the emulator."""
        gates.capture_gate(receipt_for(tmp_path))

    @pytest.mark.parametrize(
        ("key", "value"), [("primary_syn_count", 1), ("ns_routes", ["x"])]
    )
    def test_primary_contact_or_a_route_is_refused_first(
        self, tmp_path: Path, key: str, value: object
    ) -> None:
        """Before any file is read."""
        receipt = receipt_for(tmp_path)
        receipt[key] = value
        receipt["host_pcap"] = str(tmp_path / "absent")
        with pytest.raises(ValueError, match=r"^Primary contact or external route$"):
            gates.capture_gate(receipt)

    def test_a_missing_capture_file_is_a_file_error(self, tmp_path: Path) -> None:
        """The first file is read without a check of its own."""
        receipt = receipt_for(tmp_path)
        receipt["host_pcap"] = str(tmp_path / "absent")
        with pytest.raises(FileNotFoundError):
            gates.capture_gate(receipt)

    @pytest.mark.parametrize("label", ["host", "namespace", "guest"])
    def test_a_file_without_the_capture_magic_is_refused(
        self, tmp_path: Path, label: str
    ) -> None:
        """Each of the three files."""
        receipt = receipt_for(tmp_path)
        Path(receipt[f"{label}_pcap"]).write_bytes(bytes(24))
        with pytest.raises(ValueError, match=f"^{label} capture not ready$"):
            gates.capture_gate(receipt)

    def test_the_other_byte_orders_of_the_magic_are_accepted(
        self, tmp_path: Path
    ) -> None:
        """Both microsecond and nanosecond forms, in either order."""
        receipt = receipt_for(tmp_path)
        for label, magic in (("namespace", "a1b2c3d4"), ("guest", "4d3cb2a1")):
            Path(receipt[f"{label}_pcap"]).write_bytes(bytes.fromhex(magic) + bytes(20))
        receipt["emulator_pid"] = 2**22 + 1
        with pytest.raises(ValueError, match=r"^Actual lab emulator absent$"):
            gates.capture_gate(receipt)

    def test_a_host_file_with_packets_is_refused(self, tmp_path: Path) -> None:
        """The host recorder must hold only its header."""
        receipt = receipt_for(tmp_path)
        Path(receipt["host_pcap"]).write_bytes(bytes.fromhex("d4c3b2a1") + bytes(21))
        with pytest.raises(ValueError, match=r"^Primary SYN recorder is nonempty$"):
            gates.capture_gate(receipt)

    @pytest.mark.parametrize("label", ["host", "namespace"])
    def test_a_recorder_that_is_gone_is_refused(
        self, tmp_path: Path, label: str
    ) -> None:
        """No such process."""
        receipt = receipt_for(tmp_path)
        receipt[f"{label}_recorder_pid"] = 2**22 + 1
        with pytest.raises(ValueError, match=f"^{label} recorder absent$"):
            gates.capture_gate(receipt)

    @pytest.mark.parametrize("label", ["host", "namespace"])
    def test_a_recorder_with_another_start_time_is_refused(
        self, tmp_path: Path, label: str
    ) -> None:
        """A reused PID."""
        receipt = receipt_for(tmp_path)
        receipt[f"{label}_recorder_starttime"] = "1"
        with pytest.raises(ValueError, match=f"^{label} recorder PID reused$"):
            gates.capture_gate(receipt)

    def test_an_emulator_that_is_gone_is_refused(self, tmp_path: Path) -> None:
        """No such process."""
        receipt = receipt_for(tmp_path)
        receipt["emulator_pid"] = 2**22 + 1
        with pytest.raises(ValueError, match=r"^Actual lab emulator absent$"):
            gates.capture_gate(receipt)

    def test_an_emulator_with_another_start_time_is_refused(
        self, tmp_path: Path
    ) -> None:
        """A reused PID."""
        receipt = receipt_for(tmp_path)
        receipt["emulator_starttime"] = "1"
        with pytest.raises(ValueError, match=r"^Emulator PID reused$"):
            gates.capture_gate(receipt)

    @pytest.mark.usefixtures("links")
    @pytest.mark.parametrize(
        "key", ["emulator_sha256", "owned_working_image", "emulator_netns"]
    )
    def test_an_emulator_that_changed_is_refused(
        self, tmp_path: Path, key: str
    ) -> None:
        """The executable, the image and the namespace."""
        receipt = receipt_for(tmp_path)
        receipt[key] = "changed"
        message = r"^Emulator executable, image or namespace changed$"
        with pytest.raises(ValueError, match=message):
            gates.capture_gate(receipt)


class ControllerTests:
    """The root check."""

    def test_a_user_who_is_not_root_is_refused(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The message names /proc."""
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        with pytest.raises(PermissionError, match="requires root to inspect"):
            gates.require_controller_uid()

    def test_root_is_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Nothing is raised."""
        monkeypatch.setattr(os, "geteuid", lambda: 0)
        gates.require_controller_uid()


RUNTIME = {"source_a7_sha256": A7_SHA, "emulator_pid": 42}


def written(tmp_path: Path) -> Path:
    """Write the five plans and their digests.

    Returns
    -------
    pathlib.Path
        The plan directory.
    """
    directory = tmp_path / "plans"
    hashes = cases.write_plans(directory, RUNTIME, 15750)
    (directory / "source-hashes.json").write_text(json.dumps(hashes))
    return directory


class PlanGateTests:
    """The five plans that the planner hashed."""

    def test_the_written_plans_are_accepted(self, tmp_path: Path) -> None:
        """Their own digests and the emulator that they name."""
        gates.plan_gate(written(tmp_path), 42)

    def test_a_different_inventory_is_refused_first(self, tmp_path: Path) -> None:
        """A name missing from the hash list."""
        directory = written(tmp_path)
        hashes = json.loads((directory / "source-hashes.json").read_text())
        del hashes["probe"]
        (directory / "source-hashes.json").write_text(json.dumps(hashes))
        with pytest.raises(ValueError, match=r"^Plan inventory differs$"):
            gates.plan_gate(directory, 42)

    def test_a_missing_hash_list_is_a_file_error(self, tmp_path: Path) -> None:
        """The list is read first."""
        with pytest.raises(FileNotFoundError):
            gates.plan_gate(tmp_path, 42)

    @pytest.mark.parametrize("name", ["readiness", "guard", "seed", "ban", "probe"])
    def test_a_changed_plan_is_refused_by_name(self, tmp_path: Path, name: str) -> None:
        """A byte is added."""
        directory = written(tmp_path)
        path = directory / f"{name}.json"
        path.write_bytes(path.read_bytes() + b" ")
        with pytest.raises(ValueError, match=f"^{name} source plan changed$"):
            gates.plan_gate(directory, 42)

    def test_another_emulator_is_refused(self, tmp_path: Path) -> None:
        """The plans name PID 42."""
        with pytest.raises(ValueError, match=r"^Plan identity, profile or endpoint"):
            gates.plan_gate(written(tmp_path), 43)

    def test_a_plan_that_does_not_validate_is_refused_before_its_identity(
        self, tmp_path: Path
    ) -> None:
        """The generic validation names the schema."""
        directory = written(tmp_path)
        plan = json.loads((directory / "readiness.json").read_text())
        plan["schema_version"] = 2
        raw = json.dumps(plan).encode()
        (directory / "readiness.json").write_bytes(raw)
        hashes = json.loads((directory / "source-hashes.json").read_text())
        hashes["readiness"] = hashlib.sha256(raw).hexdigest()
        (directory / "source-hashes.json").write_text(json.dumps(hashes))
        with pytest.raises(ValueError, match="schema"):
            gates.plan_gate(directory, 42)
