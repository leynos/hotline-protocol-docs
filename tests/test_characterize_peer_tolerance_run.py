"""Characterize ``peer_tolerance_run.py``: what it records, with its own hash."""

import json
import signal
import sys
import typing as typ

import pytest
from peer_run_fakes import FIRST_PORT
from peer_run_rig import (
    COPIED,
    ORACLE_BYTES,
    OWNED,
    PEER_BYTES,
    SCRIPT,
    SHX,
    Rig,
    build_rig,
    manifest_of,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    """Build the synthetic repository and load the script against fakes.

    Returns
    -------
    Rig
        The prepared rig.
    """
    return build_rig(tmp_path, monkeypatch)


class PeerToleranceRunTests:
    """Pin what the receiver-matrix runner does, records and refuses."""

    def test_the_manifest_records_the_hash_of_the_running_script(
        self, rig: Rig
    ) -> None:
        """The runner and fixture hashes, and every other field, are as recorded."""
        rig.run()
        fixture = (rig.protocol / "scripts/peer_tolerance_fixture.py").read_bytes()
        expected = {
            "schema_version": 1,
            "profile": "compiled-historical-peer and controlled-receiver-fixture",
            "native_conformance": False,
            "source_commit": "c0ffee",
            "peer_binary_sha256": sha(PEER_BYTES),
            "oracle_sha256": sha(ORACLE_BYTES),
            "cases": list(rig.cases),
            "ports": list(range(FIRST_PORT, FIRST_PORT + len(rig.cases))),
            "real_home_file_before": None,
            "real_home_file_after": None,
            "source_fixture_sha256": sha(fixture),
            "source_runner_sha256": sha(SCRIPT.read_bytes()),
        }
        assert manifest_of(rig) == expected, manifest_of(rig)

    def test_the_four_sources_are_copied_and_frozen_with_their_sums(
        self, rig: Rig
    ) -> None:
        """Four scripts are copied from the protocol tree; every file is summed."""
        rig.run()
        copied = sorted(p.name for p in (rig.destination / "sources").iterdir())
        assert copied == sorted(COPIED), copied
        for name in COPIED:
            kept = (rig.destination / "sources" / name).read_bytes()
            assert kept == (rig.protocol / "scripts" / name).read_bytes(), name
        lines = (rig.destination / "SHA256SUMS").read_text().splitlines()
        files = sorted(
            p
            for p in rig.destination.rglob("*")
            if p.is_file() and p.name != "SHA256SUMS"
        )
        expected = [
            f"{sha(p.read_bytes())}  {OWNED}/{p.relative_to(rig.destination)}"
            for p in files
        ]
        assert lines == expected, lines

    def test_each_case_gets_a_plan_a_port_a_fixture_and_a_session(
        self, rig: Rig, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The plan, fixture and driver commands are built per case and port."""
        rig.run()
        evidence_scripts = rig.protocol / "scripts"
        fixtures = [
            argv for argv, _ in rig.boundary.popens if argv[0] == sys.executable
        ]
        assert len(fixtures) == len(rig.cases), fixtures
        for index, case in enumerate(rig.cases):
            port = FIRST_PORT + index
            expected = [
                sys.executable,
                str(evidence_scripts / "peer_tolerance_fixture.py"),
                "--evidence",
                str(rig.root / "evidence/gap-remediation/2026-11-13"),
                "--case",
                case,
                "--port",
                str(port),
                "--output",
                str(rig.work / "fixtures" / case),
            ]
            assert fixtures[index] == expected, fixtures[index]
            plan = json.loads((rig.work / f"plan-{case}.json").read_text())
            assert plan["environment"] == {
                "controlled_receiver_fixture": {
                    "profile": "controlled-receiver-fixture",
                    "case": case,
                    "source_peer": "shx 0.1.48 modern terminal build",
                }
            }, plan
            assert plan["steps"][0]["command"] == "hello", plan
            assert plan["steps"][1]["command"] == f"connect 127.0.0.1:{port}", plan
            argv, options = rig.boundary.runs[index]
            expected = [
                sys.executable,
                str(evidence_scripts / "capture_shx_session.py"),
                str(rig.work / f"plan-{case}.json"),
                "--binary",
                str(rig.root / "tools/shx-peer/source/hx"),
                "--peer-profile",
                str(rig.root / SHX / "peer-profile.json"),
                "--oracle-binary",
                str(rig.root / "evidence/hotline-server-1.9/inputs/HLserver19.pef"),
                "--output",
                str(rig.work / "captures" / case),
            ]
            assert argv == expected, argv
            assert options == {
                "capture_output": True,
                "text": True,
                "check": False,
            }, options
            log = (rig.destination / f"capture-{case}.log").read_text()
            assert log == "driver out\ndriver err\n", log
        out = capsys.readouterr().out
        done = [f"Completed full peer session: {case}\n" for case in rig.cases]
        assert out == "".join(done) + f"Frozen evidence: {rig.destination}\n", out

    def test_the_root_recorder_is_started_on_loopback_and_stopped_with_sigint(
        self, rig: Rig
    ) -> None:
        """One recorder covers ports 15600 to 15609 and ends with SIGINT."""
        rig.run()
        argv, recorder = rig.boundary.popens[0]
        expected = [
            "sudo",
            "-n",
            "tcpdump",
            "-i",
            "lo",
            "-y",
            "EN10MB",
            "-s",
            "0",
            "-U",
            "-Z",
            "leynos",
            "-w",
            str(rig.work / "host.pcap"),
            "tcp",
            "and",
            "portrange",
            "15600-15609",
        ]
        assert argv == expected, argv
        assert recorder.signals == [signal.SIGINT], recorder.signals
        assert recorder.waits == [10], recorder.waits
        assert rig.boundary.sleeps[0] == 1, rig.boundary.sleeps

    def test_every_port_is_probed_before_anything_is_created(self, rig: Rig) -> None:
        """A busy port stops the run before the work directory exists."""
        rig.boundary.busy_ports = {FIRST_PORT + 2}
        with pytest.raises(OSError, match="Address already in use"):
            rig.run()
        expected = [("127.0.0.1", FIRST_PORT + i) for i in range(3)]
        assert rig.boundary.binds == expected, rig.boundary.binds
        assert not rig.work.exists(), "work was created"
        assert rig.boundary.popens == [], "a process started"

    def test_the_home_file_state_is_recorded_when_it_exists(self, rig: Rig) -> None:
        """The hash, size and mtime of ``~/.hxvars`` are recorded before and after."""
        own = rig.home / ".hxvars"
        own.write_text("variables")
        rig.run()
        stat = own.stat()
        state = [sha(b"variables"), stat.st_size, stat.st_mtime_ns]
        manifest = manifest_of(rig)
        assert manifest["real_home_file_before"] == state, manifest
        assert manifest["real_home_file_after"] == state, manifest

    def test_a_changed_home_file_fails_the_run_before_the_manifest(
        self, rig: Rig
    ) -> None:
        """A change to ``~/.hxvars`` during a session stops the run."""
        own = rig.home / ".hxvars"
        own.write_text("variables")

        def disturb() -> None:
            """Change the guarded file while a session runs."""
            own.write_text("changed variables")

        rig.boundary.during_session = disturb
        message = "Real HOME/.hxvars changed; preserve private run and escalate"
        with pytest.raises(RuntimeError, match=message):
            rig.run()
        assert not (rig.work / "manifest.json").exists(), "manifest written"
        assert not rig.destination.exists(), "evidence frozen"
