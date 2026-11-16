"""Characterize ``capture_shx_session.py``: its report and its own hash."""

import typing as typ

import pytest
from shx_session_fakes import FD, PID
from shx_session_rig import (
    ORACLE_BYTES,
    PEER_BYTES,
    REPLIES,
    SCRIPT,
    STEPS,
    Rig,
    build_rig,
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


class CaptureReportTests:
    """Pin what a completed capture records, including its own hash."""

    def test_the_report_records_the_hash_of_the_running_script(self, rig: Rig) -> None:
        """``driver_sha256`` and the other identities are as recorded."""
        report = rig.capture()
        assert report["driver_sha256"] == sha(SCRIPT.read_bytes()), report
        assert report["peer_binary_sha256"] == sha(PEER_BYTES), report
        assert report["oracle_sha256"] == sha(ORACLE_BYTES), report
        assert report["plan_sha256"] == sha(rig.plan.read_bytes()), report
        assert report["peer_profile_sha256"] == sha(rig.profile.read_bytes()), report

    def test_the_report_of_a_completed_session(self, rig: Rig) -> None:
        """Status, steps, environment and home-file state of a clean session."""
        report = rig.capture()
        assert report["schema_version"] == 1, report
        assert report["profile"] == "compiled-historical-peer", report
        assert report["native_conformance"] is False, report
        assert report["status"] == "completed", report
        assert not report["error"], report
        assert report["completed_steps"] == len(STEPS), report
        assert report["environment"] == {"case": "x"}, report
        assert report["controller_child_pid"] == PID, report
        assert report["peer_exit_code"] == 0, report
        assert report["host_home_file_before"] == {"exists": False}, report
        assert report["host_home_file_after"] == {"exists": False}, report
        expected = {
            "LANG": "C.UTF-8",
            "LC_ALL": None,
            "LC_CTYPE": None,
            "TERM": "dumb",
        }
        assert report["terminal_environment"] == expected, report
        assert report == rig.read_report(), "the returned report is the one written"

    def test_the_command_is_bwrap_over_strace_over_the_peer(self, rig: Rig) -> None:
        """The sandbox plan: binds, chdir, strace options and the peer's flags."""
        report = rig.capture()
        out = rig.output
        expected = [
            "/usr/bin/bwrap",
            "--unshare-user",
            "--die-with-parent",
            "--ro-bind",
            "/",
            "/",
            "--bind",
            str(rig.root),
            str(rig.root),
            "--bind",
            str(out / "home"),
            str(rig.home),
            "--bind",
            str(out / "tmp"),
            "/tmp",  # ruff: ignore[hardcoded-temp-file]  # the sandbox's own /tmp, as written
            "--proc",
            "/proc",
            "--dev",
            "/dev",
            "--chdir",
            str(out / "work"),
            "--",
            "/usr/bin/strace",
            "-f",
            "-ttt",
            "-xx",
            "-yy",
            "-s",
            "131072",
            "-e",
            "trace=network,read,write,close,execve,exit_group",
            "-o",
            str(out / "syscalls.log"),
            str(rig.binary),
            "-q",
            "-d",
        ]
        assert report["command"] == expected, report["command"]
        assert rig.terminal.execs == [], "the child branch ran"

    def test_each_step_is_typed_and_every_event_is_recorded_in_order(
        self, rig: Rig
    ) -> None:
        """Input, output and process-exit events carry step numbers and hex."""
        report = rig.capture()
        assert rig.terminal.written == [b"help\n", b"quit\n"], rig.terminal.written
        kinds = [(e["event"], e["step"]) for e in report["events"]]
        expected = [
            ("input", 0),
            ("output", 0),
            ("input", 1),
            ("output", 1),
            ("process-exit", 1),
        ]
        assert kinds == expected, kinds
        hexes = [e["hex"] for e in report["events"]]
        assert hexes == [
            b"help\n".hex(),
            REPLIES["help"].hex(),
            b"quit\n".hex(),
            b"bye\r\n".hex(),
            b"0".hex(),
        ], hexes
        elapsed = [e["elapsed_ns"] for e in report["events"]]
        assert elapsed == sorted(elapsed), elapsed

    def test_the_captured_bytes_and_sums_are_written(self, rig: Rig) -> None:
        """The output directory holds the copies, the bytes, the report and sums."""
        rig.capture()
        out = rig.output
        expected = [
            "SHA256SUMS",
            "home",
            "peer-profile.json",
            "plan.json",
            "report.json",
            "stdout.bin",
            "stdout.txt",
            "tmp",
            "work",
        ]
        assert sorted(p.name for p in out.iterdir()) == expected, (
            "differs from the recorded value"
        )
        assert (out / "plan.json").read_bytes() == rig.plan.read_bytes(), "plan"
        kept = (out / "peer-profile.json").read_bytes()
        assert kept == rig.profile.read_bytes(), "peer-profile.json"
        raw = REPLIES["help"] + b"bye\r\n"
        assert (out / "stdout.bin").read_bytes() == raw, "stdout.bin"
        assert (out / "stdout.txt").read_bytes() == raw, "stdout.txt"
        files = sorted(
            p for p in out.iterdir() if p.is_file() and p.name != "SHA256SUMS"
        )
        expected = "".join(f"{sha(p.read_bytes())}  {p.name}\n" for p in files)
        assert (out / "SHA256SUMS").read_text() == expected, expected

    def test_the_terminal_is_closed_and_a_finished_child_is_not_signalled(
        self, rig: Rig
    ) -> None:
        """A child that exited by itself is neither killed nor waited for again."""
        rig.capture()
        assert rig.terminal.closed == [FD], rig.terminal.closed
        assert rig.terminal.killed == [], rig.terminal.killed
        assert not rig.terminal.reaped, "waited for an ended child"

    def test_the_home_file_is_guarded_and_its_state_recorded(self, rig: Rig) -> None:
        """An existing ``~/.hxvars`` is recorded by size, mtime and hash, twice."""
        guarded = rig.home / ".hxvars"
        guarded.write_text("variables")
        report = rig.capture()
        stat = guarded.stat()
        state = {
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "sha256": sha(b"variables"),
        }
        assert report["host_home_file_before"] == state, report
        assert report["host_home_file_after"] == state, report
        assert report["status"] == "completed", report

    def test_a_changed_home_file_fails_a_session_that_otherwise_completed(
        self, rig: Rig
    ) -> None:
        """A change to ``~/.hxvars`` during the capture overrides the status."""
        guarded = rig.home / ".hxvars"
        guarded.write_text("variables")

        def disturb(_: bytes) -> None:
            """Change the guarded file when a line is typed."""
            guarded.write_text("changed")

        rig.terminal.on_write = disturb
        report = rig.capture()
        assert report["completed_steps"] == len(STEPS), report
        assert report["status"] == "failed", report
        assert report["error"] == "Host home-file state changed during capture", report
        assert report["host_home_file_after"]["sha256"] == sha(b"changed"), report


def test_digest_hashes_a_file(tmp_path: Path, rig: Rig) -> None:
    """``digest`` is the SHA-256 of the file's bytes."""
    target = tmp_path / "f"
    target.write_bytes(b"abc")
    assert rig.module.digest(target) == sha(b"abc"), "digest differs"
