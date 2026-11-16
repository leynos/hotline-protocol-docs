"""Characterize ``peer_tolerance_run.py``: its refusals, failures and command line."""

import json
import signal
import sys
import typing as typ
from pathlib import Path

import pytest
from peer_run_fakes import FIRST_PORT
from peer_run_rig import SHX, Rig, build_rig, sha

if typ.TYPE_CHECKING:
    import collections.abc as cabc


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    """Build the synthetic repository and load the script against fakes.

    Returns
    -------
    Rig
        The prepared rig.
    """
    return build_rig(tmp_path, monkeypatch)


class PeerToleranceRunRefusalTests:
    """Pin the refusals, in the order in which the runner makes them."""

    def test_work_outside_the_private_root_is_refused(self, rig: Rig) -> None:
        """A work directory outside ``state/delegation/peer`` is refused."""
        rig.work = rig.root / "elsewhere/run-1"
        message = "Output paths must be owned private or evidence paths"
        with pytest.raises(ValueError, match=message):
            rig.run()

    def test_a_destination_other_than_the_owned_one_is_refused(self, rig: Rig) -> None:
        """Only the delegated-peer evidence directory is accepted."""
        rig.destination = rig.root / "evidence/other"
        message = "Output paths must be owned private or evidence paths"
        with pytest.raises(ValueError, match=message):
            rig.run()

    @pytest.mark.parametrize("existing", ["work", "destination"])
    def test_existing_outputs_are_refused(self, rig: Rig, existing: str) -> None:
        """A run or evidence directory that exists is refused."""
        getattr(rig, existing).mkdir(parents=True)
        message = "Run and evidence outputs must be fresh"
        with pytest.raises(ValueError, match=message):
            rig.run()

    def test_ownership_is_checked_before_freshness(self, rig: Rig) -> None:
        """An existing, unowned work directory is refused as unowned."""
        rig.work = rig.root / "elsewhere"
        rig.work.mkdir()
        with pytest.raises(ValueError, match="owned private or evidence paths"):
            rig.run()

    def test_a_peer_that_is_not_the_recorded_one_is_refused(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A peer binary whose hash differs is refused."""
        monkeypatch.setattr(rig.module, "PEER", "0" * 64)
        with pytest.raises(ValueError, match="Peer/oracle identity mismatch"):
            rig.run()
        assert not rig.work.exists(), "work was created"

    def test_an_oracle_that_is_not_the_recorded_one_is_refused(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An oracle binary whose hash differs is refused."""
        monkeypatch.setattr(rig.module, "ORACLE_SHA256", "0" * 64)
        with pytest.raises(ValueError, match="Peer/oracle identity mismatch"):
            rig.run()

    def test_a_profile_for_another_peer_is_refused(self, rig: Rig) -> None:
        """A profile that records another binary hash is refused."""
        profile = rig.root / SHX / "peer-profile.json"
        profile.write_text(json.dumps({"binary_sha256": "0" * 64}))
        message = "Recorded profile does not match the running peer"
        with pytest.raises(ValueError, match=message):
            rig.run()

    def test_a_missing_peer_binary_is_a_file_error_before_any_output(
        self, rig: Rig
    ) -> None:
        """The identity check reads the binary first, so its absence is raised."""
        (rig.root / "tools/shx-peer/source/hx").unlink()
        with pytest.raises(FileNotFoundError):
            rig.run()
        assert not rig.work.exists(), "work was created"


class PeerToleranceRunFailureTests:
    """Pin the failures of a started run: what stops, what is signalled."""

    def stopped(self, rig: Rig, message: str) -> None:
        """Run, expect the failure, and check that the run was left unfrozen.

        Parameters
        ----------
        rig : Rig
            The rig to run.
        message : str
            The message that the failure must carry.
        """
        with pytest.raises(RuntimeError, match=message):
            rig.run()
        assert not rig.destination.exists(), "evidence was frozen"
        assert not (rig.work / "manifest.json").exists(), "manifest was written"
        recorder = rig.boundary.popens[0][1]
        assert recorder.signals == [signal.SIGINT], recorder.signals

    def test_a_recorder_that_exits_early_stops_the_run(self, rig: Rig) -> None:
        """A recorder that has ended before the first session is a failure."""
        rig.boundary.recorder_exit = 1
        self.stopped(rig, "Loopback recorder exited before first session")
        assert len(rig.boundary.popens) == 1, "a fixture started"

    def test_a_fixture_that_never_signals_ready_stops_the_run(self, rig: Rig) -> None:
        """A fixture that ends without its ready file is a failure."""
        rig.boundary.fixture_ready = False
        rig.boundary.fixture_exit = 3
        self.stopped(rig, f"Fixture did not start: {rig.cases[0]}")
        assert rig.boundary.runs == [], "a session ran"

    def test_a_fixture_that_outlives_its_session_is_terminated(self, rig: Rig) -> None:
        """A fixture still live 35 seconds after the session gets SIGTERM."""
        rig.boundary.fixture_stalls = True
        self.stopped(rig, f"Fixture remained live: {rig.cases[0]}")
        server = rig.boundary.popens[1][1]
        assert server.signals == [signal.SIGTERM], server.signals
        assert server.waits == [35, 5], server.waits

    def test_a_failed_session_preserves_the_run_and_stops(self, rig: Rig) -> None:
        """A non-zero driver code stops the matrix and names the work directory."""
        rig.boundary.session_code = 1
        self.stopped(rig, f"Session failed: {rig.cases[0]}; preserved at ")
        assert len(rig.boundary.runs) == 1, "the matrix went on"
        log = (rig.work / f"capture-{rig.cases[0]}.log").read_text()
        assert log == "driver out\ndriver err\n", log

    def test_a_fixture_that_ends_badly_fails_the_session(self, rig: Rig) -> None:
        """A non-zero fixture code is a failed session too."""
        rig.boundary.fixture_code = 2
        self.stopped(rig, f"Session failed: {rig.cases[0]}")


def test_free_binds_the_loopback_port(rig: Rig) -> None:
    """The probe binds 127.0.0.1 and lets any error through."""
    rig.module.free(FIRST_PORT)
    assert rig.boundary.binds == [("127.0.0.1", FIRST_PORT)], rig.boundary.binds
    rig.boundary.busy_ports = {FIRST_PORT}
    with pytest.raises(OSError, match="Address already in use"):
        rig.module.free(FIRST_PORT)


def test_sha_hashes_a_file(tmp_path: Path, rig: Rig) -> None:
    """``sha`` is the SHA-256 of the file's bytes."""
    target = tmp_path / "f"
    target.write_bytes(b"abc")
    assert rig.module.sha(target) == sha(b"abc"), "digest differs"


class PeerToleranceRunCommandLineTests:
    """Pin the command line: four required options, handed to ``run`` as paths."""

    def invoke(
        self,
        rig: Rig,
        monkeypatch: pytest.MonkeyPatch,
        arguments: cabc.Sequence[str],
    ) -> list[tuple[Path, ...]]:
        """Run ``main`` with some arguments and a recording ``run``.

        Returns
        -------
        list[tuple[pathlib.Path, ...]]
            The arguments that ``run`` received, per call.
        """
        calls: list[tuple[Path, ...]] = []
        monkeypatch.setattr(rig.module, "run", lambda *given: calls.append(given))
        monkeypatch.setattr(sys, "argv", ["peer_tolerance_run.py", *arguments])
        rig.module.main()
        return calls

    def test_the_four_options_become_the_four_paths(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """``--root``, ``--protocol``, ``--work`` and ``--destination`` map in order."""
        calls = self.invoke(
            rig,
            monkeypatch,
            ["--root", "r", "--protocol", "p", "--work", "w", "--destination", "d"],
        )
        expected = [(Path("r"), Path("p"), Path("w"), Path("d"))]
        assert calls == expected, calls

    def test_a_missing_option_is_a_usage_error(
        self, rig: Rig, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each option is required; argparse exits with status 2."""
        with pytest.raises(SystemExit) as caught:
            self.invoke(rig, monkeypatch, ["--root", "r"])
        assert caught.value.code == 2, caught.value.code
