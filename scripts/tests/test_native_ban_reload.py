"""Semantic fault controls for the frozen persisted-ban reload witness."""

import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path
from shutil import copytree

import pytest
from native_control_readiness import probe
from verify_native_ban_reload import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-ban-reload-01"
)
C56 = CORPUS.parent / "native-ban-control-01"


class NativeBanReloadTest:
    """Semantic fault controls for the frozen persisted-ban reload witness."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def report(self) -> Report:
        """Load the one-probe capture report of the frozen corpus.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the probe capture.
        """
        return json.loads((CORPUS / "c61/probe-capture/report.json").read_text())

    def test_frozen_replay(self) -> None:
        """The frozen witness replays to its 42-byte login rejection."""
        assert verify(CORPUS)["login_error_bytes"] == 42, "login error length differs"

    def test_wrong_error_text(self) -> None:
        """A changed login error text is rejected by the probe check."""
        report = self.report()
        report["frames"][0]["fields"][0]["hex"] = "78"
        with pytest.raises(ValueError, match="Permanent login rejection differs"):
            probe(report)

    def test_missing_trtp_hello(self) -> None:
        """A probe whose TRTP hello is missing is rejected by the probe check."""
        report = self.report()
        sends = [e for e in report["events"] if e["event"] == "send"]
        sends[0]["hex"] = "00"
        with pytest.raises(ValueError, match="Fresh TRTP plus Login107 absent"):
            probe(report)

    def corrupt(self, change: cabc.Callable[[Path], None], reason: str) -> None:
        """Change a copy of the witness, rehash it and expect the verifier to reject it.

        Parameters
        ----------
        change : collections.abc.Callable[[pathlib.Path], None]
            The change to make to the copied corpus.
        reason : str
            A regular expression that the rejection message must match.
        """
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
            with pytest.raises(ValueError, match=reason):
                verify(p)

    def edit_json(
        self,
        p: Path,
        name: str,
        edit: cabc.Callable[[dict[str, typ.Any]], None],
    ) -> None:
        """Apply an edit to one JSON file of the copied corpus.

        Parameters
        ----------
        p : pathlib.Path
            The copied corpus.
        name : str
            The path of the JSON file, relative to the copied corpus.
        edit : collections.abc.Callable[[dict[str, typing.Any]], None]
            The edit to apply to the parsed value.
        """
        file = p / name
        value = json.loads(file.read_text())
        edit(value)
        file.write_text(json.dumps(value))

    def test_rehashed_emulator_identity(self) -> None:
        """A rehashed emulator identity that differs from the boot is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/ui-ready.json",
                lambda x: x["actual_emulator"].update(starttime="1"),
            ),
            "Read-only UI boot identity differs",
        )

    def test_rehashed_read_only_ui_claim(self) -> None:
        """A rehashed UI claim that the Ban tab was saved is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p, "c61/ui-observation.json", lambda x: x["ban_tab"].update(saved=True)
            ),
            "Read-only Ban UI row or Cancel claim differs",
        )

    def test_rehashed_target_vector(self) -> None:
        """A rehashed probe vector with a changed fresh login is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/probe-asrun.json",
                lambda x: x["steps"][3].update(hex="0000006b00000002"),
            ),
            "Prepared/as-run one-probe vector differs",
        )

    def test_rehashed_extra_ban_request(self) -> None:
        """A rehashed probe vector with an extra 110 request is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/probe-asrun.json",
                lambda x: x["steps"].insert(4, {"op": "send", "hex": "0000006e"}),
            ),
            "Prepared/as-run one-probe vector differs",
        )

    def test_rehashed_packet_byte_parity(self) -> None:
        """A rehashed guest packet view that differs from the stream is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "packet-views.json",
                lambda x: x["views"]["guest"].update(received_hex="00"),
            ),
            "guest complete scoped TCP stream differs",
        )

    def test_rehashed_recorder_deadline(self) -> None:
        """A rehashed recorder deadline that differs from the boot is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p,
                "c61/host-ready-preprobe.json",
                lambda x: x.update(deadline_utc="2026-11-14T04:00:00+00:00"),
            ),
            "host recorder identity or deadline differs",
        )

    def test_rehashed_packet_drop(self) -> None:
        """A rehashed recorder log that reports a dropped packet is rejected."""

        def change(p: Path) -> None:
            """Report one dropped packet in the namespace recorder log.

            Parameters
            ----------
            p : pathlib.Path
                The copied corpus.
            """
            path = p / "c61/namespace-recorder.log"
            path.write_bytes(
                path.read_bytes().replace(
                    b"0 packets dropped by kernel", b"1 packets dropped by kernel"
                )
            )

        self.corrupt(change, "namespace recorder count/drop differs")

    def test_rehashed_cleanup(self) -> None:
        """A rehashed terminal profile that reports a live PID is rejected."""
        self.corrupt(
            lambda p: self.edit_json(
                p, "c61/terminal.json", lambda x: x.update(actual_pid_gone=False)
            ),
            "Terminal profile, forced retirement or ban bytes differ",
        )

    def test_rehashed_ban_bytes(self) -> None:
        """A rehashed stored ban file with one flipped bit is rejected."""

        def change(p: Path) -> None:
            """Flip the last bit of the stored ban file of the copied corpus.

            Parameters
            ----------
            p : pathlib.Path
                The copied corpus.
            """
            path = p / "c61/Banned-postprobe.data.bin"
            data = bytearray(path.read_bytes())
            data[-1] ^= 1
            path.write_bytes(data)

        self.corrupt(change, "Stored ban or account bytes differ")
