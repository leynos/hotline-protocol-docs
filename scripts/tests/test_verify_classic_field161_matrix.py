"""Fault controls for the portable Classic field-161 corpus."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_classic_field161_matrix import (
    check_case,
    check_readiness,
    check_source_snapshot,
    verify,
)

# scripts/tests sits two levels below the repository root that holds evidence/.
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/classic-field161-01"
)
# Decision D18: the retained corpus is refused at the capture gate, because the
# hash of mothra's capture_readiness.py no longer matches the manifest. The
# golden records this test as an error with this message.
KNOWN_RED = "capture gate source identity"
REPLAY_REASON = f"ValueError: {KNOWN_RED}"


class ClassicField161MatrixTests:
    """Reject each altered frozen source, receipt, journal, unit and cutoff fact."""

    @pytest.fixture(autouse=True)
    def _load(self, tmp_path: Path) -> None:
        """Copy the corpus into a fresh scratch directory and read its manifest."""
        self.base = tmp_path / "classic-field161-01"
        shutil.copytree(CORPUS, self.base)
        self.manifest = json.loads((self.base / "manifest.json").read_text())

    def packets(self) -> dict[str, list[dict[str, typ.Any]]]:
        """Read every selected PCAP view of the scratch copy.

        Returns
        -------
        dict[str, list[dict[str, typing.Any]]]
            The packets of each view, keyed ``pcaps/NAME``.
        """
        return {
            "pcaps/" + p.name: read_packets(p)
            for p in (self.base / "pcaps").glob("*.pcap")
        }

    def case(self, name: str = "one-byte-161") -> dict[str, typ.Any]:
        """Check one case of the scratch copy.

        Returns
        -------
        dict[str, typing.Any]
            The case verdict.
        """
        return check_case(self.base, name, self.manifest["cases"][name], self.packets())

    @pytest.mark.xfail(
        raises=ValueError,
        strict=True,
        reason=REPLAY_REASON,
    )
    def test_original_corpus_replays(self) -> None:
        """Replay the retained corpus; it is known red, and only for one reason.

        The replay must raise the capture-gate ``ValueError``. A pass is an
        unexpected success, which the strict marker turns into a failure; any
        other exception, or the same type with another message, also fails.

        Raises
        ------
        ValueError
            The capture-gate refusal, which the marker expects.
        AssertionError
            If the replay raises a ``ValueError`` with another message.
        """
        try:
            result = verify(CORPUS)
        except ValueError as error:
            if str(error) != KNOWN_RED:
                message = f"the replay was refused for another reason: {error}"
                raise AssertionError(message) from error
            raise
        assert set(result["cases"]) == {"omit-161", "one-byte-161", "four-byte-161"}, (
            'set(result["cases"]) == {"omit-161", "one-byte-161", "four-byte-161"}'
        )
        assert result["capture"]["journals_zero_drops"], (
            'result["capture"]["journals_zero_drops"]'
        )

    def test_changed_frozen_proxy_source_rejected(self) -> None:
        """A changed proxy snapshot is refused."""
        snapshot = self.base / "as-run/classic_login_proxy.py.txt"
        snapshot.write_bytes(snapshot.read_bytes() + b"\n")
        with pytest.raises(ValueError, match="proxy source snapshot"):
            check_source_snapshot(self.base, self.manifest["source"], "proxy")

    def test_wrong_forwarded_ack_guest_byte_rejected(self) -> None:
        """A flipped byte in the forwarded ACK breaks downstream parity."""
        p = self.base / "pcaps/client-guest-post.pcap"
        data = bytearray(p.read_bytes())
        report = json.loads((self.base / "one-byte-161/proxy/report.json").read_text())
        ack = bytes.fromhex(report["entries"][3]["forwarded_hex"])
        offset = data.find(ack)
        assert offset > 0, "offset > 0"
        data[offset + len(ack) - 1] ^= 1
        p.write_bytes(data)
        with pytest.raises(ValueError, match="downstream parity"):
            self.case()

    def test_missing_guest_record_rejected(self) -> None:
        """A truncated guest capture cannot be read."""
        p = self.base / "pcaps/client-guest-post.pcap"
        p.write_bytes(p.read_bytes()[:-5])
        with pytest.raises(ValueError, match="Truncated"):
            self.packets()

    def test_wrong_expected_161_ack_rejected(self) -> None:
        """A wrong expected ACK digest is refused."""
        self.manifest["cases"]["one-byte-161"]["expected_ack_sha256"] = "0" * 64
        with pytest.raises(ValueError, match="source/forwarded ACK"):
            self.case()

    def test_kernel_drop_claim_rejected(self) -> None:
        """A journal that claims a kernel drop is refused."""
        p = self.base / "ns-recorder-journal.txt"
        p.write_text(
            p.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel"
            )
        )
        with pytest.raises(ValueError, match="capture drops"):
            check_readiness(self.base, self.manifest)

    def test_late_cutoff_rejected(self) -> None:
        """A teardown later than the cutoff is refused."""
        p = self.base / "one-byte-161/proxy/report.json"
        report = json.loads(p.read_text())
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        p.write_text(json.dumps(report))
        with pytest.raises(ValueError, match="cutoff timing"):
            self.case()

    def test_live_unit_claim_after_cleanup_rejected(self) -> None:
        """A unit that still claims a main PID after cleanup is refused."""
        p = self.base / "units-terminal.txt"
        p.write_text(p.read_text().replace("MainPID=0", "MainPID=42", 1))
        with pytest.raises(ValueError, match="unit cleanup"):
            check_readiness(self.base, self.manifest)
