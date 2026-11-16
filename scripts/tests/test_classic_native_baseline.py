"""Fault controls for the finite Classic/native proxy baseline corpus."""

import copy
import dataclasses as dc
import json
import typing as typ
from pathlib import Path

import pytest
from verify_classic_native_baseline import (
    check_source_snapshot,
    equal_pairs,
    flow,
    verify,
    verify_control,
    verify_proxy_log,
    verify_watchdog,
)

# scripts/tests sits two levels below the repository root that holds evidence/.
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01"
)


@dc.dataclass(frozen=True, slots=True)
class Captures:
    """The proxy reports and the wire streams split out of them."""

    reports: dict[str, dict[str, typ.Any]]
    client: dict[str, bytes]
    server: dict[str, bytes]
    data: tuple[bytes, bytes]


def wire(report: dict[str, typ.Any], events: tuple[str, ...]) -> bytes:
    """Join the raw bytes of the logged entries of the named events.

    Returns
    -------
    bytes
        The concatenated raw bytes, in log order.
    """
    return b"".join(
        bytes.fromhex(e["raw_hex"]) for e in report["entries"] if e["event"] in events
    )


@pytest.fixture(scope="module")
def captures() -> Captures:
    """Load the proxy reports of both cases once for the module.

    Returns
    -------
    Captures
        The reports and the client, server and banner streams of each case.
    """
    reports = {
        case: json.loads((CORPUS / case / "proxy/report.json").read_text())
        for case in ("b46", "b47")
    }
    return Captures(
        reports=reports,
        client={
            case: wire(r, ("client-handshake", "login-request", "client"))
            for case, r in reports.items()
        },
        server={
            case: wire(r, ("server-handshake", "server")) for case, r in reports.items()
        },
        data=(
            wire(reports["b47"], ("data-client",)),
            wire(reports["b47"], ("data-server",)),
        ),
    )


class ClassicNativeBaselineTests:
    """Reject each altered control, watchdog and proxy-log fact in the baseline."""

    def test_portable_corpus(self) -> None:
        """The retained corpus replays to its request types and banner sizes."""
        receipt = verify(CORPUS)
        assert receipt["b46"]["control"]["request_types"] == [107], (
            "the B46 request types differ"
        )
        assert receipt["b47"]["control"]["request_types"] == [107, 121, 300, 212], (
            "the B47 request types differ"
        )
        assert receipt["b47"]["data_bytes"] == [16, 58], "the banner sizes differ"

    def test_changed_frozen_proxy_source(self, tmp_path: Path) -> None:
        """A changed frozen proxy snapshot must fail its digest check."""
        source = json.loads((CORPUS / "manifest.json").read_text())["source"]
        base = tmp_path
        snapshot = base / source["proxy_snapshot_path"]
        snapshot.parent.mkdir()
        snapshot.write_bytes(
            (CORPUS / source["proxy_snapshot_path"]).read_bytes() + b"\n"
        )
        with pytest.raises(ValueError, match="As-run proxy snapshot"):
            check_source_snapshot(base, source, "proxy")

    def test_changed_reply_type(self, captures: Captures) -> None:
        """A changed reply type must break the reply sequence."""
        server = bytearray(captures.server["b47"])
        server[10:12] = (1).to_bytes(2, "big")
        with pytest.raises(ValueError, match="Reply sequence"):
            verify_control("b47", captures.client["b47"], bytes(server))

    def test_changed_reply_id(self, captures: Captures) -> None:
        """A changed reply ID must break the reply sequence."""
        server = bytearray(captures.server["b47"])
        server[12:16] = (9).to_bytes(4, "big")
        with pytest.raises(ValueError, match="Reply sequence"):
            verify_control("b47", captures.client["b47"], bytes(server))

    def test_wrong_login_161(self, captures: Captures) -> None:
        """A wrong field 161 in the login acknowledgement must be rejected."""
        server = captures.server["b47"].replace(
            bytes.fromhex("00a100020000"), bytes.fromhex("00a100020001"), 1
        )
        with pytest.raises(ValueError, match="Login ACK fields"):
            verify_control("b47", captures.client["b47"], server)

    def test_changed_agreement(self, captures: Captures) -> None:
        """A changed agreement text must be rejected."""
        server = captures.server["b47"].replace(
            b"This is the server agreement", b"That is the server agreement", 1
        )
        with pytest.raises(ValueError, match="Agreement text"):
            verify_control("b47", captures.client["b47"], server)

    def test_b46_did_not_get_121(self, captures: Captures) -> None:
        """A B46 case that sends request 121 must not pass as a B47 case."""
        with pytest.raises(ValueError, match="Request sequence"):
            verify_control("b47", captures.client["b46"], captures.server["b47"])
        with pytest.raises(ValueError, match="Request sequence"):
            verify_control("b46", captures.client["b47"], captures.server["b46"])

    def test_changed_capture_view(self, captures: Captures) -> None:
        """One differing capture view must fail the byte-identity check."""
        pairs = [(captures.client["b47"], captures.server["b47"])] * 5
        pairs[2] = (captures.client["b47"][:-1] + b"x", captures.server["b47"])
        with pytest.raises(ValueError, match="Capture view byte mismatch"):
            equal_pairs(pairs, [150, 514])

    def test_missing_guest_syn(self) -> None:
        """A route with no SYN in the capture must be refused."""
        route = ["client-guest-post.pcap", "10.0.2.15", 49162, "10.0.2.2", 15652]
        with pytest.raises(ValueError, match="Missing or reused route SYN"):
            flow([], route)

    def test_late_relay_teardown(self, captures: Captures) -> None:
        """A relay torn down after the watchdog window must be rejected."""
        report = copy.deepcopy(captures.reports["b47"])
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        with pytest.raises(ValueError, match="Watchdog teardown"):
            verify_watchdog(report)

    def test_native_rejection_claim_and_bad_banner(self, captures: Captures) -> None:
        """A native rejection claim and an altered banner must both be refused."""
        report = copy.deepcopy(captures.reports["b47"])
        report["status"] = "native-rejection"
        with pytest.raises(ValueError, match="Proxy outcome"):
            verify_watchdog(report)
        with pytest.raises(ValueError, match="Data server log"):
            verify_proxy_log(
                "b47",
                captures.reports["b47"],
                captures.client["b47"],
                captures.server["b47"],
                (captures.data[0], captures.data[1][:-1] + b"x"),
            )
