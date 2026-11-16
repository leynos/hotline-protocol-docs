"""Check the banner, the proxy audit and the watchdog of the roster witness."""

import typing as typ

from verify_classic_roster_subject_115_common import (
    FORWARDED_ROSTER_SHA,
    RAW_ACK_SHA,
    RAW_ROSTER_SHA,
    load,
    need,
)
from verify_classic_roster_subject_115_wire import (
    Exchange,
    build_exchange,
    check_frame_headers,
    check_login_and_name,
    check_roster,
)
from verify_mac_peer_first_session import field_map

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from verify_classic_roster_subject_115_common import Packets

REFERENCE_INDEX = 6  # position of the reply that carries the transfer reference
DATA_HEADER_BYTES = 16  # length of the data-stream header that carries the reference
BANNER_IMAGE_BYTES = 58  # length of the banner image, a single GIF89a frame
PROXY_ENTRIES = 15  # audit entries that the proxy writes for one session
CUTOFF_SPACING_NS = 28_000_000_000  # watchdog due time after the login ACK
OBSERVED_ELAPSED_NS = 28_129_110_855  # the recorded time from ACK to relay teardown
OBSERVATION_LIMIT_NS = 30_000_000_000  # the observation window the claim allows


def check_banner(exchange: Exchange) -> None:
    """Check the banner data stream against the transfer reference."""
    reference = field_map(exchange.replies[REFERENCE_INDEX])[107]
    data = exchange.data
    need(
        len(data[0][0]) == DATA_HEADER_BYTES
        and data[0][0][:4] == b"HTXF"
        and data[0][0][4:8] == reference
        and len(data[0][1]) == BANNER_IMAGE_BYTES
        and data[0][1][:6] == b"GIF89a",
        "banner data/reference",
    )


def logged_bytes(
    entries: list[dict[str, typ.Any]],
    events: cabc.Collection[str],
    key: str,
) -> bytes:
    """Join the bytes under ``key`` of every audit entry whose event is listed.

    Returns
    -------
    bytes
        The concatenated bytes, in audit order.
    """
    return b"".join(bytes.fromhex(e[key]) for e in entries if e["event"] in events)


def check_audit(base: Path, exchange: Exchange) -> dict[str, typ.Any]:
    """Check the proxy audit report against the captured control and data bytes.

    Returns
    -------
    dict[str, typing.Any]
        The parsed proxy report.
    """
    report = load(base / "run/proxy/report.json")
    entries = report["entries"]
    need(
        len(entries) == PROXY_ENTRIES
        and sum(e["raw_hex"] != e["forwarded_hex"] for e in entries) == 1,
        "single proxy audit mutation",
    )
    need(
        [e["event"] for e in entries]
        == [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
            "client",
            "server",
            "server",
            "server",
            "client",
            "client",
            "server",
            "server",
            "data-client",
            "data-server",
        ],
        "proxy audit order",
    )
    need(
        logged_bytes(
            entries, {"client-handshake", "login-request", "client"}, "raw_hex"
        )
        == exchange.client
        and logged_bytes(entries, {"server-handshake", "server"}, "raw_hex")
        == exchange.raw
        and logged_bytes(entries, {"server-handshake", "server"}, "forwarded_hex")
        == exchange.downstream,
        "proxy audit/control bytes",
    )
    need(
        logged_bytes(entries, {"data-client"}, "raw_hex") == exchange.data[0][0]
        and logged_bytes(entries, {"data-server"}, "raw_hex") == exchange.data[0][1],
        "proxy audit/data bytes",
    )
    return report


def check_watchdog(report: dict[str, typ.Any], manifest: dict[str, typ.Any]) -> float:
    """Check the watchdog observation and the manifest roster hashes.

    Returns
    -------
    float
        The elapsed time from the login ACK to relay teardown, in seconds.
    """
    obs = report["observation"]
    elapsed = obs["relay_teardown_ns"] - obs["ack_sent_monotonic_ns"]
    need(
        report["status"] == "intentional-observation-cutoff"
        and report["variant"] == "roster-subject-115"
        and not report["errors"]
        and obs["state"] == "fired"
        and obs["valid_30_seconds"] is True,
        "watchdog outcome",
    )
    need(
        obs["cutoff_due_ns"] - obs["ack_sent_monotonic_ns"] == CUTOFF_SPACING_NS
        and elapsed == OBSERVED_ELAPSED_NS
        and elapsed < OBSERVATION_LIMIT_NS,
        "watchdog timing",
    )
    need(
        obs["raw_ack_sha256"] == obs["forwarded_ack_sha256"] == RAW_ACK_SHA,
        "watchdog login identity",
    )
    need(
        manifest["raw_roster_sha256"] == RAW_ROSTER_SHA
        and manifest["forwarded_roster_sha256"] == FORWARDED_ROSTER_SHA,
        "manifest roster hashes",
    )
    return elapsed / 1e9


def wire_check(
    base: Path,
    manifest: dict[str, typ.Any],
    packets: Packets,
) -> dict[str, typ.Any]:
    """Check the Classic control exchange, the roster reply and the audit trail.

    Returns
    -------
    dict[str, typing.Any]
        The frame types of both directions, the roster ID and lengths, and the
        watchdog time in seconds.
    """
    exchange = build_exchange(manifest, packets)
    check_frame_headers(exchange)
    check_login_and_name(exchange)
    roster = check_roster(exchange)
    check_banner(exchange)
    report = check_audit(base, exchange)
    watchdog_seconds = check_watchdog(report, manifest)
    return {
        "requests": [f["type"] for f in exchange.requests],
        "replies": [f["type"] for f in exchange.replies],
        "roster_id": roster["roster_id"],
        "roster_bytes": roster["roster_bytes"],
        "watchdog_seconds": watchdog_seconds,
    }
