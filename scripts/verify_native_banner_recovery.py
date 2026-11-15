"""Check the phase-checked banner recovery captures and the post-reset boundary.

Recovery cases pause for three minutes of GUI phases and confirm each phase
through freshly authenticated sessions; the post-reset case checks that bytes
sent after a reset are accounted for in both packet views.
"""

import datetime as dt
import typing as typ

from native_banner_cases import GIF_B, URL
from native_plan import packet
from native_wire_names import (
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_NAME,
    HTXF_MAGIC_HEX,
    TYPE_EMPTY_ACK,
)
from pcap_tcp import direction, lifetime, stream
from verify_native_banner_format_checks import (
    HTXF_BANNER_TAIL_HEX,
    OWNER_REQUEST,
    banner_ack,
    banners,
    requests,
)
from verify_native_banners import fields
from verify_native_core import require
from verify_native_queues import frame_time

type Report = dict[str, typ.Any]

ABSENT_DELIMITER = ("absent", 91)  # the 500 that closes the absent phase
RESTORED_DELIMITER = ("restored", 92)
PHASE_PAUSES = 12
PHASE_PAUSE_SECONDS = 30
PLANNED_PAUSE_SECONDS = 360
NANOSECONDS_PER_SECOND = 1e9
MICROSECONDS_PER_SECOND = 1e6
NANOSECONDS_PER_MICROSECOND = 1000
BANNER_GUEST_PORT = 5501
TCP_RST = 4
OWNER_ACKS = [*range(20, 26), *range(30, 36), 80, 90]
RECOVERY_QUIETS = 2
POST_RESET_REQUEST = 90
HOST_ADDRESS = "10.0.2.2"
GUEST_ADDRESS = "10.0.2.15"
GUEST_BASE_PORT = 5500
RECORDER_BASE_PORT = 15500


def has_reply(report: Report, connection: str, identifier: int) -> bool:
    """Say whether a connection received an error-free reply to a request.

    Returns
    -------
    bool
        True when a reply with that ID and no error exists.
    """
    return any(
        f["connection"] == connection
        and f["is_reply"]
        and f["id"] == identifier
        and f["error"] == 0
        for f in report["frames"]
    )


def check_initial_banner(report: Report, plan: Report, *, early: bool) -> None:
    """Check the 122 that a delayed login emits before its 212 request."""
    initial = banners(report, "main")
    require(
        len(initial) == (0 if early else 1), "Initial delayed banner metadata differs"
    )
    if initial:
        require(
            fields(initial[0]) == {FIELD_BANNER_TYPE: b"GIFf", FIELD_BANNER_LINK: URL},
            "Initial recovery metadata differs",
        )
        ack_frame = next(
            f
            for f in report["frames"]
            if f["connection"] == "main" and f["is_reply"] and f["id"] == OWNER_REQUEST
        )
        require(
            initial[0]["action"] < ack_frame["action"],
            "Initial banner was not advertised before212",
        )
    if "initial_completion" in plan["expectation"]:
        require(
            plan["expectation"]["initial_completion"]
            == ("early" if early else "delayed"),
            "Recovery input mode differs",
        )


def check_phases(report: Report) -> None:
    """Check the phase delimiters and the owner's activity ACKs."""
    for connection, identifier in [ABSENT_DELIMITER, RESTORED_DELIMITER]:
        require(
            has_reply(report, connection, identifier),
            "Missing protocol phase delimiter",
        )
    for identifier in OWNER_ACKS:
        require(has_reply(report, "main", identifier), "Missing owner activity ACK")


def check_pauses(report: Report, plan: Report) -> None:
    """Check that every 30-second GUI phase pause was observed in full."""
    pauses = [
        e
        for e in report["events"]
        if e["event"] == "pause"
        and plan["steps"][e["action"]]["seconds"] == PHASE_PAUSE_SECONDS
    ]
    require(len(pauses) == PHASE_PAUSES, "Recovery pause inventory differs")
    for event in pauses:
        prior = max(
            e["elapsed_ns"]
            for e in report["events"]
            if e["action"] == event["action"] - 1
        )
        require(
            event["elapsed_ns"] - prior >= PHASE_PAUSE_SECONDS * NANOSECONDS_PER_SECOND,
            "Shortened recovery phase pause",
        )


def check_recovery(report: Report, plan: Report) -> Report:
    """Check a recovery case: absent then restored banner, in the right order.

    Returns
    -------
    dict[str, typing.Any]
        The advertised size, the input mode and the first quiet and receive times.
    """
    require(report["status"] == "completed", "Incomplete recovery observation")
    reference, size = banner_ack(report)
    require(size == len(GIF_B), "Recovery advertisement differs")
    require(not banners(report, "absent"), "Missing phase still advertises banner")
    restored = banners(report, "restored")
    require(
        len(restored) == 1
        and fields(restored[0]) == {FIELD_BANNER_TYPE: b"GIFf", FIELD_BANNER_LINK: URL},
        "Restored phase lacks GIF metadata",
    )
    early = FIELD_NAME in fields(requests(report, "main")[0])
    check_initial_banner(report, plan, early=early)
    check_phases(report)
    data = report["streams"]["banner"]
    require(
        data["sent_hex"] == HTXF_MAGIC_HEX + reference.hex() + HTXF_BANNER_TAIL_HEX,
        "Recovery reference changed",
    )
    require(bytes.fromhex(data["received_hex"]) == GIF_B, "Restored payload differs")
    quiets = [
        e
        for e in report["events"]
        if e["connection"] == "banner" and e["event"] == "quiet"
    ]
    receives = [
        e
        for e in report["events"]
        if e["connection"] == "banner" and e["event"] == "receive"
    ]
    require(
        len(quiets) == RECOVERY_QUIETS
        and quiets[0]["elapsed_ns"]
        < receives[0]["elapsed_ns"]
        < quiets[1]["elapsed_ns"],
        "Recovery silence/data ordering differs",
    )
    check_pauses(report, plan)
    return {
        "advertised_bytes": size,
        "initial_completion": "early" if early else "delayed",
        "received_bytes": len(GIF_B),
        "planned_pause_seconds": PLANNED_PAUSE_SECONDS,
        "first_quiet_elapsed_seconds": quiets[0]["elapsed_ns"] / NANOSECONDS_PER_SECOND,
        "first_receive_elapsed_seconds": receives[0]["elapsed_ns"]
        / NANOSECONDS_PER_SECOND,
    }


def check_post_reset_streams(
    report: Report, packets: Report, difference: Report
) -> None:
    """Check each connection's bytes in the host and guest packet views.

    ``packets`` holds the host and guest captures, as ``{"host": ..., "guest": ...}``.
    """
    started = (
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
    )
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        client, endpoint = tuple(event["local_address"]), tuple(event["peer_address"])
        when = int(started + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND)
        name = event["connection"]
        recorded = report["streams"][name]
        for label, source, target in [
            ("host", client, endpoint),
            (
                "guest",
                (HOST_ADDRESS, client[1]),
                (GUEST_ADDRESS, GUEST_BASE_PORT + endpoint[1] - RECORDER_BASE_PORT),
            ),
        ]:
            selected = lifetime(packets[label], source, target, when)
            expected = (
                difference["guest_sent_hex"]
                if label == "guest" and name == "main"
                else recorded["sent_hex"]
            )
            require(
                stream(selected, source, target).hex() == expected,
                "Post-reset boundary input differs",
            )
            require(
                stream(selected, target, source).hex() == recorded["received_hex"],
                "Post-reset boundary output differs",
            )


def check_post_reset_write(
    report: Report,
    host: list[Report],
    guest: list[Report],
    difference: Report,
) -> None:
    """Check that the write after a reset was sent, but never consumed."""
    require(
        difference["case"] == "empty-followup-ack"
        and difference["connection"] == "main",
        "Unexpected post-reset boundary case",
    )
    require(
        report["streams"]["main"]["sent_hex"] == difference["host_sent_hex"],
        "Post-reset host write differs",
    )
    follow_up = packet(TYPE_EMPTY_ACK, POST_RESET_REQUEST)
    require(
        difference["host_sent_hex"] == difference["guest_sent_hex"] + follow_up
        and difference["unconsumed_suffix_hex"] == follow_up,
        "Post-reset unconsumed suffix differs",
    )
    check_post_reset_streams(report, {"host": host, "guest": guest}, difference)


def check_native_restore(guest: list[Report], report: Report, summary: Report) -> None:
    """Check in the guest view that the banner bytes followed the restoration.

    The summary gains the delay of the first native data after the 212 ACK.
    """
    connect = next(
        e
        for e in report["events"]
        if e["connection"] == "banner" and e["event"] == "connect"
    )
    started = (
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
    )
    client = (HOST_ADDRESS, connect["local_address"][1])
    server = (GUEST_ADDRESS, BANNER_GUEST_PORT)
    selected = lifetime(
        guest,
        client,
        server,
        int(started + connect["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND),
    )
    native_data = [
        p
        for p in direction(selected, server, client)
        if p["payload_hex"] and not p["flags"] & TCP_RST
    ]
    require(bool(native_data), "Missing native restored-banner bytes")
    ack = next(
        f
        for f in report["frames"]
        if f["connection"] == "main" and f["is_reply"] and f["id"] == OWNER_REQUEST
    )
    first = min(p["timestamp_us"] for p in native_data)
    require(
        started + summary["first_quiet_elapsed_seconds"] * MICROSECONDS_PER_SECOND
        < first
        <= started + summary["first_receive_elapsed_seconds"] * MICROSECONDS_PER_SECOND,
        "Native restore/read ordering differs",
    )
    summary["first_native_data_after_ack_seconds"] = (
        first - frame_time(report, ack, guest)
    ) / MICROSECONDS_PER_SECOND
