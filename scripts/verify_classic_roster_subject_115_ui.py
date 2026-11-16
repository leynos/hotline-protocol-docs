"""Check the connected screenshot against the guest delivery of the roster."""

import typing as typ

from verify_classic_roster_subject_115_common import load, need, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

    from verify_classic_roster_subject_115_common import Packets

DELIVERY_PACKET_INDEX = 478  # the record index of the roster packet at the guest
DELIVERY_TIMESTAMP_US = 1_794_629_905_744_557  # the guest delivery time, microseconds
SOURCE_MTIME_NS = 1_794_629_906_672_474_509  # the host mtime of the screenshot


def ui_check(base: Path, packets: Packets) -> dict[str, typ.Any]:
    """Check the screenshot identity and its order after the roster delivery.

    Returns
    -------
    dict[str, typing.Any]
        The screenshot path and the seconds from delivery to the snapshot.
    """
    receipt = load(base / "ui-timing.json")
    screenshot = base / receipt["screenshot"]
    need(
        screenshot.is_file()
        and sha(screenshot.read_bytes()) == receipt["screenshot_sha256"],
        "UI screenshot identity",
    )
    need(
        receipt["screenshot"] == "run/after-agree-1s.png"
        and receipt["screenshot_sha256"]
        == "d2b9c17e3176044ab981f4c1bee036bfc8eb38dfafd4180f46e1422f500751bc",
        "UI image provenance",
    )
    need(
        receipt["source_file_mtime_ns"] == SOURCE_MTIME_NS,
        "UI host mtime receipt",
    )
    arrivals = [
        p
        for p in packets["pcaps/client-guest-post.pcap"]
        if b"fixture-subject" in bytes.fromhex(p["payload_hex"])
        and p["dst_ip"] == "10.0.2.15"
    ]
    need(
        len(arrivals) == 1
        and arrivals[0]["timestamp_us"] == receipt["guest_delivery_packet_timestamp_us"]
        and receipt["guest_delivery_packet_index"] == DELIVERY_PACKET_INDEX,
        "guest roster delivery packet",
    )
    need(
        receipt["guest_delivery_packet_timestamp_us"] == DELIVERY_TIMESTAMP_US
        and receipt["source_file_mtime_ns"] // 1000
        > receipt["guest_delivery_packet_timestamp_us"],
        "UI after delivery",
    )
    need(
        receipt["proxy_audit_timestamp_us"]
        <= receipt["guest_delivery_packet_timestamp_us"],
        "UI proxy packet sequence",
    )
    # The visual assertion was reviewed from this exact image; timestamp is retained
    # source-host metadata and does not independently prove client rendering time.
    return {
        "screenshot": receipt["screenshot"],
        "delivery_to_snapshot_seconds": (
            receipt["source_file_mtime_ns"] // 1000
            - receipt["guest_delivery_packet_timestamp_us"]
        )
        / 1e6,
    }
