"""Reconcile socket recordings with independently observed TCP lifetimes."""

from datetime import datetime

from pcap_tcp import direction, lifetime, stream
from verify_native_core import require


def reconcile(
    report: dict,
    host: list[dict],
    guest: list[dict],
    unread_output: dict[str, bytes] | None = None,
) -> dict:
    """Require exact bytes in both views, retaining guest close observations."""
    observations = {}
    started = datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
    for event in report["events"]:
        if event["event"] != "connect":
            continue
        name = event["connection"]
        source = tuple(event["local_address"])
        endpoint = tuple(event["peer_address"])
        connect_us = int(started + event["elapsed_ns"] / 1000)
        guest_source = ("10.0.2.2", source[1])
        guest_endpoint = ("10.0.2.15", 5500 + endpoint[1] - 15500)
        recorded = report["streams"][name]
        packets = []
        for label, all_packets, client, server in [
            ("host", host, source, endpoint),
            ("guest", guest, guest_source, guest_endpoint),
        ]:
            packets = lifetime(all_packets, client, server, connect_us)
            require(
                stream(packets, client, server).hex() == recorded["sent_hex"],
                f"{name}: {label} input differs",
            )
            unread = (unread_output or {}).get(name, b"")
            require(
                stream(packets, server, client)
                == bytes.fromhex(recorded["received_hex"]) + unread,
                f"{name}: {label} output differs",
            )
        incoming = direction(packets, guest_source, guest_endpoint)
        outgoing = direction(packets, guest_endpoint, guest_source)
        client_ends = [p for p in incoming if p["flags"] & 5]
        server_ends = [p for p in outgoing if p["flags"] & 5]
        server_first = bool(server_ends) and (
            not client_ends
            or server_ends[0]["timestamp_us"] < client_ends[0]["timestamp_us"]
        )
        observations[name] = {
            "client_port": source[1],
            "sent_bytes": len(bytes.fromhex(recorded["sent_hex"])),
            "received_bytes": len(bytes.fromhex(recorded["received_hex"])),
            "unread_output_hex": (unread_output or {}).get(name, b"").hex(),
            "guest_server_initiated_close": server_first,
            "guest_server_close_kind": ("RST" if server_ends[0]["flags"] & 4 else "FIN")
            if server_ends
            else None,
        }
    require(set(observations) == set(report["streams"]), "Missing socket identity")
    return observations
