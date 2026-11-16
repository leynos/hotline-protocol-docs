"""Check the external HTTP exchanges and control FIN of the Classic client capture."""

import typing as typ

from verify_mac_peer_first_session_core import (
    AGREEMENT_US,
    FIN_FLAG,
    HOST_CLIENT,
    HTTP_CONNECTIONS,
    HTTP_HOST,
    HTTP_MESSAGE,
    HTTP_PORT,
    HTTP_REQUEST,
    is_syn,
    require,
    selected_streams,
)

type Record = dict[str, typ.Any]


def http_exchange(packets: list[Record], port: int) -> Record:
    """Check one external HTTP exchange and record when its GET and reply were sent.

    Returns
    -------
    dict[str, typing.Any]
        The guest port and the times of the GET and of the reply.
    """
    source = ("10.0.2.15", port)
    dest = (HTTP_HOST, HTTP_PORT)
    syn = next(
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == source
        if (p["dst_ip"], p["dst_port"]) == dest
        if is_syn(p)
    )
    view, request, reply = selected_streams(packets, source, dest, syn["timestamp_us"])
    require(
        request.startswith(HTTP_REQUEST)
        and b"\r\nHost: www.developingnetwork.com\r\n" in request,
        HTTP_MESSAGE,
    )
    require(
        request.endswith(b"\r\n\r\n")
        and reply.startswith(b"HTTP/1.1 404 Not Found\r\n"),
        HTTP_MESSAGE,
    )
    get_when = min(
        p["timestamp_us"] for p in view if p["src_port"] == port and p["payload_hex"]
    )
    reply_when = min(
        p["timestamp_us"]
        for p in view
        if p["src_port"] == HTTP_PORT and p["payload_hex"]
    )
    return {"guest_source_port": port, "get_us": get_when, "reply_us": reply_when}


def check_http(packets: list[Record]) -> list[Record]:
    """Count complete SYN-scoped TCP exchanges, never duplicated packets.

    Returns
    -------
    list[dict[str, typing.Any]]
        One record per external HTTP exchange, in guest source-port order.
    """
    sources = {
        p["src_port"]
        for p in packets
        if p["src_ip"] == "10.0.2.15"
        if p["dst_ip"] == HTTP_HOST
        if p["dst_port"] == HTTP_PORT
        if is_syn(p)
    }
    require(len(sources) == HTTP_CONNECTIONS, "External HTTP connection count differs")
    result = [http_exchange(packets, port) for port in sorted(sources)]
    require(
        result[0]["get_us"] < AGREEMENT_US,
        "First external GET no longer precedes agreement",
    )
    return result


def check_teardown(
    client: list[Record], view: list[Record]
) -> tuple[list[Record], int, int]:
    """Check the HTTP exchanges and the control FIN that follows the final request.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], int, int]
        The HTTP exchanges, the time of the final request and the time of the FIN.
    """
    http = check_http(client)
    last_request = max(
        p["timestamp_us"]
        for p in view
        if p["src_port"] == HOST_CLIENT[1]
        and bytes.fromhex(p["payload_hex"]).startswith(
            bytes.fromhex("000000d400000004")
        )
    )
    client_fin = min(
        p["timestamp_us"]
        for p in view
        if p["src_port"] == HOST_CLIENT[1] and p["flags"] & FIN_FLAG
    )
    require(client_fin > last_request, "Missing control FIN after final request")
    return http, last_request, client_fin
