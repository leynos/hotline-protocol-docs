"""Name the constants and the shared checks of the Classic client session verifier."""

import typing as typ

from pcap_tcp import lifetime, stream

type Record = dict[str, typ.Any]

AGREEMENT = (
    b"This is the server agreement.  \r"
    b"The server owner puts any kind of conditions or conditions they want you "
    b"to agree to before entering.  \r"
    b"They can change this agreement by modifying the agreement.txt file "
    b"in the server directory.\rSay you agree!"
)
HTTP_REQUEST = b"GET /zipads/zip-hot.asp?c=82&h=69 HTTP/1.1\r\n"
CONTROL_CONNECT_US = 1794592084729501
DATA_CONNECT_US = 1794592189150000
CLIENT_CONTROL = ("10.0.2.15", 49152)
CLIENT_TARGET = ("10.0.2.2", 15500)
HOST_CLIENT = ("127.0.0.1", 59232)
HOST_SERVER = ("127.0.0.1", 15500)
SERVER_NAT = ("10.0.2.2", 59232)
SERVER_CONTROL = ("10.0.2.15", 5500)
CLIENT_DATA = ("10.0.2.15", 49155)
CLIENT_DATA_TARGET = ("10.0.2.2", 15501)
SERVER_DATA_NAT = ("10.0.2.2", 36936)
SERVER_DATA = ("10.0.2.15", 5501)

CAPTURE_NAMES = (
    "host-final.pcap",
    "client-guest-final.pcap",
    "server-guest-final.pcap",
)
FRAME_HEADER_BYTES = 20  # the control frame header, before its payload
MAX_CONTROL_PAYLOAD = 524288
SYN_FLAG = 2
ACK_FLAG = 16
FIN_FLAG = 1
HTTP_HOST = "207.148.248.143"
HTTP_PORT = 80
HTTP_CONNECTIONS = 5
HTTP_MESSAGE = "Missing or changed external HTTP exchange"
AGREEMENT_US = 1794592188965025  # the time of the agreement, after the first GET
CLIENT_TCP_CONNECTIONS = 7
CONTROL_LIFETIMES = (23, 24, 25)  # packets in the host, client and server views
CLIENT_DATA_PACKETS = 7
SERVER_DATA_PACKETS = 12
BANNER_BYTES = 58
DATA_MESSAGE = "Missing or changed 15501 guest transfer bytes"


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # callers pass a condition positionally
    message: str,
) -> None:
    """Raise ValueError with the message unless the condition holds.

    Raises
    ------
    ValueError
        When the condition is false.
    """
    if not condition:
        raise ValueError(message)


def is_syn(packet: Record) -> bool:
    """Return whether a TCP packet opens a connection: SYN set and ACK clear.

    Returns
    -------
    bool
        True for a bare SYN.
    """
    return bool(packet["flags"] & SYN_FLAG) and not packet["flags"] & ACK_FLAG


def selected_streams(
    packets: list[Record], source: tuple[str, int], dest: tuple[str, int], near_us: int
) -> tuple[list[Record], bytes, bytes]:
    """Return one connection's packets and the bytes each side sent.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], bytes, bytes]
        The connection's packets, the initiator's bytes and the responder's bytes.
    """
    view = lifetime(packets, source, dest, near_us)
    return view, stream(view, source, dest), stream(view, dest, source)
