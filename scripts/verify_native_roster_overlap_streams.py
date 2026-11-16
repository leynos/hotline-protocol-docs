"""Check the TCP streams and the SYN scope of the four lifetimes of the overlap."""

import typing as typ

from verify_native_roster_overlap_common import need, read

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path
    from types import ModuleType

type Endpoint = tuple[str, int]
type Pair = tuple[Endpoint, Endpoint]
type Direction = tuple[str, Pair, Pair, str]
type Packets = list[dict[str, typ.Any]]
type Captures = tuple[ModuleType, Packets, Packets]

# The TCP flag bits that the SYN and close checks read.
TCP_FIN = 1
TCP_SYN = 2
TCP_RST = 4
TCP_ACK = 16
# The primary bridge ports, which the namespace capture must never contact.
PRIMARY_PORTS = (15500, 15501)
# The server ports of the namespace and guest sides of each stream.
NAMESPACE_SERVER_PORT = 15820
GUEST_SERVER_PORT = 5500
# The FIN packets that a closed stream carries on each side.
CLOSE_FIN_COUNT = 2
# The four lifetimes: the folder, the stream label and the client source port.
EXPECTED_STREAMS = (
    ("readiness", "main", 58390),
    ("results", "a", 57748),
    ("results", "b", 57750),
    ("postflight", "main", 41566),
)


def _directions(port: int) -> list[Direction]:
    """Return the two directions of one lifetime and their stream endpoints.

    Parameters
    ----------
    port : int
        The client source port of the lifetime.

    Returns
    -------
    list[Direction]
        For each direction: its label, the namespace endpoints, the guest endpoints
        and the key of the observed bytes.
    """
    n_client = ("127.0.0.1", port)
    n_server = ("127.0.0.1", NAMESPACE_SERVER_PORT)
    g_client = ("10.0.2.2", port)
    g_server = ("10.0.2.15", GUEST_SERVER_PORT)
    return [
        ("sent", (n_client, n_server), (g_client, g_server), "sent_hex"),
        ("received", (n_server, n_client), (g_server, g_client), "received_hex"),
    ]


def _paired_streams(
    captures: Captures, port: int
) -> cabc.Iterator[tuple[str, bytes, bytes, str]]:
    """Yield the namespace and guest stream of each direction, one at a time.

    The streams are read lazily, one direction after the next, so a check made by
    the caller on one direction runs before the next direction is read.

    Parameters
    ----------
    captures : tuple[types.ModuleType, list, list]
        The frozen TCP module, the namespace packets and the guest packets.
    port : int
        The client source port of the lifetime.

    Yields
    ------
    tuple[str, bytes, bytes, str]
        The direction label, the namespace stream, the guest stream and the key.
    """
    tcp, namespace, guest = captures
    for label, namespace_pair, guest_pair, key in _directions(port):
        yield (
            label,
            tcp.stream(namespace, *namespace_pair),
            tcp.stream(guest, *guest_pair),
            key,
        )


def _check_paired(
    captures: Captures, lifetime: str, observed: dict[str, typ.Any], port: int
) -> None:
    """Check that both captures carry the observed bytes in each direction.

    Parameters
    ----------
    captures : tuple[types.ModuleType, list, list]
        The frozen TCP module, the namespace packets and the guest packets.
    lifetime : str
        The name of the lifetime, the folder and the label, for the message.
    observed : dict[str, typing.Any]
        The stream record of the lifetime, with the sent and received bytes.
    port : int
        The client source port of the lifetime.
    """
    for label, namespace_stream, guest_stream, key in _paired_streams(captures, port):
        need(
            namespace_stream == guest_stream == bytes.fromhex(observed[key]),
            f"{lifetime} {label} paired bytes or tails differ",
        )


def _check_closes(captures: Captures, lifetime: str, port: int) -> None:
    """Check that each capture closes the lifetime with two FINs and a final ACK.

    Parameters
    ----------
    captures : tuple[types.ModuleType, list, list]
        The frozen TCP module, the namespace packets and the guest packets.
    lifetime : str
        The name of the lifetime, for the message.
    port : int
        The client source port of the lifetime.
    """
    _, namespace, guest = captures
    for name, packets in (("namespace", namespace), ("guest", guest)):
        selected = [
            p
            for p in packets
            if any(p[key] == port for key in ("src_port", "dst_port"))
        ]
        need(
            len([p for p in selected if p["flags"] & TCP_FIN]) == CLOSE_FIN_COUNT
            and not any(p["flags"] & TCP_RST for p in selected)
            and selected[-1]["flags"] & TCP_ACK,
            f"{lifetime} {name} TCP close or tail differs",
        )


def _check_lifetimes(raw: Path, report: dict[str, typ.Any], captures: Captures) -> None:
    """Check the paired bytes and the close of each of the four lifetimes.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    report : dict[str, typing.Any]
        The parsed ``results/report.json``, which holds the results lifetimes.
    captures : tuple[types.ModuleType, list, list]
        The frozen TCP module, the namespace packets and the guest packets.
    """
    for folder, label, port in EXPECTED_STREAMS:
        source = report if folder == "results" else read(raw / folder / "report.json")
        observed = source["streams"][label]
        lifetime = f"{folder}/{label}"
        _check_paired(captures, lifetime, observed, port)
        _check_closes(captures, lifetime, port)


def _check_namespace(namespace: list[dict[str, typ.Any]]) -> None:
    """Check the SYN scope of the namespace capture and its primary bridge contact.

    Parameters
    ----------
    namespace : list[dict[str, typing.Any]]
        The packets of the namespace capture.
    """
    syn_ports = [
        p["src_port"]
        for p in namespace
        if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK
    ]
    need(
        syn_ports == [port for _, _, port in EXPECTED_STREAMS],
        "Four SYN-scoped lifetimes differ",
    )
    need(
        all(
            p["src_port"] not in PRIMARY_PORTS and p["dst_port"] not in PRIMARY_PORTS
            for p in namespace
        ),
        "Namespace capture contacted primary bridge",
    )


def _check_guest(guest: list[dict[str, typ.Any]]) -> None:
    """Check that the guest capture has SYNs only for the four lifetimes.

    Parameters
    ----------
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.
    """
    need(
        {
            p["src_port"]
            for p in guest
            if p["flags"] & TCP_SYN and not p["flags"] & TCP_ACK
        }
        == {port for _, _, port in EXPECTED_STREAMS},
        "Guest SYN scope has another connection",
    )


def streams(
    corpus: Path, modules: tuple[ModuleType, ...], report: dict[str, typ.Any]
) -> None:
    """Check the TCP streams and the SYN scope of the overlap captures.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[types.ModuleType, ...]
        The frozen modules from :func:`verify_native_roster_overlap_common.frozen`.
    report : dict[str, typing.Any]
        The parsed ``results/report.json``.
    """
    raw = corpus / "raw"
    _, _, _, tcp = modules[0], modules[1], modules[3], modules[4]
    host = tcp.read_packets(raw / "primary-syn.pcap")
    namespace = tcp.read_packets(raw / "lab-namespace.pcap")
    guest = tcp.read_packets(raw / "lab-guest.pcap")
    need(not host, "Primary ports received a SYN")
    _check_namespace(namespace)
    _check_lifetimes(raw, report, (tcp, namespace, guest))
    _check_guest(guest)
