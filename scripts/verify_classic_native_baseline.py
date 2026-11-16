"""Replay the finite B46/B47 Classic-to-native proxy baseline evidence."""

import json
import typing as typ
from pathlib import Path

from native_filp import decode as decode_filp
from pcap_tcp import lifetime, read_packets, stream
from script_cli import run
from verify_classic_native_baseline_a7 import verify_a7
from verify_classic_native_baseline_common import (
    AGREEMENT_SHA,
    CLIENT_NETNS_INODE,
    DATA_SHA,
    FILP_SHA,
    GIF_BYTES,
    HTXF_BYTES,
    PARSER_SHA,
    PROXY_SHA,
    RSRC_SHA,
    STATIC_ACTIONS,
    VIEW_COUNT,
    digest,
    require,
)
from verify_classic_native_baseline_proxy import (
    ordered_frames,
    verify_control,
    verify_proxy_log,
    verify_watchdog,
)
from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames

__all__ = [
    "AGREEMENT",
    "AGREEMENT_SHA",
    "DATA_SHA",
    "FILP_SHA",
    "PARSER_SHA",
    "PROXY_SHA",
    "RSRC_SHA",
    "STATIC_ACTIONS",
    "check_source_snapshot",
    "decode_filp",
    "digest",
    "equal_pairs",
    "field_map",
    "flow",
    "main",
    "ordered_frames",
    "parse_frames",
    "require",
    "show",
    "verify",
    "verify_a7",
    "verify_case",
    "verify_control",
    "verify_proxy_log",
    "verify_views",
    "verify_watchdog",
]


def check_source_snapshot(base: Path, source: dict[str, typ.Any], key: str) -> None:
    """Check the provenance and the stored snapshot of one frozen source file."""
    names = {"proxy": "classic_login_proxy.py", "parser": "pcap_tcp.py"}
    require(key in names, "Unknown source snapshot")
    name = names[key]
    expected = PROXY_SHA if key == "proxy" else PARSER_SHA
    require(
        source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}"
        and source[f"{key}_revision"] == "79d867dc80c0aea50ad77569aae89e1d0bf37915"
        and source[f"{key}_snapshot_path"] == f"as-run/{name}.txt"
        and source[f"{key}_sha256"] == expected,
        f"As-run {key} provenance",
    )
    require(
        digest((base / source[f"{key}_snapshot_path"]).read_bytes()) == expected,
        f"As-run {key} snapshot",
    )


def flow(
    packets: list[dict[str, typ.Any]], route: list[typ.Any]
) -> tuple[bytes, bytes]:
    """Return both directions of the one TCP stream that a route's SYN opens.

    Returns
    -------
    tuple[bytes, bytes]
        The client-to-server stream and the server-to-client stream.
    """
    _, src_ip, src_port, dst_ip, dst_port = route
    source, target = (src_ip, src_port), (dst_ip, dst_port)
    syns = [
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == source
        and (p["dst_ip"], p["dst_port"]) == target
        and p["flags"] & 2
        and not p["flags"] & 16
    ]
    require(len(syns) == 1, "Missing or reused route SYN")
    selected = lifetime(packets, source, target, syns[0]["timestamp_us"])
    return stream(selected, source, target), stream(selected, target, source)


def equal_pairs(
    pairs: list[tuple[bytes, bytes]], expected: list[int]
) -> tuple[bytes, bytes]:
    """Require every capture view to carry the same two streams.

    Returns
    -------
    tuple[bytes, bytes]
        The client and server streams of the first view.
    """
    require(len(pairs) == VIEW_COUNT, "Five capture views required")
    require(
        len({pair[0] for pair in pairs}) == len({pair[1] for pair in pairs}) == 1,
        "Capture view byte mismatch",
    )
    client, server = pairs[0]
    require([len(client), len(server)] == expected, "Stream length differs")
    return client, server


def verify_views(
    routes: list[typ.Any],
    expected: list[int],
    packets: dict[str, list[dict[str, typ.Any]]],
) -> tuple[bytes, bytes]:
    """Check that every named route yields the same streams of the expected lengths.

    Returns
    -------
    tuple[bytes, bytes]
        The client and server streams that all the views share.
    """
    return equal_pairs([flow(packets[route[0]], route) for route in routes], expected)


def verify_case(base: Path, case: str, spec: dict[str, typ.Any]) -> dict[str, typ.Any]:
    """Replay one baseline case from its guest, namespace and host captures.

    Returns
    -------
    dict[str, typing.Any]
        The control and banner summaries, the watchdog and the A7 replays.
    """
    directory = base / case
    for side in ("client", "server"):
        before = (directory / f"{side}-guest-pre.pcap").read_bytes()
        after = (directory / f"{side}-guest-post.pcap").read_bytes()
        require(
            after.startswith(before),
            f"{side} guest snapshot is not an untrimmed append",
        )
    packets = {
        name: read_packets(directory / name)
        for name in (
            "client-guest-post.pcap",
            "server-guest-post.pcap",
            "namespace.pcap",
            "host.pcap",
        )
    }
    client, server = verify_views(
        spec["routes"]["control"], spec["control_lengths"], packets
    )
    data = None
    if case == "b47":
        data = verify_views(spec["routes"]["data"], spec["data_lengths"], packets)
        require(
            data[0][:4] == b"HTXF" and len(data[0]) == HTXF_BYTES, "Data request header"
        )
        require(data[0][4:8] == bytes.fromhex("003f7729"), "Dynamic banner reference")
        require(
            data[1][:6] == b"GIF89a" and len(data[1]) == GIF_BYTES, "Banner data bytes"
        )
    control = verify_control(case, client, server)
    report = json.loads((directory / "proxy/report.json").read_text())
    require(
        report["variant"] == "baseline"
        and report["routes"] == {"control": 15500, "data": 15501},
        "Proxy route/variant",
    )
    watchdog = verify_watchdog(report)
    verify_proxy_log(case, report, client, server, data)
    return {
        "control": control,
        "data_bytes": [len(x) for x in data] if data else None,
        "watchdog": watchdog,
        "a7": verify_a7(directory),
    }


def verify(base: Path) -> dict[str, typ.Any]:
    """Replay the retained B46 and B47 baseline cases under ``base``.

    Returns
    -------
    dict[str, typing.Any]
        The verified summary of each case, keyed by case name.
    """
    manifest = json.loads((base / "manifest.json").read_text())
    require(manifest["schema_version"] == 1, "Manifest schema")
    source = manifest["source"]
    require(source["proxy_sha256"] == PROXY_SHA, "As-run proxy source")
    for key in ("proxy", "parser"):
        check_source_snapshot(base, source, key)
    require(
        manifest["runtime"]["client_netns_inode"] == CLIENT_NETNS_INODE,
        "Client namespace",
    )
    return {
        case: verify_case(base, case, manifest["runs"][case]) for case in ("b46", "b47")
    }


def show(corpus: str) -> None:
    """Replay the baseline corpus at ``corpus`` and print its summary as JSON."""
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Replay the baseline corpus named on the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
