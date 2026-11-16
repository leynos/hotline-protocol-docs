"""Replay the finite B56/B57 Classic server-name field-162 evidence offline."""

import json
import typing as typ
from pathlib import Path

from pcap_tcp import read_packets
from script_cli import run
from verify_classic_native_baseline import flow, verify_a7
from verify_classic_server_name_162_b57 import check_b57
from verify_classic_server_name_162_capture import check_capture
from verify_classic_server_name_162_common import (
    AGREEMENT_ACTION,
    AGREEMENT_BYTES,
    AGREEMENT_SHA,
    CLIENT_HELLO,
    FIELDS,
    FILP_SHA,
    FORWARDED_ACK,
    PARSER_SHA,
    PCAP_HEADER_HEX,
    PCAP_VIEWS,
    PROXY_SHA,
    RAW_ACK,
    ROUTES,
    SERVER_HELLO,
    digest,
    load,
    require,
)
from verify_mac_peer_first_session import field_map, parse_frames

__all__ = [
    "AGREEMENT_SHA",
    "CLIENT_HELLO",
    "FIELDS",
    "FILP_SHA",
    "FORWARDED_ACK",
    "PARSER_SHA",
    "PROXY_SHA",
    "RAW_ACK",
    "ROUTES",
    "SERVER_HELLO",
    "check_a7",
    "check_b56",
    "check_b57",
    "check_capture",
    "check_selection",
    "check_source",
    "digest",
    "field_map",
    "flow",
    "inventory",
    "load",
    "main",
    "parse_frames",
    "read_packets",
    "require",
    "show",
    "verify",
    "verify_a7",
]


def inventory(base: Path) -> int:
    """Check every file of the corpus against its SHA256SUMS and the file set.

    Returns
    -------
    int
        The number of inventoried files.
    """
    root = base.resolve().parents[3]
    names: set[str] = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        require(
            path.is_file() and path.resolve().is_relative_to(base), "inventory path"
        )
        require(relative not in names, "duplicate inventory path")
        names.add(relative)
        require(digest(path.read_bytes()) == expected, f"SHA inventory {relative}")
    actual = {
        str(p.relative_to(root))
        for p in base.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    require(names == actual, "SHA inventory file set")
    return len(names)


def check_source(base: Path, source: dict[str, typ.Any]) -> None:
    """Check the provenance and the stored snapshots of the frozen sources."""
    for key, name, revision, expected in (
        (
            "proxy",
            "classic_login_proxy.py",
            "12b51a2d8271ffa06cd1589501f0ca1d36bb37fe",
            PROXY_SHA,
        ),
        (
            "parser",
            "pcap_tcp.py",
            "79d867dc80c0aea50ad77569aae89e1d0bf37915",
            PARSER_SHA,
        ),
    ):
        require(
            source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}"
            and source[f"{key}_revision"] == revision
            and source[f"{key}_snapshot_path"] == f"as-run/{name}.txt"
            and source[f"{key}_sha256"] == expected,
            f"{key} provenance",
        )
        require(
            digest((base / source[f"{key}_snapshot_path"]).read_bytes()) == expected,
            f"{key} source snapshot",
        )
    require(
        source["client_data_sha256"]
        == "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
        and source["client_resource_sha256"]
        == "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b"
        and source["client_vers_short"] == "1.9.1.0"
        and source["vendor_authenticity"] == "unproved",
        "Classic client identity record",
    )


def check_a7(base: Path, label: str) -> dict[str, typ.Any]:
    """Check the two A7 replays of one run and the agreement they carry.

    Returns
    -------
    dict[str, typing.Any]
        The A7 summary of the run.
    """
    directory = base / label
    result = verify_a7(directory)
    require(
        result
        == {"actions_each": 29, "accounts": 2, "files": 41, "filp_sha256": FILP_SHA},
        f"{label} A7 fixture",
    )
    for name in ("a7-preflight", "a7-postflight"):
        report = load(directory / name / "report.json")
        agreement = next(f for f in report["frames"] if f["action"] == AGREEMENT_ACTION)
        data = bytes.fromhex(agreement["fields"][0]["hex"])
        require(
            len(data) == AGREEMENT_BYTES and digest(data) == AGREEMENT_SHA,
            f"{label} agreement",
        )
    return result


def check_b56(base: Path) -> dict[str, typ.Any]:
    """Check the B56 run, which must stop before any connection to the peer.

    Returns
    -------
    dict[str, typing.Any]
        The outcome and the namespace packet count of the run.
    """
    directory = base / "b56"
    terminal = load(directory / "terminal.json")
    require(
        terminal["outcome"] == "infrastructure-stop-before-connect"
        and terminal["client_connect_activated"] is False
        and terminal["proxy_ready"] is False,
        "B56 failure label",
    )
    require(
        (directory / "namespace.pcap").read_bytes() == bytes.fromhex(PCAP_HEADER_HEX),
        "B56 namespace zero-contact capture",
    )
    pre = (directory / "client-guest-pre.pcap").read_bytes()
    post = (directory / "client-guest-post.pcap").read_bytes()
    require(
        pre == post
        and digest(pre)
        == terminal["client_guest_pre_sha256"]
        == terminal["client_guest_post_sha256"],
        "B56 client guest no contact",
    )
    journal = (directory / "proxy-journal.txt").read_text()
    require(
        "FileExistsError" in journal and "classic-proxy-b56.service" in journal,
        "B56 output leaf failure",
    )
    units = (directory / "units-terminal.txt").read_text()
    require(
        "Id=mothra-classic-proxy-b56.service\nActiveState=failed\nMainPID=0\nResult=exit-code"
        in units
        and "15652" not in (directory / "listeners-terminal.txt").read_text(),
        "B56 failed setup cleanup",
    )
    return {"outcome": "infrastructure-stop-before-connect", "namespace_packets": 0}


def check_selection(
    base: Path,
    selection: dict[str, typ.Any],
    packets: dict[str, list[dict[str, typ.Any]]],
) -> None:
    """Check each selected PCAP view and the SYN lifetime of each route in it."""
    for name, spec in selection.items():
        chosen = base / "pcaps" / name
        require(
            chosen.stat().st_size == spec["selected_bytes"]
            and digest(chosen.read_bytes()) == spec["selected_sha256"]
            and len(packets["pcaps/" + name]) == len(spec["selected_record_indexes"]),
            f"selected PCAP identity {name}",
        )
        for route in spec["routes"]:
            src, port, dst, target = route["route"]
            selected = [
                p
                for p in packets["pcaps/" + name]
                if (p["src_ip"], p["src_port"], p["dst_ip"], p["dst_port"])
                in {(src, port, dst, target), (dst, target, src, port)}
            ]
            syns = [
                p
                for p in selected
                if p["src_ip"] == src
                and p["src_port"] == port
                and p["flags"] & 2
                and not p["flags"] & 16
            ]
            require(
                len(selected) == route["packet_count"]
                and len(syns) == 1
                and [p["flags"] for p in selected if p["flags"] & 5]
                == route["terminal_flags"]
                and bool(route["terminal_flags"]),
                f"selected SYN lifetime/tails {name}",
            )


def verify(base: Path) -> dict[str, typ.Any]:
    """Replay the retained B56 and B57 runs under ``base``.

    Returns
    -------
    dict[str, typing.Any]
        The inventory count and the verified summary of each run.
    """
    base = base.resolve()
    count = inventory(base)
    manifest = load(base / "manifest.json")
    require(manifest["schema_version"] == 1, "manifest schema")
    require(
        manifest["b56"]["outcome"] == "infrastructure-stop-before-connect"
        and manifest["b57"]["outcome"] == "intentional-observation-cutoff",
        "run outcomes",
    )
    require(
        bytes.fromhex(manifest["original_ack_hex"]) == RAW_ACK, "original ACK manifest"
    )
    check_source(base, manifest["source"])
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    require(len(packets) == PCAP_VIEWS, "four selected PCAP views")
    check_selection(base, manifest["selection"], packets)
    return {
        "inventory_files": count,
        "b56": {
            **check_b56(base),
            "a7": check_a7(base, "b56"),
            "capture": check_capture(base, "b56", manifest),
        },
        "b57": {
            **check_b57(base, manifest, packets),
            "a7": check_a7(base, "b57"),
            "capture": check_capture(base, "b57", manifest),
        },
    }


def show(corpus: str) -> None:
    """Replay the corpus at ``corpus`` and print its summary as JSON."""
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Replay the corpus named on the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
