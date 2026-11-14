"""Replay the finite B46/B47 Classic-to-native proxy baseline evidence."""

import argparse
import hashlib
import json
from pathlib import Path

from native_filp import decode as decode_filp
from pcap_tcp import lifetime, read_packets, stream
from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames

FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
DATA_SHA = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
RSRC_SHA = "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5"
PROXY_SHA = "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
STATIC_ACTIONS = (4, 5, 6, 8, 10, 12, 16, 23, 27)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_source_snapshot(base: Path, source: dict, key: str) -> None:
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


def ordered_frames(frames: list[dict]) -> list[tuple[int, int, int, int, int]]:
    return [(f["flags"], f["is_reply"], f["type"], f["id"], f["error"]) for f in frames]


def verify_control(case: str, client: bytes, server: bytes) -> dict:
    require(client[:12] == bytes.fromhex("54525450484f544c00010002"), "Client hello")
    require(server[:8] == bytes.fromhex("5452545000000000"), "Server hello")
    requests = parse_frames(client[12:])
    replies = parse_frames(server[8:])
    expected_requests = [(0, 0, 107, 1, 0)]
    expected_replies = [(0, 1, 0, 1, 0), (0, 0, 109, 1, 0)]
    if case == "b47":
        expected_requests += [(0, 0, 121, 2, 0), (0, 0, 300, 3, 0), (0, 0, 212, 4, 0)]
        expected_replies += [
            (0, 1, 0, 2, 0),
            (0, 0, 354, 2, 0),
            (0, 0, 122, 3, 0),
            (0, 1, 0, 3, 0),
            (0, 1, 0, 4, 0),
        ]
    require(ordered_frames(requests) == expected_requests, "Request sequence")
    require(ordered_frames(replies) == expected_replies, "Reply sequence")
    require(
        field_map(replies[0]) == {160: b"\x00\xbe", 161: b"\0\0"}, "Login ACK fields"
    )
    agreement = field_map(replies[1])
    require(agreement == {101: AGREEMENT}, "Agreement text")
    require(
        len(AGREEMENT) == 242 and digest(AGREEMENT) == AGREEMENT_SHA,
        "Agreement identity",
    )
    if case == "b47":
        require(field_map(requests[1])[102] == b"unnamed", "121 display name")
        require(
            field_map(requests[2]) == {} and field_map(requests[3]) == {},
            "Automatic requests",
        )
        require(
            field_map(replies[5])
            == {300: bytes.fromhex("003c019e00120007756e6e616d6564")},
            "Roster record",
        )
        require(
            field_map(replies[6])[107] == bytes.fromhex("003f7729"), "Banner reference"
        )
    return {
        "request_types": [f["type"] for f in requests],
        "reply_types": [f["type"] for f in replies],
    }


def verify_watchdog(report: dict) -> dict:
    observation = report["observation"]
    require(report["status"] == "intentional-observation-cutoff", "Proxy outcome")
    require(
        observation["state"] == "fired" and observation["valid_30_seconds"] is True,
        "Watchdog receipt",
    )
    start = observation["ack_sent_monotonic_ns"]
    finish = observation["relay_teardown_ns"]
    cutoff = observation["cutoff_actual_ns"]
    due = observation["cutoff_due_ns"]
    require(due - start == 28_000_000_000, "Watchdog target")
    require(
        start <= due <= cutoff <= finish < start + 30_000_000_000, "Watchdog teardown"
    )
    require(not report["errors"] and observation["error"] is None, "Proxy errors")
    require(
        observation["raw_ack_sha256"] == observation["forwarded_ack_sha256"],
        "ACK rewrite",
    )
    return {"teardown_seconds": (finish - start) / 1e9, "status": report["status"]}


def verify_proxy_log(
    case: str,
    report: dict,
    client: bytes,
    server: bytes,
    data: tuple[bytes, bytes] | None,
) -> None:
    entries = report["entries"]

    def logged(event: str) -> bytes:
        return b"".join(
            bytes.fromhex(e["raw_hex"]) for e in entries if e["event"] == event
        )

    require(
        all(e.get("raw_hex") == e.get("forwarded_hex") for e in entries),
        "Proxy altered baseline bytes",
    )
    control_client = (
        logged("client-handshake") + logged("login-request") + logged("client")
    )
    control_server = logged("server-handshake") + logged("server")
    require(
        control_client == client and control_server == server, "Proxy log/wire mismatch"
    )
    if case == "b46":
        expected = [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
        ]
        require([e["event"] for e in entries] == expected, "B46 must stop before 121")
    else:
        if data is None:
            raise ValueError("Missing B47 data")
        require(
            sum(e["event"] == "data-client" for e in entries) == 1
            and sum(e["event"] == "data-server" for e in entries) == 1,
            "Banner attachment",
        )
        require(logged("data-client") == data[0], "Data client log")
        require(logged("data-server") == data[1], "Data server log")
    raw = bytes.fromhex(entries[3]["raw_hex"])
    require(
        raw == server[8 : 8 + len(raw)]
        and digest(raw) == report["observation"]["raw_ack_sha256"],
        "ACK receipt mismatch",
    )


def verify_a7(directory: Path) -> dict:
    pre = json.loads((directory / "a7-preflight/report.json").read_text())
    post = json.loads((directory / "a7-postflight/report.json").read_text())
    require(
        all(
            x["status"] == "completed" and x["completed_actions"] == 29
            for x in (pre, post)
        ),
        "A7 action completion",
    )
    require(
        pre["oracle_sha256"]
        == post["oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "Native oracle identity",
    )
    for r in (pre, post):
        frames = {f["action"]: f for f in r["frames"]}
        filp = bytes.fromhex(r["streams"]["download"]["received_hex"])
        require(
            len(frames[8]["fields"]) == 2 and len(frames[10]["fields"]) == 41,
            "A7 accounts/Files",
        )
        require(
            len(filp) == 1_049_073 and digest(filp) == FILP_SHA,
            "Full FILP incl both forks",
        )
        forks = decode_filp(filp)
        require(digest(forks["DATA"]) == DATA_SHA, "A7 data fork")
        require(digest(forks["MACR"]) == RSRC_SHA, "A7 resource fork")
        require(
            digest(bytes.fromhex(frames[6]["fields"][0]["hex"])) == AGREEMENT_SHA,
            "A7 agreement",
        )
    pf = {f["action"]: f for f in pre["frames"]}
    qf = {f["action"]: f for f in post["frames"]}
    require(all(pf[i] == qf[i] for i in STATIC_ACTIONS), "A7 static frame drift")
    return {"actions_each": 29, "accounts": 2, "files": 41, "filp_sha256": FILP_SHA}


def flow(packets: list[dict], route: list) -> tuple[bytes, bytes]:
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
    require(len(pairs) == 5, "Five capture views required")
    require(
        len({pair[0] for pair in pairs}) == len({pair[1] for pair in pairs}) == 1,
        "Capture view byte mismatch",
    )
    client, server = pairs[0]
    require([len(client), len(server)] == expected, "Stream length differs")
    return client, server


def verify_views(
    routes: list, expected: list[int], packets: dict
) -> tuple[bytes, bytes]:
    return equal_pairs([flow(packets[route[0]], route) for route in routes], expected)


def verify_case(base: Path, case: str, spec: dict) -> dict:
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
        require(data[0][:4] == b"HTXF" and len(data[0]) == 16, "Data request header")
        require(data[0][4:8] == bytes.fromhex("003f7729"), "Dynamic banner reference")
        require(data[1][:6] == b"GIF89a" and len(data[1]) == 58, "Banner data bytes")
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


def verify(base: Path) -> dict:
    manifest = json.loads((base / "manifest.json").read_text())
    require(manifest["schema_version"] == 1, "Manifest schema")
    source = manifest["source"]
    require(source["proxy_sha256"] == PROXY_SHA, "As-run proxy source")
    for key in ("proxy", "parser"):
        check_source_snapshot(base, source, key)
    require(manifest["runtime"]["client_netns_inode"] == 4026532479, "Client namespace")
    return {
        case: verify_case(base, case, manifest["runs"][case]) for case in ("b46", "b47")
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), indent=2))


if __name__ == "__main__":
    main()
