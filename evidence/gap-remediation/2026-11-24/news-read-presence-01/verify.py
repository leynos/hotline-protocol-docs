"""Replay nine native article reads from the driver, namespace and guest records."""

import datetime as dt
import hashlib
import json
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, verify_capture
from protocol_capture_decode import decode_frame

ROOT = Path(__file__).resolve().parent
COMMIT = "0aa767791555fc2c590a2e9a46ffa68c80967301"
FIXTURE = "afdc1845d8e15d053330db97710bd84a4864dd1d391d3f3fc46de95ed01eb4ef"
RESOURCE = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
ENCODINGS = {"absent": None, "empty": "", "zero": "00000000"}
CASES = {f"{field}-{shape}" for field in (326, 334, 337) for shape in ENCODINGS}


def read(path):
    return json.loads((ROOT / path).read_bytes())


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def check_read(case, report, plan, reference):
    field, shape = case.split("-")
    field = int(field)
    expected = [(f["id"], f["hex"]) for f in reference["fields"]]
    if field == 326:
        expected = [(k, v) for k, v in expected if k != 326]
    if ENCODINGS[shape] is not None:
        expected.insert(1 if field == 326 else len(expected), (field, ENCODINGS[shape]))
    events = report["events"]
    requests = {e["action"]: e["hex"] for e in events if e["event"] == "send"}
    require(list(requests) == [1, 3, 7, 9], "request actions")
    require(
        all(plan["steps"][i]["hex"] == h for i, h in requests.items()), "planned bytes"
    )
    req = decode_frame(bytes.fromhex(requests[7]))
    require((req["type"], req["id"], req["is_reply"]) == (400, 10, 0), "read header")
    require(
        not req["unconsumed_hex"]
        and [(f["id"], f["hex"]) for f in req["fields"]] == expected,
        "read fields",
    )
    for r in report["frames"]:
        wire = bytes.fromhex(
            "".join(
                e["hex"]
                for e in events
                if e["event"] == "receive" and e["action"] == r["action"]
            )
        )
        decoded = decode_frame(wire)
        require(all(r[k] == v for k, v in decoded.items()), "reply decode")
    require(
        [(r["type"], r["id"], r["action"]) for r in report["frames"]]
        == [(0, 1, 4), (354, 1, 5), (109, 2, 6), (0, 10, 8), (0, 90, 10)],
        "session sequence",
    )
    login, _, _, reply, barrier = report["frames"]
    require(login["is_reply"] == 1 and login["error"] == 0, "administrator login")
    require(reply["is_reply"] == 1 and not reply["unconsumed_hex"], "read reply")
    require(
        barrier["is_reply"] == 1 and barrier["error"] == 0 and not barrier["fields"],
        "liveness",
    )
    require(
        [(e["action"], e["event"]) for e in events[-2:]]
        == [(11, "quiet"), (12, "close")],
        "quiet and close",
    )
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in reply["fields"]}
    if field == 326:
        require(
            reply["error"] == 1
            and values
            == {
                100: b"Cannot get article data because an invalid category was specified."
            },
            "article error",
        )
    else:
        require(
            reply["error"] == 0
            and values[328] == b"First root"
            and values[327] == b"text/plain"
            and values[333] == b"first-body\r\n\0\xff",
            "article body",
        )
    return reply["payload_hex"]


def replay():
    manifest = read("manifest.json")
    env = read("environment.json")
    require(
        manifest["planner_commit"] == COMMIT
        and set(manifest["cases"])
        == CASES
        == {p.name for p in (ROOT / "captures").iterdir()},
        "case inventory",
    )
    require(
        manifest["installed_forks"]
        == {
            "native-app-4352-0": ORACLE_SHA256,
            "native-app-4353-1": RESOURCE,
            "native-category-4352-0": FIXTURE,
        },
        "installed forks",
    )
    require(
        env["server_fork_hashes"]
        == {"HLserver19": ORACLE_SHA256, ".rsrc/HLserver19": RESOURCE}
        and env["article_category_sha256"] == FIXTURE,
        "runtime identity",
    )
    require(
        manifest["disk_fuser_exit"] == 1
        and manifest["disk_fuser_output_bytes"] == 0
        and list(manifest["retired_services"].values()) == ["inactive"] * 4,
        "retirement",
    )
    require(
        [a["ifname"] for a in read("ns-addr.json")] == ["lo"]
        and read("ns-route.json") == [],
        "isolated namespace",
    )
    require(
        not read_packets(ROOT / "host.pcap")
        and (ROOT / "host.pcap").stat().st_size == 24,
        "host control",
    )
    require(
        manifest["network_statistics"]
        == {
            "host": {"captured": 0, "dropped": 0},
            "ns": {"captured": 184, "dropped": 0},
        },
        "recorder counts",
    )
    packets = [read_packets(ROOT / f) for f in ("namespace.pcap", "guest.pcap")]
    gates = {k: v["receipt"] for k, v in read("readiness.json").items()}
    comparison = {
        r["case"]: r
        for r in map(
            json.loads, (ROOT / "stream-comparison.jsonl").read_text().splitlines()
        )
    }
    require(set(comparison) == CASES, "comparison inventory")
    reference_steps = read("captures/334-absent/plan.json")["steps"]
    ref = decode_frame(bytes.fromhex(reference_steps[7]["hex"]))
    require(
        [v["id"] for v in ref["fields"]] == [325, 326, 327]
        and ref["fields"][1]["hex"] == "00000001"
        and ref["fields"][2]["hex"] == b"text/plain".hex(),
        "listed reference",
    )
    payloads = {}
    for case in sorted(CASES):
        folder = ROOT / "captures" / case
        verify_capture(folder)
        report, plan = (read(folder / p) for p in ("report.json", "plan.json"))
        require(
            report["status"] == "completed"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_identity"]["commit"] == COMMIT
            and not report["driver_identity"]["dirty"],
            "driver identity",
        )
        require(
            plan["environment"] == env
            and plan["gap_ids"] == ["GAP-016"]
            and plan["steps"][:7] + plan["steps"][8:]
            == reference_steps[:7] + reference_steps[8:],
            "fixed actions",
        )
        payloads[case] = check_read(case, report, plan, ref)
        (connect,) = [e for e in report["events"] if e["event"] == "connect"]
        client, server = tuple(connect["local_address"]), tuple(connect["peer_address"])
        require(
            client[0] == "127.0.0.1" and server == ("127.0.0.1", 16140), "endpoints"
        )
        when = int(
            dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1e6
            + connect["elapsed_ns"] / 1000
        )
        both = report["streams"]["main"]
        for label, pkts, src, dst in (
            ("loopback", packets[0], client, server),
            ("guest", packets[1], ("10.0.2.2", client[1]), ("10.0.2.15", 5500)),
        ):
            tcp = lifetime(pkts, src, dst, when)
            for event, key, start, end in (
                ("send", "sent_hex", src, dst),
                ("receive", "received_hex", dst, src),
            ):
                raw = stream(tcp, start, end)
                require(
                    raw.hex()
                    == both[key]
                    == "".join(
                        e["hex"] for e in report["events"] if e["event"] == event
                    ),
                    "wire stream",
                )
            v = comparison[case]["views"][label]
            require(
                v
                == {
                    "received_bytes": len(raw),
                    "received_sha256": hashlib.sha256(raw).hexdigest(),
                    "unread_hex": "",
                }
                and len(raw) == comparison[case]["consumed"],
                "stream comparison",
            )
    for case in CASES | {"postflight"}:
        for scope in ("host", "namespace", "guest"):
            original = gates[f"{scope}-ready.json"]
            gate = gates[f"{case}-{scope}-gate.json"]
            require(
                all(
                    original[k] == gate[k]
                    for k in ("pid", "start_ticks", "netns_inode", "deadline_utc")
                ),
                "readiness identity",
            )
    require(
        len({p for c, p in payloads.items() if c.startswith("326-")}) == 1
        and len({p for c, p in payloads.items() if not c.startswith("326-")}) == 1,
        "complete payload agreement",
    )
    print("Verified nine native article reads at both packet boundaries")


if __name__ == "__main__":
    replay()
