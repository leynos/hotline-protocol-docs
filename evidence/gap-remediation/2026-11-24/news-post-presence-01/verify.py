"""Reconcile isolated news post sessions, their listings and article body reads."""

import datetime as dt
import hashlib
import json
import typing as typ
from pathlib import Path

from native_news_decode import articles
from pcap_reader import Packet
from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, verify_capture
from protocol_capture_decode import decode_frame
from verify_native_news_catalogue import check_cached_list

type Record = dict[str, typ.Any]

ROOT = Path(__file__).resolve().parent
SHAPES = {"absent": None, "empty": "", "zero": "00000000"}
TARGETS = (326, 334, 337)
# Chronological order on the initially empty fixture, recorded separately
# from the public IDs assigned by the server.
ORDER = (
    "334-zero",
    "326-absent",
    "326-empty",
    "326-zero",
    "334-absent",
    "334-empty",
    "337-absent",
    "337-empty",
    "337-zero",
)
BASE_FORK = "fe1154b4561e932c29ac7dab45d9e9a0dad7b6e8083c7e77efa0f3da1b8252f6"
PLANNER_COMMIT = "66c2831fb4b6f4e086eadb49c9e674c649cea63b"


def require(condition: bool, reason: str) -> None:
    """Raise ValueError when an evidence invariant fails."""
    if not condition:
        raise ValueError(reason)


def load(path: str | Path) -> Record:
    """Load a JSON record relative to the retained corpus."""
    return json.loads((ROOT / path).read_bytes())


def fields(frame: Record) -> dict[int, bytes]:
    """Index complete fields by their unique wire identifiers."""
    values = {v["id"]: bytes.fromhex(v["hex"]) for v in frame["fields"]}
    require(
        len(values) == frame["declared_field_count"] == len(frame["fields"])
        and not frame["unconsumed_hex"],
        "field boundaries",
    )
    return values


def from_wire(events: list[Record], action: int, kind: str) -> Record:
    """Decode one action from the retained wire event fragments."""
    chunks = [e for e in events if e["action"] == action]
    require(
        bool(chunks)
        and all(e["connection"] == "main" and e["event"] == kind for e in chunks),
        "action boundary",
    )
    return decode_frame(bytes.fromhex("".join(e["hex"] for e in chunks)))


def pair(
    events: list[Record], action: int, transaction: int
) -> tuple[dict[int, bytes], Record]:
    """Decode and correlate a request and its reply."""
    req = from_wire(events, action, "send")
    res = from_wire(events, action + 1, "receive")
    require(
        req["type"] == transaction
        and not req["is_reply"]
        and res["type"] == 0
        and res["id"] == req["id"]
        and res["is_reply"],
        "correlated reply",
    )
    return fields(req), res


def check_session(case: str, views: list[list[Packet]], record: Record) -> list[Record]:
    """Verify the driver record against both captured TCP streams."""
    folder = ROOT / "captures" / case
    verify_capture(folder)
    p, r = (load(folder / name) for name in ("plan.json", "report.json"))
    ident = r["driver_identity"]
    require(
        r["status"] == "completed"
        and ident["commit"] == PLANNER_COMMIT
        and not ident["dirty"]
        and r["oracle_sha256"] == ORACLE_SHA256,
        "capture identity",
    )
    require(
        p["environment"] == load("environment.json") and p["gap_ids"] == ["GAP-016"],
        "case environment",
    )
    events = r["events"]
    for e in events:
        if e["event"] == "send":
            require(e["hex"] == p["steps"][e["action"]]["hex"], "planned send")
    (connect,) = [e for e in events if e["event"] == "connect"]
    source, dest = tuple(connect["local_address"]), tuple(connect["peer_address"])
    require(
        source[0] == "127.0.0.1" and dest == ("127.0.0.1", 16140), "isolated forward"
    )
    timestamp = int(
        dt.datetime.fromisoformat(r["started_at_utc"]).timestamp() * 1e6
        + connect["elapsed_ns"] / 1000
    )
    for label, packets, src, dst in (
        ("loopback", views[0], source, dest),
        ("guest", views[1], ("10.0.2.2", source[1]), ("10.0.2.15", 5500)),
    ):
        flow = lifetime(packets, src, dst, timestamp)
        for kind, key, a, b in (
            ("send", "sent_hex", src, dst),
            ("receive", "received_hex", dst, src),
        ):
            raw = stream(flow, a, b)
            require(
                raw.hex()
                == r["streams"]["main"][key]
                == "".join(e["hex"] for e in events if e["event"] == kind),
                "TCP stream",
            )
        require(
            record["consumed"] == len(raw)
            and record["views"][label]
            == {
                "received_bytes": len(raw),
                "received_sha256": hashlib.sha256(raw).hexdigest(),
                "unread_hex": "",
            },
            "wire comparison",
        )
    for f in r["frames"]:
        decoded = from_wire(events, f["action"], "receive")
        require(all(f[k] == v for k, v in decoded.items()), "reported frame bytes")
    require([e["event"] for e in events[-2:]] == ["quiet", "close"], "quiet interval")
    _, login = pair(events, 3, 107)
    require(login["error"] == 0, "native login")
    _, barrier = pair(events, 9 if case.startswith("body-") else 13, 500)
    require(barrier["error"] == 0 and not fields(barrier), "liveness")
    return events


def listing(events: list[Record], action: int) -> tuple[bytes, bytes, list[dict]]:
    """Return the category path, encoded listing and decoded rows."""
    req, res = pair(events, action, 371)
    fs = fields(res)
    require(res["error"] == 0 and set(fs) == {321}, "list payload")
    return req[325], fs[321], articles(fs[321])


def replay() -> None:
    """Reconcile the posting and read sessions with the stopped category."""
    m = load("manifest.json")
    env = load("environment.json")
    require(
        m["planner_commit"] == PLANNER_COMMIT
        and env["article_category_sha256"] == BASE_FORK
        and env["server_fork_hashes"]["HLserver19"] == ORACLE_SHA256,
        "fixture identity",
    )
    require(
        m["installed_forks"]["native-app-4352-0"] == ORACLE_SHA256
        and m["installed_forks"]["native-app-4353-1"]
        == env["server_fork_hashes"][".rsrc/HLserver19"]
        == "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
        "installed application",
    )
    require(
        m["disk_fuser_exit"] == 1
        and m["disk_fuser_output_bytes"] == 0
        and list(m["retired_services"].values()) == ["inactive"] * 4,
        "retirement",
    )
    require(
        not read_packets(ROOT / "host.pcap")
        and (ROOT / "host.pcap").stat().st_size == 24
        and m["network_statistics"]["host"] == {"captured": 0, "dropped": 0}
        and m["network_statistics"]["ns"]["dropped"] == 0,
        "host boundary",
    )
    require(
        load("ns-route.json") == []
        and [i["ifname"] for i in load("ns-addr.json")] == ["lo"],
        "isolated namespace",
    )
    cases = {f"{f}-{s}" for f in TARGETS for s in SHAPES}
    require(cases == set(ORDER), "comparison inventory")
    wire = {
        r["case"]: r
        for r in map(
            json.loads, (ROOT / "stream-comparison.jsonl").read_text().splitlines()
        )
    }
    require(
        set(wire) == set(m["cases"]) == {p.name for p in (ROOT / "captures").iterdir()},
        "capture inventory",
    )
    gate = {k: v["receipt"] for k, v in load("readiness.json").items()}
    for c in {*wire, "postflight"}:
        for where in ("host", "namespace", "guest"):
            before = gate[f"{where}-ready.json"]
            after = gate[f"{c}-{where}-gate.json"]
            require(
                all(
                    before[k] == after[k]
                    for k in ("pid", "start_ticks", "netns_inode", "deadline_utc")
                ),
                "readiness identity",
            )
    views = [read_packets(ROOT / p) for p in ("namespace.pcap", "guest.pcap")]
    previous = bytes(10)
    historical = load("reference-post.json")
    require(
        historical["path"]
        == "evidence/gap-remediation/2026-11-13/native-news-01/posts/plan.json"
        and historical["action"] == 11
        and historical["sha256"]
        == "f4d34fd133734629e2b0aa6862a3ec8895ac7997a531d20da386ee7a76cd294f"
        and hashlib.sha256(bytes.fromhex(historical["request_hex"])).hexdigest()
        == "2d3a823e5ef0fec81da98192af628d76eebdac2046659a73b7e5f8ce8362830c",
        "historical post control",
    )
    expected_inventory = set(cases)
    for case in ORDER:
        events = check_session(case, views, wire[case])
        path, prior, old = listing(events, 7)
        require(previous == prior, "continuity between postings")
        req, ack = pair(events, 9, 410)
        target, shape = case.split("-")
        field = int(target)
        matches = from_wire(events, 9, "send")
        control = decode_frame(bytes.fromhex(historical["request_hex"]))
        require(
            matches["id"] == control["id"]
            and [v for v in matches["fields"] if v["id"] != field]
            == [v for v in control["fields"] if v["id"] != field],
            "fixed post fields",
        )
        require(
            [v["hex"] for v in matches["fields"] if v["id"] == field]
            == ([] if SHAPES[shape] is None else [SHAPES[shape]]),
            "post encoding",
        )
        after_path, previous, new = listing(events, 11)
        require(path == after_path == req[325], "category path")
        old_ids = {v["id"] for v in old}
        added = [v for v in new if v["id"] not in old_ids]
        require(
            [v for v in new if v["id"] in old_ids] == old, "existing rows preserved"
        )
        require(
            ack["error"] == 0 and not fields(ack) and len(added) == 1,
            "one accepted post",
        )
        (row,) = added
        require(
            row["id"] > 0
            and row["parent"] == 0
            and row["flags"] == 0
            and row["title"] == req[328]
            and row["flavours"] == [(req[327], len(req[333]))],
            "new listed root",
        )
        body = "body-" + case
        expected_inventory.add(body)
        body_events = check_session(body, views, wire[body])
        reader, res = pair(body_events, 7, 400)
        values = fields(res)
        require(
            reader[325] == path
            and int.from_bytes(reader[326], "big") == row["id"]
            and reader[327] == req[327],
            "read listed ID",
        )
        require(
            res["error"] == 0
            and values[330] == row["date"]
            and values[328] == row["title"]
            and values[327] == req[327]
            and values[333] == req[333],
            "posted body readback",
        )
    require(set(wire) == expected_inventory, "paired body inventory")
    category = (ROOT / "final-category.data").read_bytes()
    require(
        hashlib.sha256(category).hexdigest()
        == m["installed_forks"]["native-category-4352-0"],
        "stopped category data fork",
    )
    check_cached_list(category, {0: previous}, 0)
    print(
        "Verified nine native root posts and their article body reads at both packet boundaries"
    )


if __name__ == "__main__":
    replay()
