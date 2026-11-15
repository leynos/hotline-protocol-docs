#!/usr/bin/env python3
"""Verify account replacement, password sentinels and native record bytes."""

import argparse
import json
from datetime import datetime
from itertools import pairwise
from pathlib import Path

import native_account_update_cases as cases
from native_auth_cases import complement
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_article_deletion import measured_wait
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields, sha

LABELS = [
    "preserve",
    "absent",
    "empty",
    "literal-x",
    "replace32",
    "preserve32",
    "sparse",
    "attribute65",
]
BASE_PASSWORD = b"account-base-26"
PASSWORDS = {
    "preserve": BASE_PASSWORD,
    "absent": b"",
    "empty": b"",
    "literal-x": b"\x87",
    "replace32": b"p" * 32,
    "preserve32": b"q" * 31,
    "sparse": BASE_PASSWORD,
    "attribute65": BASE_PASSWORD,
}
ACCESS = bytes.fromhex("2000000000000000")


def username(label: str) -> bytes:
    return ("m-au26-" + label).encode()


def values(label: str, after: bool) -> tuple[bytes, bytes, bytes, bytes]:
    password = (
        PASSWORDS[label]
        if after
        else b"q" * 32
        if label == "preserve32"
        else BASE_PASSWORD
    )
    name = b"" if after and label == "sparse" else b"Account26-" + label.encode()
    attribute = (
        b""
        if after and label == "sparse"
        else b"X" * 64
        if after and label == "attribute65"
        else b"opaque26"
    )
    access = bytes(8) if after and label == "sparse" else ACCESS
    return name, attribute, password, access


def account_reply(frame: dict, label: str, after: bool) -> None:
    name, _, password, access = values(label, after)
    expected = {105: complement(username(label)), 110: access}
    if name:
        expected[102] = name
    if password:
        expected[106] = b"x"
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Account retrieval/default/placeholder differs",
    )


def account_record(label: str, after: bool) -> bytes:
    name, attribute, password, access = values(label, after)
    result = bytearray(734)
    result[:2] = b"\0\1"
    result[4:12] = access
    for offset, value in [
        (0x210, name),
        (0x254, attribute),
        (0x298, username(label)),
        (0x2BC, complement(password)),
    ]:
        result[offset : offset + 2] = len(value).to_bytes(2, "big")
        result[offset + 2 : offset + 2 + len(value)] = value
    return bytes(result)


def enumeration(frame: dict) -> list[str]:
    require(
        frame["error"] == 0 and all(f["id"] == 101 for f in frame["fields"]),
        "Account enumeration failed",
    )
    return sorted(f["hex"] for f in frame["fields"])


def storage(directory: Path) -> None:
    catalogues = {}
    for phase, after, count in [("native-seed", False, 17), ("native-final", True, 18)]:
        base = directory / phase
        rows = json.loads((base / "extraction.json").read_text())["records"]
        require(
            len(rows) == count and len({r["catalog"] for r in rows}) == count,
            "Account positive catalogue inventory differs",
        )
        catalogues[phase] = {r["catalog"]: r for r in rows}
        expected_paths = {
            "/Hotline19/Users/" + username(label).decode() + suffix
            for label in LABELS
            for suffix in ["", "/UserData"]
        } | {"/Hotline19/Files/m-au26-seed-flush"}
        if after:
            expected_paths.add("/Hotline19/Files/m-au26-final-flush")
        require(
            {r["path"] for r in rows} == expected_paths, "Owned account paths differ"
        )
        for label in LABELS:
            row = next(
                r
                for r in rows
                if r["path"]
                == "/Hotline19/Users/" + username(label).decode() + "/UserData"
            )
            data = (base / (row["key"] + ".data")).read_bytes()
            require(
                not row["directory"] and data == account_record(label, after),
                "Stored 734-byte account record differs",
            )
            require(
                (base / (row["key"] + ".rsrc")).read_bytes() == b"",
                "Account resource fork differs",
            )
    before, final = catalogues["native-seed"], catalogues["native-final"]
    require(
        set(before) < set(final)
        and all(final[i]["path"] == r["path"] for i, r in before.items()),
        "Account update changed catalogue identity",
    )
    for phase, count in [("native-cleanup", 23), ("native-published", 24)]:
        base = directory / phase
        moved = {
            r["catalog"]: r
            for r in json.loads((base / "extraction.json").read_text())["records"]
        }
        require(
            len(moved) == count and set(final) < set(moved),
            "Positive account cleanup inventory differs",
        )
        for identifier, original in final.items():
            row = moved[identifier]
            path = (
                original["path"]
                .replace("/Hotline19/Users/", "/Trash/")
                .replace("/Hotline19/Files/", "/Trash/")
            )
            require(
                row["path"] == path and row["directory"] == original["directory"],
                "Account Trash identity/path differs",
            )
            if not row["directory"]:
                for fork in ["data", "rsrc"]:
                    require(
                        (
                            directory / "native-final" / (original["key"] + "." + fork)
                        ).read_bytes()
                        == (base / (row["key"] + "." + fork)).read_bytes(),
                        "Account cleanup changed original fork",
                    )
        unrelated = [r for i, r in moved.items() if i not in final]
        if phase == "native-cleanup":
            require(
                len(unrelated) == 5
                and all(r["path"].startswith("/Trash/") for r in unrelated),
                "Prior Trash observations differ",
            )
        else:
            require(
                len(
                    [
                        r
                        for r in unrelated
                        if r["path"] == "/Hotline19/Files/m-au26-publish"
                    ]
                )
                == 1,
                "Separate account publisher differs",
            )


def verify(directory: Path) -> dict:
    manifest = json.loads((directory / "manifest.json").read_text())
    runtime = json.loads((directory / "runtime.json").read_text())
    require(
        cases.LABELS == LABELS
        and runtime["emulator_pid"] == 1259319
        and runtime["running_executable_sha256"]
        == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
        "Account case/runtime identity differs",
    )
    expected = {
        "preflight": cases.preflight(),
        "seed": cases.seed(),
        "base32-login": cases.probe("preserve32", b"q" * 32, True),
    }
    for label in LABELS:
        expected["mutation-" + label] = cases.mutate(label)
        expected["login-" + label] = cases.probe(label, PASSWORDS[label], True)
        old = b"q" * 32 if label == "preserve32" else BASE_PASSWORD
        wrong = old if old != PASSWORDS[label] else b"wrong-account26"
        expected["reject-" + label] = cases.probe(label, wrong, False)
    expected.update(
        {
            "final": cases.finalization(),
            "cleanup": cases.cleanup(),
            "publish": cases.publish_cleanup(),
            "remove-publisher": cases.remove_publisher(),
        }
    )
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Account report inventory differs",
    )
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(len(host) == 732, "Account packet recorder count differs")
    statistics = (directory / "host-capture-statistics.txt").read_text()
    require(
        "732 packets captured" in statistics
        and "0 packets dropped by kernel" in statistics,
        "Account capture drops/count differ",
    )
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports, connections = {}, 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps
            and plan["expectation"] == expectation
            and plan["environment"] == runtime,
            "Account as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == manifest["reports"][key] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "Account capture provenance/completion differs",
        )
        reference = (
            fields(reply(report, 80))[107].hex()
            if key in {"seed", "final", "publish"}
            else ""
        )
        for connection, recorded in report["streams"].items():
            sent = "".join(
                bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
                for s in steps
                if s["op"] == "send" and s["connection"] == connection
            )
            require(
                recorded["sent_hex"] == sent, "Account recorded input differs from plan"
            )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key == "seed":
            measured_wait(report, "pause")
        if key.startswith(("mutation-", "login-", "reject-")) or key == "base32-login":
            measured_wait(report, "expect_quiet")
    require(
        all(
            datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(expected)
        ),
        "Account fixture chronology differs",
    )
    for index, label in enumerate(LABELS, 100):
        pre = reply(reports["preflight"], index)
        require(
            pre["error"] == 1
            and fields(pre)
            == {100: b"No account with login \xd2" + username(label) + b"\xd3."},
            "Owned account was not initially absent",
        )
        require(
            reply(reports["seed"], index)["error"] == 0
            and fields(reply(reports["seed"], index)) == {},
            "Account creation ACK differs",
        )
        account_reply(reply(reports["seed"], index + 100), label, False)
        changed = reports["mutation-" + label]
        account_reply(reply(changed, 10), label, False)
        require(
            reply(changed, 11)["error"] == 0 and fields(reply(changed, 11)) == {},
            "Account update ACK differs",
        )
        account_reply(reply(changed, 12), label, True)
        require(
            reply(changed, 90)["error"] == 0 and fields(reply(changed, 90)) == {},
            "Account update lost control liveness",
        )
        account_reply(reply(reports["final"], index), label, True)
    for key, report in reports.items():
        if key.startswith("login-") or key == "base32-login":
            label = (
                "preserve32" if key == "base32-login" else key.removeprefix("login-")
            )
            access = ACCESS if key == "base32-login" else values(label, True)[3]
            require(
                [(f["type"], f["error"]) for f in report["frames"]]
                == [(0, 0), (354, 0), (109, 0), (0, 0)]
                and fields(report["frames"][1]) == {110: access},
                "Replacement password login/privileges differ",
            )
        elif key.startswith("reject-"):
            require(
                len(report["frames"]) == 1
                and reply(report, 1)["error"] == 1
                and fields(reply(report, 1)) == {100: b"Incorrect login."},
                "Old/wrong password rejection differs",
            )
        elif key != "preflight":
            require(
                all(f["error"] == 0 for f in report["frames"]),
                "Account control operation failed",
            )
    baseline = enumeration(reply(reports["preflight"], 10))
    files = listing(reply(reports["preflight"], 11))
    require(
        len(baseline) == 2 and len(files) == 41,
        "Initial account/Files inventory differs",
    )
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            enumeration(reply(reports[key], 90)) == baseline,
            "Owned account cleanup did not restore enumeration",
        )
        after = listing(reply(reports[key], 91))
        if key == "publish":
            require(b"m-au26-publish" in after, "Account publisher missing")
            after.pop(b"m-au26-publish")
        require(after == files, "Account helper cleanup did not restore Files")
    storage(directory)
    addresses = {
        "10014df0",
        "100146f0",
        "10014bc0",
        "100149e0",
        "100073c0",
        "100075e0",
        "100071a0",
        "10005d30",
        "10005f90",
        "10011960",
        "10007340",
    }
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == 11
        and {p.stem.removeprefix("AC-D-") for p in queries} == addresses,
        "Account oracle inventory differs",
    )
    for p in queries:
        q = json.loads(p.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == p.with_suffix(".c").read_text(),
            "Account oracle identity/code differs",
        )
    require(
        len(reports) == manifest["completed_reports"] == 31
        and connections == manifest["paired_connections"] == 34,
        "Account aggregate counts differ",
    )
    return {
        "completed_reports": 31,
        "paired_connections": connections,
        "owned_accounts": 8,
        "positive_logins": 9,
        "negative_logins": 8,
        "native_record_bytes": 734,
        "positive_original_trash_objects": 18,
        "oracle_queries": 11,
        "scope": "Sentinel/replacement/default/width fixtures only; opaque111 meaning, live-edit propagation, conflicts/protected deletion, forced write failures and restart persistence remain open",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))
