"""Offline fake-wire and report fault controls for one native 304 rate case."""

import copy
import json
import socket
import time
import unittest
from unittest.mock import patch

import native_rate304_cases as cases
import native_rate304_control as control
from native_plan import packet, payload
from protocol_capture import decode_frame
from verify_classic_native_baseline import AGREEMENT
from verify_native_auth import ADMIN

ENV = {
    "fixture_profile": "control-only",
    "emulator_pid": 100,
    "emulator_starttime": "123",
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 456,
    "owned_working_image": "/ignored/working.dsk",
    "owned_working_image_inode": 789,
}


def frame(name, kind, identifier, fields, *, reply=0, error=0, when=0):
    raw = bytes.fromhex(
        packet(kind, identifier, payload(fields), reply=reply, error=error)
    )
    return {
        "connection": name,
        "raw_hex": raw.hex(),
        "arrival_elapsed_ns": when,
        **decode_frame(raw),
    }


def roster(uid, icon, name):
    return (
        uid.to_bytes(2, "big")
        + icon.to_bytes(2, "big")
        + b"\0\0"
        + len(name).to_bytes(2, "big")
        + name
    )


def update(uid, icon):
    return [
        (103, uid.to_bytes(2, "big")),
        (104, icon.to_bytes(2, "big")),
        (112, b"\0"),
        (102, cases.SUBJECT_NAME),
    ]


def fake_report(plan):
    frames = []

    def add(name, kind, identifier, fields, *, reply=0, error=0, when=0):
        frames.append(
            frame(name, kind, identifier, fields, reply=reply, error=error, when=when)
        )

    for name, access, uid, when in (
        ("observer", ADMIN, 1, 0),
        ("paced", bytes(8), 2, 100),
        ("burst", bytes(8), 3, 1100),
    ):
        add(name, 0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1, when=when)
        add(name, 354, 0, [(110, access)], when=when)
        add(name, 109, 0, [(101, AGREEMENT)], when=when)
    add("observer", 0, 10, [(300, roster(1, 1, cases.OBS_NAME))], reply=1, when=0)
    for name, uid, when in (("paced", 2, 100), ("burst", 3, 1100)):
        add(
            name,
            0,
            10,
            [
                (300, roster(1, 1, cases.OBS_NAME)),
                (300, roster(uid, 1, cases.SUBJECT_NAME)),
            ],
            reply=1,
            when=when,
        )
        add("observer", 301, 0, update(uid, 1), when=when)
        for index in range(26):
            add("observer", 301, 0, update(uid, index + 2), when=when + index + 1)
            add(
                name,
                0,
                (2000 if name == "paced" else 4000) + index,
                [],
                reply=1,
                when=when + index + 1,
            )
    add("observer", 301, 0, update(2, 28), when=1000)
    add("paced", 0, 2026, [], reply=1, when=1000)
    add("observer", 302, 0, [(103, b"\0\2")], when=1001)
    add("observer", 302, 0, [(103, b"\0\3")], when=1400)
    add("probe", 0, 1, [(100, cases.TEMPORARY_BAN)], reply=1, error=1, when=1500)
    for kind, identifier in plan["request_ids"]["observer_controls"].items():
        if kind == "300":
            data = [(300, roster(1, 1, cases.OBS_NAME))]
        else:
            data = [(101, b"fixture")]
        add("observer", 0, identifier, data, reply=1, when=1600)
    return {
        "frames": frames,
        "identities": {"paced_uid": 2, "burst_uid": 3},
        "actions": [{"label": "burst-login", "elapsed_ns": 1050}],
        "timing": {
            "paced_trial_seconds": 9,
            "burst_trial_seconds": 9,
            "subject_quiet_seconds": 71,
            "native_60_seconds_proven": False,
        },
        "terminals": {
            "observer": "bounded_no_eof",
            "paced": "bounded_no_eof",
            "burst": "eof",
            "probe": "bounded_no_eof",
        },
    }


class Rate304Tests(unittest.TestCase):
    def setUp(self):
        self.plan = cases.source_plan(ENV)
        self.report = fake_report(self.plan)
        self.digest_patch = patch.object(
            control,
            "field_digest",
            side_effect=lambda f: control.BASELINE_FIELDS[
                {
                    6000: 348,
                    6001: 200,
                    6002: 206,
                    6004: 303,
                }[f["id"]]
            ],
        )
        self.digest_patch.start()
        self.addCleanup(self.digest_patch.stop)

    def test_producer_exact_104_only_and_ids(self):
        raw = bytes.fromhex(cases.update(1000, 2))
        decoded = decode_frame(raw)
        self.assertEqual(decoded["type"], 304)
        self.assertEqual(decoded["id"], 1000)
        self.assertEqual(decoded["fields"], [{"id": 104, "hex": "0002"}])
        self.assertEqual(self.plan["request_ids"]["paced_304"], list(range(1000, 1027)))
        with self.assertRaises(ValueError):
            cases.source_plan(ENV, 15881)
        with self.assertRaises(ValueError):
            cases.source_plan({**ENV, "fixture_profile": "full-a7"})

    def test_generated_schedule_exact(self):
        actions = control.expected_actions(self.plan, 14)
        self.assertEqual(
            actions[0], ("observer-login", "observer", self.plan["logins"]["observer"])
        )
        self.assertEqual(actions[-1][0], "observer-303")
        self.assertEqual(len(actions), 4 + 52 + 14 + 4 + 52 + 2 + 5)
        with self.assertRaises(ValueError):
            control.expected_actions(self.plan, 16)

    def test_fake_wire_acceptance_and_semantic_faults(self):
        control.classify(self.plan, self.report)
        faults = [
            (
                lambda r: r["frames"].pop(
                    next(
                        i
                        for i, f in enumerate(r["frames"])
                        if f["connection"] == "paced" and f["id"] == 2026
                    )
                ),
                "barrier",
            ),
            (
                lambda r: r["frames"].__setitem__(
                    next(
                        i
                        for i, f in enumerate(r["frames"])
                        if f["connection"] == "probe"
                    ),
                    frame("probe", 0, 1, [], reply=1, when=1500),
                ),
                "ban",
            ),
            (lambda r: r["timing"].__setitem__("subject_quiet_seconds", 60), "reset"),
            (
                lambda r: r["timing"].__setitem__("burst_trial_seconds", 22),
                "burst timing",
            ),
            (lambda r: r["terminals"].__setitem__("burst", "bounded_no_eof"), "close"),
            (lambda r: r["identities"].__setitem__("paced_uid", 4), "uid"),
            (
                lambda r: r["frames"].__setitem__(
                    next(
                        i
                        for i, f in enumerate(r["frames"])
                        if f["connection"] == "paced" and f["type"] == 354
                    ),
                    frame("paced", 354, 0, [(110, ADMIN)], when=100),
                ),
                "early-login-access",
            ),
            (
                lambda r: r["frames"].pop(
                    next(
                        i
                        for i, f in enumerate(r["frames"])
                        if f["connection"] == "observer" and f["id"] == 6000
                    )
                ),
                "retained-control",
            ),
            (
                lambda r: r["frames"].append(
                    frame("observer", 301, 0, update(3, 28), when=1200)
                ),
                "terminal301",
            ),
            (
                lambda r: r["frames"].append(
                    frame("paced", 0, 1000, [], reply=1, when=150)
                ),
                "304ACK",
            ),
        ]
        for mutate, label in faults:
            with self.subTest(label=label), self.assertRaises(ValueError):
                changed = copy.deepcopy(self.report)
                mutate(changed)
                control.classify(self.plan, changed)

    def test_real_socketpair_reassembles_and_preserves_truncated_tail(self):
        wire = control.Wire(self.plan, time.monotonic() + 2)
        source, peer = socket.socketpair()
        self.addCleanup(source.close)
        self.addCleanup(peer.close)
        wire.recorder.sockets["observer"] = source
        wire.buffers["observer"] = bytearray()
        raw = bytes.fromhex(packet(0, 77, payload([(101, b"ok")]), reply=1))
        peer.sendall(raw[:11])
        wire.poll(0.02)
        self.assertEqual(wire.frames, [])
        peer.sendall(raw[11:] + b"\xaa\xbb")
        wire.poll(0.02)
        self.assertEqual(wire.frames[0]["raw_hex"], raw.hex())
        self.assertEqual(wire.buffers["observer"], b"\xaa\xbb")
        peer.shutdown(socket.SHUT_WR)
        wire.poll(0.02)
        self.assertEqual(wire.terminals["observer"], "eof")
        self.assertEqual(wire.buffers["observer"], b"\xaa\xbb")

    def full_fake_report(self):
        source = fake_report(self.plan)
        pool = source["frames"] + [
            frame("observer", 0, 5000 + i, [], reply=1) for i in range(14)
        ]
        events, actions, observed = [], [], []
        tick = 0

        def emit(name, kind, raw=""):
            nonlocal tick
            tick += 1_000_000
            events.append(
                {"connection": name, "event": kind, "hex": raw, "elapsed_ns": tick}
            )

        def take(name, kind, identifier=None, icon=None):
            for pos, candidate in enumerate(pool):
                if candidate["connection"] != name or candidate["type"] != kind:
                    continue
                if identifier is not None and candidate["id"] != identifier:
                    continue
                if icon is not None and control.exact_fields(candidate).get(
                    104
                ) != icon.to_bytes(2, "big"):
                    continue
                result = pool.pop(pos)
                emit(name, "receive", result["raw_hex"])
                result["arrival_elapsed_ns"] = tick
                observed.append(result)
                return
            raise AssertionError((name, kind, identifier, icon))

        for label, name, raw in control.expected_actions(self.plan, 14):
            if label == "paced-304-after-quiet":
                tick += 71_000_000_000
            if label.endswith("-login"):
                emit(name, "send", cases.HELLO)
                emit(name, "receive", cases.HELLO_REPLY)
            first = len(events)
            emit(name, "send", raw)
            actions.append(
                {
                    "label": label,
                    "connection": name,
                    "hex": raw,
                    "elapsed_ns": tick,
                    "event_range": [first, len(events)],
                }
            )
            if label.endswith("-login") and name != "probe":
                for kind, identifier in ((0, 1), (354, 0), (109, 0)):
                    take(name, kind, identifier)
                if name in {"paced", "burst"}:
                    take("observer", 301, icon=1)
            elif label.endswith("-roster"):
                take(name, 0, 10)
            elif label == "observer-roster-initial":
                take("observer", 0, 10)
            elif label == "burst-304-terminal":
                emit("burst", "eof")
                take("observer", 302, icon=None)
            elif label.startswith(("paced-304-", "burst-304-")):
                icon = 28 if label == "paced-304-after-quiet" else int(label[-2:]) + 2
                take("observer", 301, icon=icon)
            elif label.startswith(("paced-500-", "burst-500-")):
                ident = (
                    2026
                    if label == "paced-500-after-quiet"
                    else int.from_bytes(bytes.fromhex(raw)[4:8], "big")
                )
                take(name, 0, ident)
                if label == "paced-500-after-quiet":
                    take("observer", 302, icon=None)
            elif label.startswith("observer-idle500-"):
                take("observer", 0, int.from_bytes(bytes.fromhex(raw)[4:8], "big"))
            elif label == "probe-login":
                take("probe", 0, 1)
            elif label.startswith("observer-"):
                take("observer", 0, int.from_bytes(bytes.fromhex(raw)[4:8], "big"))
        self.assertEqual(pool, [])
        streams = {}
        for event in events:
            view = streams.setdefault(
                event["connection"], {"sent_hex": "", "received_hex": ""}
            )
            if event["event"] == "send":
                view["sent_hex"] += event["hex"]
            elif event["event"] == "receive":
                view["received_hex"] += event["hex"]
        return {
            **source,
            "status": "completed",
            "native_clock_calibrated": False,
            "plan_sha256": cases.digest(
                (json.dumps(self.plan, indent=2) + "\n").encode()
            ),
            "cases_sha256": control.digest(
                __import__("pathlib").Path(cases.__file__).read_bytes()
            ),
            "source_sha256": control.digest(
                __import__("pathlib").Path(control.__file__).read_bytes()
            ),
            "oracle_sha256": control.ORACLE_SHA256,
            "frames": observed,
            "events": events,
            "actions": actions,
            "streams": streams,
            "unparsed_hex": {name: "" for name in streams},
        }

    def test_full_fake_wire_report_and_faults(self):
        report = self.full_fake_report()
        control.verify_report(self.plan, report)
        faults = [
            lambda r: r.__setitem__("source_sha256", "0" * 64),
            lambda r: r.__setitem__("native_clock_calibrated", True),
            lambda r: r["actions"][10].__setitem__("label", "reordered"),
            lambda r: r["streams"]["paced"].__setitem__("received_hex", "00"),
            lambda r: r["terminals"].__setitem__("burst", "bounded_no_eof"),
            lambda r: r["frames"].pop(),
            lambda r: r["unparsed_hex"].__setitem__("paced", "aa"),
        ]
        for mutate in faults:
            with self.subTest(fault=mutate), self.assertRaises(ValueError):
                changed = copy.deepcopy(report)
                mutate(changed)
                control.verify_report(self.plan, changed)


if __name__ == "__main__":
    unittest.main()
