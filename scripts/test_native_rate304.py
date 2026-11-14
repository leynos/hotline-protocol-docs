"""Offline fake-wire and report fault controls for one native 304 rate case."""

import copy
import json
import socket
import threading
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


def fake_report(plan, observer_uid=1):
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
    add(
        "observer",
        0,
        10,
        [(300, roster(observer_uid, 1, cases.OBS_NAME))],
        reply=1,
        when=0,
    )
    for name, uid, when in (("paced", 2, 100), ("burst", 3, 1100)):
        add(
            name,
            0,
            10,
            [
                (300, roster(observer_uid, 1, cases.OBS_NAME)),
                (300, roster(uid, 1, cases.SUBJECT_NAME)),
            ],
            reply=1,
            when=when,
        )
        add("observer", 301, 0, update(uid, 1), when=when)
        for index in range(26):
            add("observer", 301, 0, update(uid, index + 2), when=when + index + 1)
            add(name, 301, 0, update(uid, index + 2), when=when + index + 1)
            add(
                name,
                0,
                (2000 if name == "paced" else 4000) + index,
                [],
                reply=1,
                when=when + index + 1,
            )
    add("observer", 301, 0, update(2, 28), when=1000)
    add("paced", 301, 0, update(2, 28), when=1000)
    add("paced", 0, 2026, [], reply=1, when=1000)
    add("observer", 302, 0, [(103, b"\0\2")], when=1001)
    add("observer", 302, 0, [(103, b"\0\3")], when=1400)
    add("probe", 0, 1, [(100, cases.TEMPORARY_BAN)], reply=1, error=1, when=1500)
    for kind, identifier in plan["request_ids"]["observer_controls"].items():
        if kind == "300":
            data = [(300, roster(observer_uid, 1, cases.OBS_NAME))]
        else:
            data = [(101, b"fixture")]
        add("observer", 0, identifier, data, reply=1, when=1600)
    return {
        "frames": frames,
        "identities": {"observer_uid": observer_uid, "paced_uid": 2, "burst_uid": 3},
        "actions": [
            {"label": "burst-login", "elapsed_ns": 1050},
            {"label": "burst-304-terminal", "elapsed_ns": 1350},
            {"label": "probe-login", "elapsed_ns": 1450},
        ],
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
        self.assertEqual(self.plan["schedule"]["schema_version"], 2)
        self.assertIn("26 ordered 304+500", self.plan["schedule"]["phase_mode"])
        actions = control.expected_actions(self.plan, 14, 1)
        self.assertEqual(
            actions[0], ("observer-login", "observer", self.plan["logins"]["observer"])
        )
        self.assertEqual(actions[-1][0], "observer-303")
        self.assertEqual(len(actions), 4 + 52 + 14 + 4 + 52 + 2 + 5)
        with self.assertRaises(ValueError):
            control.expected_actions(self.plan, 16, 1)

    def test_observer_303_uses_dynamic_self_uid(self):
        raw = cases.observer_control(303, 6004, 7)
        decoded = decode_frame(bytes.fromhex(raw))
        self.assertEqual(decoded["type"], 303)
        self.assertEqual(decoded["fields"], [{"id": 103, "hex": "0007"}])
        self.assertEqual(control.expected_actions(self.plan, 14, 7)[-1][2], raw)
        for uid in (None, 0, -1, 65536):
            with self.subTest(uid=uid), self.assertRaises(ValueError):
                cases.observer_control(303, 6004, uid)
        with self.assertRaises(ValueError):
            cases.observer_control(300, 10, 7)

    def test_303_report_target_must_match_independent_roster_uid(self):
        valid = self.full_fake_report(observer_uid=7)
        control.verify_report(self.plan, valid)
        self.assertEqual(valid["identities"]["observer_uid"], 7)
        with self.assertRaises(ValueError):
            control.verify_report(
                self.plan, self.full_fake_report(observer_uid=7, target_uid=1)
            )

    def test_post_ban_roster_uid_drift_rejected_with_consistent_raw(self):
        report = self.full_fake_report(observer_uid=7)
        old = next(
            f
            for f in report["frames"]
            if f["connection"] == "observer" and f["id"] == 6003
        )
        changed = frame(
            "observer",
            0,
            6003,
            [(300, roster(8, 1, cases.OBS_NAME))],
            reply=1,
            when=old["arrival_elapsed_ns"],
        )
        report["frames"][report["frames"].index(old)] = changed
        event = next(
            e
            for e in report["events"]
            if e["event"] == "receive" and e["hex"] == old["raw_hex"]
        )
        event["hex"] = changed["raw_hex"]
        received = report["streams"]["observer"]["received_hex"]
        self.assertEqual(received.count(old["raw_hex"]), 1)
        report["streams"]["observer"]["received_hex"] = received.replace(
            old["raw_hex"], changed["raw_hex"], 1
        )
        with self.assertRaisesRegex(ValueError, "post-ban roster UID"):
            control.verify_report(self.plan, report)

    def test_fake_wire_acceptance_and_semantic_faults(self):
        control.classify(self.plan, self.report)
        terminal = copy.deepcopy(self.report)
        terminal["frames"].extend(
            [
                frame("burst", 104, 7, [(101, b"observed terminal notice")], when=1370),
                frame("observer", 302, 0, [(103, b"\0\4")], when=1550),
            ]
        )
        control.classify(self.plan, terminal)
        faults = [
            (
                lambda r: r["frames"].pop(
                    next(
                        i
                        for i, f in enumerate(r["frames"])
                        if f["connection"] == "paced" and f["type"] == 301
                    )
                ),
                "subject301-missing-observer-and-barrier-intact",
            ),
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

    def rehearse_phase(
        self,
        delay,
        *,
        missing=False,
        duplicate=False,
        foreign=False,
        observer_first=False,
        seconds=2,
    ):
        """Run actual 52 request sends and two response sockets with delayed peers."""
        wire = control.Wire(self.plan, time.monotonic() + 4)
        subject, subject_peer = socket.socketpair()
        observer, observer_peer = socket.socketpair()
        for name, sock in (("paced", subject), ("observer", observer)):
            wire.recorder.sockets[name] = sock
            wire.buffers[name] = bytearray()
        for sock in (subject_peer, observer_peer):
            sock.settimeout(3)
        errors = []

        def exactly(sock, size):
            raw = bytearray()
            while len(raw) < size:
                part = sock.recv(size - len(raw))
                if not part:
                    raise EOFError("Synthetic peer closed early")
                raw.extend(part)
            return bytes(raw)

        def peer():
            try:
                received = []
                for _ in range(52):
                    header = exactly(subject_peer, 20)
                    body = exactly(subject_peer, int.from_bytes(header[16:20], "big"))
                    received.append(control.decode_frame(header + body))
                self.assertEqual(
                    [(f["type"], f["id"]) for f in received],
                    [
                        item
                        for i in range(26)
                        for item in ((304, 1000 + i), (500, 2000 + i))
                    ],
                )
                time.sleep(delay)
                if foreign:
                    observer_peer.sendall(
                        bytes.fromhex(packet(301, 0, payload(update(77, 2))))
                    )
                for index in range(26):
                    notice = bytes.fromhex(
                        packet(301, 0, payload(update(2, index + 2)))
                    )
                    if observer_first and not (missing and index == 25):
                        observer_peer.sendall(notice)
                    subject_peer.sendall(notice)
                    if not observer_first and not (missing and index == 25):
                        observer_peer.sendall(notice)
                    if duplicate and index == 5:
                        observer_peer.sendall(notice)
                    subject_peer.sendall(
                        bytes.fromhex(packet(0, 2000 + index, reply=1))
                    )
            except (OSError, EOFError, AssertionError, ValueError) as error:
                errors.append(error)

        worker = threading.Thread(target=peer, daemon=True)
        worker.start()
        try:
            if missing or duplicate or foreign or seconds < delay:
                with self.assertRaises(ValueError):
                    control.run_update_phase(wire, "paced", 2, seconds)
            else:
                receipt = control.run_update_phase(wire, "paced", 2, seconds)
                self.assertEqual(receipt["mode"], self.plan["schedule"]["phase_mode"])
                self.assertNotIn("observer", wire.terminals)
                self.assertEqual(len(wire.match("paced", 0, None, 1)), 26)
            self.assertTrue(wire.recorder.streams()["paced"]["sent_hex"])
            self.assertTrue(
                wire.recorder.streams()["paced"]["received_hex"] or seconds < delay
            )
            if missing or duplicate or foreign:
                self.assertTrue(wire.recorder.streams()["observer"]["received_hex"])
            if missing:
                self.assertEqual(control.validated_phase_progress(wire, "paced", 2), 25)
            if duplicate:
                self.assertEqual(control.validated_phase_progress(wire, "paced", 2), 5)
        finally:
            worker.join(timeout=3)
            for sock in (subject, observer, subject_peer, observer_peer):
                sock.close()
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(wire.recorder.sockets["observer"].fileno(), -1)

    def test_real_delayed_peer_pipeline_and_faults(self):
        self.rehearse_phase(0.75)
        self.rehearse_phase(0.75, observer_first=True)
        self.rehearse_phase(0.75, missing=True, seconds=1.1)
        self.rehearse_phase(0.75, duplicate=True)
        self.rehearse_phase(0.75, foreign=True)
        self.rehearse_phase(0.75, seconds=0.6)

    def test_old_pair_boundary_fails_before_delayed_response(self):
        wire = control.Wire(self.plan, time.monotonic() + 2)
        subject, peer = socket.socketpair()
        wire.recorder.sockets["paced"] = subject
        wire.buffers["paced"] = bytearray()

        def delayed_reply():
            time.sleep(0.75)
            peer.sendall(bytes.fromhex(packet(301, 0, payload(update(2, 2)))))
            peer.sendall(bytes.fromhex(packet(0, 2000, reply=1)))

        try:
            wire.send("paced", cases.update(1000, 2), "paced-304-00")
            wire.send("paced", cases.barrier(2000), "paced-500-00")
            worker = threading.Thread(target=delayed_reply)
            worker.start()
            with self.assertRaisesRegex(ValueError, "Missing old 0.55s pair"):
                wire.wait_for(
                    lambda: bool(wire.match("paced", 0, 2000, 1)),
                    0.55,
                    "old 0.55s pair",
                )
            self.assertIn("paced", wire.recorder.sockets)
            wire.wait_for(lambda: bool(wire.match("paced", 0, 2000, 1)), 1, "late ACK")
            worker.join(timeout=1)
            self.assertFalse(worker.is_alive())
        finally:
            subject.close()
            peer.close()

    def full_fake_report(
        self, observer_after_barrier=False, observer_uid=1, target_uid=None
    ):
        source = fake_report(self.plan, observer_uid)
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

        for label, name, raw in control.expected_actions(
            self.plan, 14, target_uid or observer_uid
        ):
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
                if not observer_after_barrier:
                    take("observer", 301, icon=icon)
                take(name, 301, icon=icon)
            elif label.startswith(("paced-500-", "burst-500-")):
                ident = (
                    2026
                    if label == "paced-500-after-quiet"
                    else int.from_bytes(bytes.fromhex(raw)[4:8], "big")
                )
                take(name, 0, ident)
                if observer_after_barrier:
                    icon = (
                        28 if label == "paced-500-after-quiet" else int(label[-2:]) + 2
                    )
                    take("observer", 301, icon=icon)
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
            "phase_progress": {"paced": 26, "burst": 26},
            "phase_mode": self.plan["schedule"]["phase_mode"],
            "phase_receipts": {
                name: {
                    "mode": self.plan["schedule"]["phase_mode"],
                    "started_elapsed_ns": next(
                        a["elapsed_ns"]
                        for a in actions
                        if a["label"] == f"{name}-304-00"
                    )
                    - 1,
                    "all_pairs_sent_elapsed_ns": next(
                        a["elapsed_ns"]
                        for a in actions
                        if a["label"] == f"{name}-500-25"
                    ),
                    "completed_elapsed_ns": max(
                        next(
                            a["elapsed_ns"]
                            for a in actions
                            if a["label"] == f"{name}-500-25"
                        ),
                        *(
                            f["arrival_elapsed_ns"]
                            for f in observed
                            if (
                                f["connection"] in (name, "observer")
                                and f["type"] == 301
                                and control.exact_fields(f).get(103)
                                == (2 if name == "paced" else 3).to_bytes(2, "big")
                                and 2
                                <= int.from_bytes(
                                    control.exact_fields(f).get(104, b"\0\0"), "big"
                                )
                                <= 27
                            )
                            or (
                                f["connection"] == name
                                and f["type"] == 0
                                and f["is_reply"] == 1
                                and f["id"]
                                in range(
                                    2000 if name == "paced" else 4000,
                                    2026 if name == "paced" else 4026,
                                )
                            )
                        ),
                    ),
                }
                for name in ("paced", "burst")
            },
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
        control.verify_report(
            self.plan, self.full_fake_report(observer_after_barrier=True)
        )
        faults = [
            lambda r: r.__setitem__("source_sha256", "0" * 64),
            lambda r: r.__setitem__("native_clock_calibrated", True),
            lambda r: r["actions"][10].__setitem__("label", "reordered"),
            lambda r: r["streams"]["paced"].__setitem__("received_hex", "00"),
            lambda r: r["terminals"].__setitem__("burst", "bounded_no_eof"),
            lambda r: r["frames"].pop(),
            lambda r: r["unparsed_hex"].__setitem__("paced", "aa"),
            lambda r: r["phase_receipts"]["paced"].__setitem__(
                "completed_elapsed_ns", 99_000_000_000
            ),
            lambda r: r["phase_progress"].__setitem__("paced", 25),
        ]
        for mutate in faults:
            with self.subTest(fault=mutate), self.assertRaises(ValueError):
                changed = copy.deepcopy(report)
                mutate(changed)
                control.verify_report(self.plan, changed)

    def test_extra_notification_rejected_with_consistent_raw_stream(self):
        original = self.full_fake_report()
        for name, kind, values, rejected in (
            ("observer", 301, update(77, 9), True),
            ("observer", 104, [(101, b"unsolicited")], True),
            ("observer", 302, [(103, b"\0\1")], True),
            ("observer", 302, [(103, b"\0\2")], True),
            ("observer", 302, [(103, b"\0\3")], True),
            ("observer", 302, [(103, b"\0\4")], False),
        ):
            with self.subTest(kind=kind):
                report = copy.deepcopy(original)
                when = report["events"][-1]["elapsed_ns"] + 1
                extra = frame(name, kind, 99, values, when=when)
                report["frames"].append(extra)
                report["events"].append(
                    {
                        "connection": name,
                        "event": "receive",
                        "hex": extra["raw_hex"],
                        "elapsed_ns": when,
                    }
                )
                report["streams"][name]["received_hex"] += extra["raw_hex"]
                if rejected:
                    with self.assertRaises(ValueError):
                        control.verify_report(self.plan, report)
                else:
                    control.verify_report(self.plan, report)


if __name__ == "__main__":
    unittest.main()
