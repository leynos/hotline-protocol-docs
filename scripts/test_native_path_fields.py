"""Offline controls for the exact field-212/325 native path matrix."""

import copy
import json
import socket
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import native_path_fields_cases as cases
import native_path_fields_control as control
from native_plan import packet, payload
from native_rate304_control import Wire
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


class PathFieldTests(unittest.TestCase):
    def test_exact_cells_and_limits(self):
        values = cases.cells()
        self.assertEqual(len(values), 12)
        self.assertEqual([v["field"] for v in values], [212] * 6 + [325] * 6)
        self.assertEqual(
            [len(bytes.fromhex(v["value_hex"])) for v in values],
            [19, 22, 19, 19, 2048, 2049, 12, 15, 12, 12, 2048, 2049],
        )
        self.assertEqual(
            values[2]["value_hex"], "00030000086d2d706174683437000003482d9a"
        )
        self.assertEqual(values[8]["value_hex"], "00020000076d2d6e34372d9a")

    def test_request_ledger(self):
        plan = cases.source_plan(ENV)
        self.assertIn("separate unchanged closed 18-action", plan["preflight"])
        self.assertEqual(len(plan["requests"]), 81)
        self.assertEqual(plan["case_request_count_with_login"], 82)
        self.assertEqual(plan["mutation_count"], 20)
        self.assertEqual(len({r["id"] for r in plan["requests"]}), 81)
        self.assertEqual(
            [r["kind"] for r in plan["requests"] if r["label"].startswith("move-")],
            [208] * 6,
        )

    def test_prepared_source_and_plan_are_immutable(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "prepared"
            cases.write_plan(output, ENV)
            self.assertEqual(control.prepared(output), cases.source_plan(ENV))
            hashes = output / "source-hashes.json"
            original = hashes.read_text()
            changed = json.loads(original)
            changed["native_path_fields_control.py"] = "0" * 64
            hashes.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "source hash differs"):
                control.prepared(output)
            hashes.write_text(original)
            (output / "plan.json").write_text("{}\n")
            with self.assertRaisesRegex(ValueError, "source hash differs"):
                control.prepared(output)

    def test_changed_count_high_byte_padding_marker_or_id_rejected(self):
        plan = cases.source_plan(ENV)
        changes = (
            lambda p: p["cells"][2].__setitem__("declared_count", 2),
            lambda p: p["cells"][0].__setitem__(
                "value_hex", p["cells"][0]["value_hex"].replace("482d9a", "482d9b")
            ),
            lambda p: p["cells"][4].__setitem__(
                "value_hex", p["cells"][4]["value_hex"][:-2]
            ),
            lambda p: p["cells"][1].__setitem__(
                "marker_hex", p["cells"][0]["marker_hex"]
            ),
            lambda p: p["requests"][1].__setitem__("id", p["requests"][0]["id"]),
        )
        for index, change in enumerate(changes):
            altered = copy.deepcopy(plan)
            change(altered)
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temp:
                output = Path(temp)
                raw = (json.dumps(altered, indent=2) + "\n").encode()
                (output / "plan.json").write_bytes(raw)
                (output / "source-hashes.json").write_text(
                    json.dumps(
                        {
                            "plan.json": cases.sha(raw),
                            "native_path_fields_cases.py": cases.sha(
                                Path(cases.__file__).read_bytes()
                            ),
                            "native_path_fields_control.py": control.sha(
                                Path(control.__file__).read_bytes()
                            ),
                        }
                    )
                )
                with self.assertRaisesRegex(ValueError, "differs from source"):
                    control.prepared(output)


# Synthetic service: it checks fixture control flow and receipt conservation.
# Its responses are chosen by this test and are not native path observations.


def model_frame(name, kind, identifier, values, *, reply=0, error=0):
    raw = bytes.fromhex(
        packet(kind, identifier, payload(values), reply=reply, error=error)
    )
    return {
        "connection": name,
        "raw_hex": raw.hex(),
        "arrival_elapsed_ns": time.monotonic_ns(),
        **decode_frame(raw),
    }


def file_record(name):
    return bytes(16) + len(name).to_bytes(4, "big") + name


def news_record(name, folder):
    if folder:
        return b"\0\2\0\0" + bytes([len(name)]) + name + b"\0"
    return b"\0\3\0\0" + bytes(24) + bytes([len(name)]) + name + bytes(3)


class FakeRecorder:
    def __init__(self):
        self.started = time.monotonic_ns()
        self.started_at_utc = datetime.now(timezone.utc).isoformat()
        self.events = []
        self.sockets = {}

    def event(self, action, name, event, raw=b""):
        self.events.append(
            {
                "action": action,
                "connection": name,
                "event": event,
                "elapsed_ns": time.monotonic_ns() - self.started,
                "hex": raw.hex(),
            }
        )

    def streams(self):
        result = {}
        for event in self.events:
            stream = result.setdefault(
                event["connection"], {"sent_hex": "", "received_hex": ""}
            )
            if event["event"] == "send":
                stream["sent_hex"] += event["hex"]
            if event["event"] == "receive":
                stream["received_hex"] += event["hex"]
        return result


class FakeWire:
    def __init__(
        self,
        plan,
        *,
        missing_readback=False,
        move_error=None,
        foreign_after_move=False,
        type_flip_after_move=False,
    ):
        self.plan = plan
        self.recorder = FakeRecorder()
        self.frames = []
        self.actions = []
        self.terminals = {}
        self.buffers = {}
        self.request_count = 0
        self.partial = {}
        self.missing_readback = missing_readback
        self.move_error = move_error
        self.foreign_after_move = foreign_after_move
        self.type_flip_after_move = type_flip_after_move
        self.folders = {"S": set(), "H": set(), "wrapper": {b"S", b"H-\x9a"}}
        self.wrapper = False
        self.news_folder = False
        self.news_category = False
        self.next_action = 0

    def execute(self, step):
        name = step["connection"]
        if step["op"] == "connect":
            self.recorder.sockets[name] = object()
            self.recorder.event(self.next_action, name, "connect")
        elif step["op"] == "send":
            self.recorder.event(
                self.next_action, name, "send", bytes.fromhex(step["hex"])
            )
        elif step["op"] == "read":
            self.recorder.event(
                self.next_action, name, "receive", bytes.fromhex(cases.HELLO_REPLY)
            )
        self.next_action += 1

    def send(self, name, raw, label):
        start = len(self.recorder.events)
        self.recorder.event(self.next_action, name, "send", bytes.fromhex(raw))
        self.next_action += 1
        action = {
            "label": label,
            "connection": name,
            "hex": raw,
            "elapsed_ns": time.monotonic_ns() - self.recorder.started,
            "event_range": [start, len(self.recorder.events)],
        }
        self.actions.append(action)
        if label.endswith("-login"):
            for frame in (
                model_frame(name, 0, 1, [(160, b"\0\xbe"), (161, b"\0\0")], reply=1),
                model_frame(name, 354, 0, [(110, ADMIN)]),
                model_frame(name, 109, 0, [(101, AGREEMENT)]),
            ):
                self.add(frame)
            return
        spec = next((s for s in self.plan["requests"] if s["label"] == label), None)
        if spec is None:
            if label.startswith("stop-files-root-"):
                spec = cases.request(
                    label,
                    200,
                    9000 + int(label.rsplit("-", 1)[1]),
                    [(202, cases.FILES_ROOT)],
                    "stop-probe",
                )
            else:
                raise AssertionError(label)
        reply = self.reply(spec, action)
        self.add(reply)

    def add(self, frame):
        self.recorder.event(
            -1, frame["connection"], "receive", bytes.fromhex(frame["raw_hex"])
        )
        frame["arrival_elapsed_ns"] = time.monotonic_ns() - self.recorder.started
        self.frames.append(frame)

    def reply(self, spec, action):
        name = action["connection"]
        label = spec["label"]
        kind = spec["kind"]
        values = []
        if kind == 348:
            values = [(101, b"account-one"), (101, b"account-two")]
        elif kind == 300:
            values = [(300, b"\0\7\0\1\0\0\0\x0f" + b"framing-fixture")]
        elif kind == 200:
            if "files-root" in label:
                names = [b"original"] + ([cases.FILES] if self.wrapper else [])
            elif "wrapper" in label:
                names = list(self.folders["wrapper"])
            elif label.endswith("-S"):
                names = sorted(self.folders["S"])
            elif label.endswith("-H"):
                names = sorted(self.folders["H"])
            else:
                names = []
            values = [(200, file_record(v)) for v in names]
            if self.type_flip_after_move and label == "after-view-0-H":
                values = [(field, b"TEXT" + raw[4:]) for field, raw in values]
            if self.missing_readback and label == "after-view-0-H":
                values = []
        elif kind == 206:
            marker = (
                bytes.fromhex(spec["marker_hex"])
                if spec["marker_hex"]
                else bytes.fromhex(spec["fields"][0][1])
            )
            values = [(201, marker), (213, b"fldr")]
        elif kind == 370:
            if "high" in label or label.startswith("news-"):
                values = (
                    [(323, news_record(cases.CATEGORY, False))]
                    if self.news_category
                    else []
                )
            else:
                values = (
                    [(323, news_record(cases.NEWS, True))] if self.news_folder else []
                )
        elif kind == 205:
            leaf = bytes.fromhex(spec["fields"][0][1])
            parent = bytes.fromhex(spec["fields"][1][1])
            if leaf == cases.FILES:
                self.wrapper = True
            elif parent == cases.SOURCE:
                self.folders["S"].add(leaf)
        elif kind == 381:
            self.news_folder = True
        elif kind == 382:
            self.news_category = True
        elif kind == 208:
            marker = bytes.fromhex(spec["marker_hex"])
            if self.move_error == label:
                return model_frame(name, 0, spec["id"], [], reply=1, error=999)
            self.folders["S"].remove(marker)
            self.folders["H"].add(marker)
            if self.foreign_after_move and label == "move-0":
                self.folders["H"].add(b"foreign")
        elif kind == 380:
            if label.endswith("category"):
                self.news_category = False
            else:
                self.news_folder = False
        elif kind == 204:
            self.wrapper = False
        return model_frame(name, 0, spec["id"], values, reply=1)

    def match(self, name, kind, identifier, reply):
        return [
            f
            for f in self.frames
            if f["connection"] == name
            and f["type"] == kind
            and f["is_reply"] == reply
            and (identifier is None or f["id"] == identifier)
        ]

    def wait_for(self, predicate, seconds, label):
        if not predicate():
            raise ValueError("Synthetic missing " + label)

    def shutdown_and_close(self, name):
        self.recorder.sockets.pop(name)
        self.recorder.event(-1, name, "close")
        self.terminals[name] = "bounded_no_eof"

    def close_all(self):
        for name in list(self.recorder.sockets):
            self.shutdown_and_close(name)


class PathModelTests(unittest.TestCase):
    def setUp(self):
        self.plan = cases.source_plan(ENV)

    def test_observed_nonzero_move_error_is_not_hardcoded(self):
        wire = FakeWire(self.plan, move_error="move-1")
        result = control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        self.assertEqual(result["results"][1]["status"], 999)
        self.assertEqual(result["results"][1]["selected_parent"], "S")
        wire.close_all()

    def test_foreign_owned_parent_entry_stops_before_second_move(self):
        wire = FakeWire(self.plan, foreign_after_move=True)
        with self.assertRaisesRegex(ValueError, "Unexpected name"):
            control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        self.assertFalse(any(a["label"] == "move-1" for a in wire.actions))
        self.assertIn("666f726569676e", wire.partial["views"][-1]["names"])
        wire.close_all()

    def test_type_change_in_moved_record_stops_before_second_move(self):
        wire = FakeWire(self.plan, type_flip_after_move=True)
        with self.assertRaisesRegex(ValueError, "file type or creator"):
            control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        self.assertFalse(any(a["label"] == "move-1" for a in wire.actions))
        wire.close_all()

    def test_all_twelve_model_outcomes_and_raw_faults(self):
        wire = FakeWire(self.plan)
        result = control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        wire.close_all()
        report = {
            "status": "completed",
            "error": "",
            "views": result["views"],
            "results": result["results"],
            "progress": result["progress"],
            "events": wire.recorder.events,
            "frames": wire.frames,
            "actions": wire.actions,
            "streams": wire.recorder.streams(),
            "terminals": wire.terminals,
            "unparsed_hex": {"main": ""},
            "request_count": wire.request_count,
            "mutation_count": 20,
            "plan_sha256": cases.sha((json.dumps(self.plan, indent=2) + "\n").encode()),
            "cases_sha256": control.sha(
                __import__("pathlib").Path(cases.__file__).read_bytes()
            ),
            "source_sha256": control.sha(
                __import__("pathlib").Path(control.__file__).read_bytes()
            ),
            "oracle_sha256": control.ORACLE_SHA256,
        }
        control.verify_report(self.plan, report)
        self.assertEqual([r["index"] for r in result["results"]], list(range(12)))
        self.assertEqual(report["request_count"], 82)
        import copy

        faults = [
            lambda r: r["views"].pop(
                next(
                    i
                    for i, v in enumerate(r["views"])
                    if v["label"] == "after-view-0-H"
                )
            ),
            lambda r: r["results"][0].__setitem__("selected_parent", "wrapper"),
            lambda r: r["results"][6].__setitem__("value_hex", "00"),
            lambda r: r["frames"][0].__setitem__("arrival_elapsed_ns", 0),
            lambda r: r["frames"][0].__setitem__(
                "arrival_elapsed_ns", r["frames"][0]["arrival_elapsed_ns"] + 10**10
            ),
            lambda r: r["streams"]["main"].__setitem__("sent_hex", "00"),
            lambda r: r["actions"][7].__setitem__("elapsed_ns", 0),
            lambda r: r["actions"][7].__setitem__(
                "elapsed_ns", r["actions"][7]["elapsed_ns"] + 10**10
            ),
            lambda r: r["terminals"].__setitem__("main", "eof"),
            lambda r: r["unparsed_hex"].__setitem__("main", "00"),
            lambda r: r.__setitem__("source_sha256", "0" * 64),
            lambda r: next(
                v for v in r["views"] if v["label"] == "final-roster"
            ).__setitem__("uid", 8),
        ]
        for index, fault in enumerate(faults):
            with self.subTest(index=index), self.assertRaises((ValueError, KeyError)):
                changed = copy.deepcopy(report)
                fault(changed)
                control.verify_report(self.plan, changed)

    def test_missing_selected_readback_fails_before_later_move(self):
        wire = FakeWire(self.plan, missing_readback=True)
        with self.assertRaisesRegex(ValueError, "Marker outside selected"):
            control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        self.assertIn("move-0", wire.partial["progress"])
        self.assertFalse(any(a["label"] == "move-1" for a in wire.actions))
        wire.close_all()

    def test_late_cleanup_failure_keeps_all_twelve_results(self):
        wire = FakeWire(self.plan)
        original_send = wire.send

        def fail_cleanup(name, raw, label):
            if label == "remove-news-category":
                raise OSError("synthetic cleanup failure")
            return original_send(name, raw, label)

        cast(Any, wire).send = fail_cleanup
        with self.assertRaisesRegex(OSError, "synthetic cleanup failure"):
            control.perform(cast(control.Wire, wire), self.plan, lambda: None)
        self.assertEqual(len(wire.partial["results"]), 12)
        self.assertEqual(
            wire.partial["own_uid"],
            next(
                v["uid"]
                for v in wire.partial["views"]
                if v["label"] == "initial-roster"
            ),
        )
        self.assertIsNone(wire.partial["current_case_index"])
        self.assertEqual(wire.partial["mutation_count"], 17)
        self.assertEqual(wire.partial["request_count"], 74)
        wire.close_all()

    def test_real_socketpair_split_reply_and_partial_failure_tail(self):
        bounds = {
            "endpoint": self.plan["endpoint"],
            "schedule": {
                "max_bytes": 65536,
                "max_frames": 8,
                "max_tail_bytes_per_flow": 4096,
                "max_simultaneous": 1,
            },
        }
        wire = Wire(bounds, time.monotonic() + 3)
        owned, peer = socket.socketpair()
        owned.setblocking(False)
        wire.recorder.sockets["main"] = owned
        wire.buffers["main"] = bytearray()
        complete = bytes.fromhex(packet(0, 100, reply=1))
        partial = bytes.fromhex(packet(0, 101, reply=1))[:13]

        def transmit():
            peer.sendall(complete[:7])
            time.sleep(0.02)
            peer.sendall(complete[7:] + partial)
            peer.shutdown(socket.SHUT_WR)

        worker = threading.Thread(target=transmit)
        worker.start()
        try:
            wire.wait_for(lambda: bool(wire.match("main", 0, 100, 1)), 1, "split reply")
            wire.poll(0.1)
            self.assertEqual(bytes(wire.buffers["main"]), partial)
            self.assertEqual(
                wire.recorder.streams()["main"]["received_hex"],
                (complete + partial).hex(),
            )
            wire.close_all()
            self.assertEqual(wire.terminals["main"], "eof")
            self.assertEqual(owned.fileno(), -1)
        finally:
            worker.join(timeout=1)
            owned.close()
            peer.close()
        self.assertFalse(worker.is_alive())

    def test_runner_failure_retains_real_partial_bytes_and_closes_fd(self):
        with tempfile.TemporaryDirectory() as temp:
            base = Path(temp)
            plan_dir = base / "plan"
            cases.write_plan(plan_dir, ENV)
            receipt = base / "receipt.json"
            receipt.write_text(
                json.dumps(
                    {
                        "deadline_utc": datetime.fromtimestamp(
                            time.time() + 600, timezone.utc
                        ).isoformat(),
                        "emulator_pid": ENV["emulator_pid"],
                    }
                )
            )
            binary = base / "binary"
            binary.write_bytes(b"synthetic binary")
            bounds = {
                "endpoint": self.plan["endpoint"],
                "schedule": {
                    "max_bytes": 65536,
                    "max_frames": 8,
                    "max_tail_bytes_per_flow": 4096,
                    "max_simultaneous": 1,
                },
            }
            wire = control.Wire(bounds, time.monotonic() + 3)
            owned, peer = socket.socketpair()
            owned.setblocking(False)
            wire.recorder.sockets["main"] = owned
            wire.buffers["main"] = bytearray()
            partial = bytes.fromhex(packet(0, 101, reply=1))[:13]

            def fail_after_receive(actual, _plan, _guard):
                actual.partial = {
                    "views": [],
                    "results": [{"index": 0, "status": "incomplete"}],
                    "progress": ["before-info-0"],
                    "mutation_count": 12,
                    "own_uid": 7,
                    "current_case_index": 0,
                }
                peer.sendall(partial)
                peer.shutdown(socket.SHUT_WR)
                actual.poll(0.1)
                raise ValueError("synthetic incomplete response")

            try:
                with (
                    patch.object(control, "prepared", return_value=self.plan),
                    patch.object(control, "runtime_gate", return_value=None),
                    patch.object(control, "Wire", return_value=wire),
                    patch.object(control, "perform", side_effect=fail_after_receive),
                    patch.object(
                        control, "ORACLE_SHA256", control.sha(binary.read_bytes())
                    ),
                    patch.object(
                        control.os,
                        "stat",
                        return_value=type("S", (), {"st_ino": 456})(),
                    ),
                ):
                    report = control.run(plan_dir, receipt, binary, base / "result")
                self.assertEqual(report["status"], "failed")
                self.assertEqual(report["unparsed_hex"]["main"], partial.hex())
                self.assertEqual(report["results"][0]["index"], 0)
                self.assertEqual(report["current_case_index"], 0)
                self.assertEqual(owned.fileno(), -1)
                self.assertEqual(
                    json.loads((base / "result" / "report.json").read_text())["status"],
                    "failed",
                )
            finally:
                owned.close()
                peer.close()


if __name__ == "__main__":
    unittest.main()
