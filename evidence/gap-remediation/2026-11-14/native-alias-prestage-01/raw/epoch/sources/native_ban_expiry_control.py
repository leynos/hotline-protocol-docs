#!/usr/bin/env python3
"""Gate three finite native ban-expiry capture epochs; never wait through expiry."""

import argparse
import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import native_ban_expiry_cases as cases
from native_control_readiness import capture_gate, readiness
from protocol_capture import ORACLE_SHA256, Recorder, validate_plan, verify_capture
from verify_native_auth import ADMIN, reply, roster
from verify_native_shx import fields

EPOCH_CASES = {
    "first": cases.FIRST,
    "pre": ("pre-probe",),
    "post": ("post-probe",),
}
TEMP_TEXT = cases.TEMPORARY_NOTICE
MAX_WINDOW_SECONDS = 720
MAX_BRACKET_SECONDS = 20
PRE_EARLIEST = 1600
PRE_LATEST = 1700
POST_EARLIEST = 1900
POST_LATEST = 2400


def require(ok: bool, reason: str) -> None:
    """Raise a value error with the reason unless the condition holds."""
    if not ok:
        raise ValueError(reason)


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict:
    """Read a JSON file."""
    return json.loads(path.read_text())


def utc(value: str) -> datetime:
    """Parse an ISO timestamp that carries an offset and return it in UTC."""
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "Missing UTC offset")
    return result.astimezone(timezone.utc)


@dataclass(frozen=True)
class TimingBounds:
    """The host time bracket of the ban request and acknowledgement, with the emulator identity."""
    request_utc: datetime
    ack_utc: datetime
    image_inode: int
    emulator_pid: int
    emulator_start_ticks: int
    emulator_sha256: str
    namespace_inode: int

    @classmethod
    def from_json(cls, value: dict) -> "TimingBounds":
        """Build the bounds from their JSON form, requiring a short request to acknowledgement bracket."""
        result = cls(
            request_utc=utc(value["request_utc"]),
            ack_utc=utc(value["ack_utc"]),
            image_inode=int(value["image_inode"]),
            emulator_pid=int(value["emulator_pid"]),
            emulator_start_ticks=int(value["emulator_start_ticks"]),
            emulator_sha256=value["emulator_sha256"],
            namespace_inode=int(value["namespace_inode"]),
        )
        require(
            0
            <= (result.ack_utc - result.request_utc).total_seconds()
            <= MAX_BRACKET_SECONDS,
            "Ban insertion request/ACK bracket exceeds20s",
        )
        return result

    def to_json(self) -> dict:
        """Return the bounds in JSON form, with the note about guest clock progression."""
        return {
            "request_utc": self.request_utc.isoformat(),
            "ack_utc": self.ack_utc.isoformat(),
            "image_inode": self.image_inode,
            "emulator_pid": self.emulator_pid,
            "emulator_start_ticks": self.emulator_start_ticks,
            "emulator_sha256": self.emulator_sha256,
            "namespace_inode": self.namespace_inode,
            "native_getdatetime_note": "Host UTC brackets one guest GetDateTime call; one-second guest clock progression is an unverified assumption until read-only guest witness.",
        }

    def gate(self, phase: str, now: datetime, receipt: dict) -> dict:
        """Check a later probe against the bounds and the live emulator identity."""
        require(phase in {"pre", "post"}, "Only later probes use timing gate")
        require(
            (
                receipt["emulator_pid"],
                int(str(receipt["emulator_starttime"])),
                receipt["emulator_sha256"],
                receipt["owned_working_image_inode"],
                receipt["emulator_netns_inode"],
            )
            == (
                self.emulator_pid,
                self.emulator_start_ticks,
                self.emulator_sha256,
                self.image_inode,
                self.namespace_inode,
            ),
            "Guest/image identity changed during idle",
        )
        anchor = self.request_utc if phase == "pre" else self.ack_utc
        elapsed = (now - anchor).total_seconds()
        lower, upper = (
            (PRE_EARLIEST, PRE_LATEST)
            if phase == "pre"
            else (POST_EARLIEST, POST_LATEST)
        )
        require(
            lower <= elapsed < upper,
            f"{phase} host-time probe outside conservative window",
        )
        return {
            "phase": phase,
            "host_elapsed_seconds": elapsed,
            "host_window": [lower, upper],
            "native_getdatetime_seconds_proven": False,
            "interpretation": "host-relative bracket only; guest clock progression requires separately retained read-only witness",
        }


def field_map(frame: dict) -> dict[int, bytes]:
    """Return a frame's fields by identifier, refusing duplicates."""
    result = fields(frame)
    require(len(result) == len(frame["fields"]), "Duplicate frame field")
    return result


def relevant(
    report: dict,
    connection: str,
    *,
    kind: int | None = None,
    identifier: int | None = None,
    reply_marker: int | None = None,
) -> list[dict]:
    """Select a connection's frames by type, identifier and reply marker."""
    return [
        f
        for f in report["frames"]
        if f["connection"] == connection
        and (kind is None or f["type"] == kind)
        and (identifier is None or f["id"] == identifier)
        and (reply_marker is None or f["is_reply"] == reply_marker)
    ]


def identity_before_110(
    frames: list[dict], saved_uid: bytes, *, protected: bool
) -> None:
    """Check the administrator and target logins before the kick request and the target's identity."""
    report = {"frames": frames}
    main = relevant(report, "main")
    target = relevant(report, "target")
    require(len(main) >= 5 and len(target) >= 3, "Missing admin or target login")
    require(
        main[0]["error"] == 0 and main[0]["is_reply"] == 1,
        "Administrator Login107 failed",
    )
    admin_access = field_map(main[1]).get(110, b"")
    require(
        main[1]["type"] == 354
        and admin_access == ADMIN
        and bool(int.from_bytes(admin_access, "big") & (1 << (63 - 22))),
        "Administrator privilege22 absent",
    )
    expected_access = cases.PROTECTED_ACCESS if protected else cases.ZERO_ACCESS
    require(
        target[0]["error"] == 0
        and target[0]["is_reply"] == 1
        and target[1]["type"] == 354
        and field_map(target[1]) == {110: expected_access}
        and target[2]["type"] == 109,
        "Target 354/access/agreement differs",
    )
    joins = [f for f in main if f["type"] == 301 and not f["is_reply"]]
    require(len(joins) == 1, "Target 301 absent or ambiguous")
    announced = field_map(joins[0])
    expected_name = cases.PROTECTED_NAME if protected else cases.ZERO_NAME
    require(
        announced.get(103) == saved_uid
        and announced.get(102) == expected_name
        and len(saved_uid) == 2
        and int.from_bytes(saved_uid, "big") > 0,
        "Saved current target UID/name differs",
    )
    snapshots = [f for f in main if f["is_reply"] and f["id"] == 32]
    require(len(snapshots) == 1, "Current roster missing")
    rows = roster(snapshots[0])
    require(
        len(rows) == 2
        and sum(
            r["uid"] == int.from_bytes(saved_uid, "big")
            and r["name_hex"] == expected_name.hex()
            for r in rows
        )
        == 1,
        "Current roster target identity differs",
    )
    require(
        any(
            r["name_hex"] == b"framing-fixture".hex()
            and r["uid"] != int.from_bytes(saved_uid, "big")
            for r in rows
        ),
        "Current admin and target roster identities overlap",
    )


def account_gate(report: dict, name: str) -> None:
    """Check that the guard found no account, or that the seed created one."""
    key, expected_name, access = (
        (cases.ZERO_KEY, cases.ZERO_NAME, cases.ZERO_ACCESS)
        if name.endswith("zero")
        else (cases.PROTECTED_KEY, cases.PROTECTED_NAME, cases.PROTECTED_ACCESS)
    )
    if name.startswith("guard"):
        frame = reply(report, 30)
        require(
            frame["error"] == 1
            and field_map(frame)
            == {100: b"No account with login \xd2" + key + b"\xd3."},
            "Owned account key already exists",
        )
    else:
        require(reply(report, 31)["error"] == 0, "Owned account create failed")
        frame = reply(report, 32)
        require(
            frame["error"] == 0
            and field_map(frame)
            == {
                102: expected_name,
                105: bytes(v ^ 255 for v in key),
                106: b"x",
                110: access,
            },
            "Owned account readback/access differs",
        )


def probe_gate(report: dict, accepted: bool) -> None:
    """Check that a probe login was accepted or refused as expected."""
    response = reply(report, 1)
    if accepted:
        require(
            response["type"] == 0 and response["error"] == 0,
            "Fresh controlled Login107 did not succeed",
        )
        values = relevant(report, "main", kind=354, reply_marker=0)
        require(
            len(values) == 1 and field_map(values[0]) == {110: cases.ZERO_ACCESS},
            "Fresh target effective access differs",
        )
        require(
            len(relevant(report, "main", kind=109, reply_marker=0)) == 1,
            "Fresh agreement missing",
        )
        snapshots = [f for f in relevant(report, "main", identifier=40, reply_marker=1)]
        require(
            len(snapshots) == 1
            and any(
                r["name_hex"] == cases.ZERO_NAME.hex() for r in roster(snapshots[0])
            ),
            "Fresh roster lacks owned target",
        )
    else:
        require(
            response["type"] == 0
            and response["error"] == 1
            and field_map(response) == {100: TEMP_TEXT},
            "Fresh Login107 temporary-ban error differs",
        )
        # Only the correlated Login107 reply is claimed. The complete TCP
        # capture, not this parsed-frame list, bounds any later observed tail.
    sends = [e["hex"] for e in report["events"] if e["event"] == "send"]
    require(
        len(sends) == (3 if accepted else 2)
        and sends[0] == "54525450484f544c00010002"
        and sends[1]
        == cases.authentication(
            cases.ZERO_KEY, cases.ZERO_PASSWORD, name=cases.ZERO_NAME
        )["hex"],
        "Fresh TRTP/107 vector differs",
    )


def outcome_gate(report: dict, name: str) -> None:
    """Check that a case completed and met the gate for its kind."""
    require(
        report["status"] == "completed"
        and report["completed_actions"] == len(cases.plans()[name]),
        f"{name} capture incomplete",
    )
    if name.startswith(("guard", "seed")):
        account_gate(report, name)
    elif name.endswith("probe"):
        probe_gate(report, name in {"kick0-probe", "post-probe"})
    elif name == "protected":
        identity_before_110(
            report["frames"],
            bytes.fromhex(report["variables"]["target_uid"]),
            protected=True,
        )
        error = reply(report, 33)
        text = field_map(error).get(100, b"")
        require(
            error["error"] == 1 and b"protected" in text.lower(),
            "Protected target kick was not rejected",
        )
        require(
            reply(report, 80, "target")["error"] == 0
            and not relevant(report, "target", kind=104)
            and not any(
                e["connection"] == "target" and e["event"] == "eof"
                for e in report["events"]
            ),
            "Protected target did not remain live",
        )
        require(
            any(
                e["connection"] == "target" and e["event"] == "quiet"
                for e in report["events"]
            ),
            "Protected target lacked post-500 bounded quiet barrier",
        )
    elif name in {"kick0", "tempban"}:
        identity_before_110(
            report["frames"],
            bytes.fromhex(report["variables"]["target_uid"]),
            protected=False,
        )
        target_notice = relevant(report, "target", kind=104, reply_marker=0)
        require(
            len(target_notice) == int(name == "tempban"),
            "Kick notice cardinality differs",
        )
        if name == "tempban":
            require(
                field_map(target_notice[0]) == {101: TEMP_TEXT},
                "Temporary notice text differs",
            )
        require(
            any(
                e["connection"] == "target" and e["event"] == "eof"
                for e in report["events"]
            ),
            "Kicked target EOF absent",
        )
        require(
            reply(report, 33)["error"] == 0
            and len(relevant(report, "main", kind=302, reply_marker=0)) == 1,
            "Requester ACK/departure differs",
        )
    else:
        raise ValueError("Unrecognised expiry fixture case")


def plan_gate(plan_path: Path) -> tuple[dict, str]:
    """Check that a prepared plan is the expected one and return it with its case name."""
    raw = plan_path.read_bytes()
    value = load(plan_path)
    name = value["expectation"]["case"]
    require(
        name in cases.plans() and plan_path.name == f"{name}.json",
        "Unexpected plan case",
    )
    validate_plan(value)
    require(
        value == cases.plan(name, cases.plans()[name], value["environment"], 15800),
        "Prepared plan changed",
    )
    hashes = load(plan_path.parent / "source-hashes.json")
    require(hashes[name] == digest(raw), "Prepared source plan hash changed")
    return value, name


def live_service(meta: dict, deadline_utc: datetime) -> None:
    """Check that the managed unit is running with the expected limits before the deadline."""
    unit = meta["unit"]
    require(
        unit.startswith("mothra-") and unit.endswith(".service"),
        "Unexpected managed unit",
    )
    command = [
        "systemctl",
        "show",
        unit,
        "--no-pager",
        "--property=ActiveState,SubState,MainPID,RuntimeMaxUSec,ActiveEnterTimestampMonotonic,KillMode",
    ]
    output = subprocess.run(command, capture_output=True, text=True, check=True).stdout
    actual = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    require(
        actual == meta["unit_properties"]
        and actual["ActiveState"] == "active"
        and actual["SubState"] == "running"
        and actual["MainPID"] == str(meta["pid"])
        and actual["KillMode"] == "control-group"
        and actual["RuntimeMaxUSec"] == "15min",
        "Managed service changed",
    )
    remaining_us = (
        deadline_utc - datetime.now(timezone.utc)
    ).total_seconds() * 1_000_000
    expiry = int(actual["ActiveEnterTimestampMonotonic"]) + 900_000_000
    require(
        expiry - time.monotonic_ns() // 1000 >= remaining_us + 5_000_000,
        "Managed service expires before epoch deadline",
    )


def namespace_gate(receipt: dict) -> None:
    """Re-read recorder placement and routes in its actual network namespace."""
    recorder_pid = receipt["namespace_recorder_pid"]
    emulator_pid = receipt["emulator_pid"]
    expected = receipt["emulator_netns_inode"]
    require(
        os.stat(f"/proc/{recorder_pid}/ns/net").st_ino
        == os.stat(f"/proc/{emulator_pid}/ns/net").st_ino
        == expected,
        "Namespace recorder is not in the emulator namespace",
    )
    prefix = ["/usr/sbin/nsenter", "-t", str(recorder_pid), "-n", "/usr/sbin/ip", "-j"]
    for family in ("-4", "-6"):
        output = subprocess.run(
            [*prefix, family, "route", "show", "table", "main"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        ).stdout
        require(json.loads(output) == [], f"Live {family} namespace routes changed")
    output = subprocess.run(
        [*prefix, "link", "show"],
        capture_output=True,
        text=True,
        check=True,
        timeout=5,
    ).stdout
    require(
        [link["ifname"] for link in json.loads(output)] == ["lo"],
        "Live namespace has a non-loopback interface",
    )


def settle_first_epoch(summary: dict, deadline_utc: datetime) -> None:
    """Leave a socket-free margin after readiness before the account cases."""
    started = datetime.now(timezone.utc)
    require(
        (deadline_utc - started).total_seconds() >= 45,
        "Insufficient epoch deadline for35s post-readiness settling",
    )
    started_ns = time.monotonic_ns()
    settle: dict[str, str | float | int] = {"started_utc": started.isoformat()}
    summary["post_readiness_settle"] = settle
    time.sleep(35)
    elapsed = (time.monotonic_ns() - started_ns) / 1_000_000_000
    settle.update(
        completed_utc=datetime.now(timezone.utc).isoformat(),
        elapsed_seconds=elapsed,
        runner_socket_actions_during_wait=0,
    )
    require(
        elapsed >= 35
        and (deadline_utc - datetime.now(timezone.utc)).total_seconds() > 10,
        "Post-readiness settling incomplete or epoch deadline reached",
    )


def runtime_gate(receipt: dict, env: dict, deadline_utc: datetime) -> None:
    """Check that the runtime receipt matches the plan and the live emulator."""
    require(os.geteuid() == 0, "Live runner requires root for /proc identity")
    require(
        all(
            receipt[key] == env[key]
            for key in (
                "emulator_pid",
                "emulator_starttime",
                "emulator_sha256",
                "emulator_netns_inode",
                "owned_working_image",
                "owned_working_image_inode",
            )
        ),
        "Runtime receipt differs from plan",
    )
    require(
        os.stat("/proc/self/ns/net").st_ino == receipt["emulator_netns_inode"],
        "Runner is not in the emulator network namespace",
    )
    capture_gate(receipt)
    namespace_gate(receipt)
    require(
        os.readlink(f"/proc/{receipt['emulator_pid']}/fd/16") == receipt["guest_pcap"],
        "Guest PCAP FD changed",
    )
    image = Path(receipt["owned_working_image"])
    require(
        image.stat().st_ino == receipt["owned_working_image_inode"],
        "Working-image inode changed",
    )
    require(
        (deadline_utc - datetime.now(timezone.utc)).total_seconds() > 10,
        "Epoch deadline too close",
    )
    require(
        (deadline_utc - utc(receipt["epoch_started_utc"])).total_seconds()
        <= MAX_WINDOW_SECONDS,
        "Epoch exceeds12min",
    )
    for label in ("host", "namespace"):
        meta = receipt["managed_capture"][label]
        require(
            meta["pid"] == receipt[f"{label}_recorder_pid"]
            and meta["deadline_utc"] == deadline_utc.isoformat()
            and meta["fd"] >= 0
            and meta["unit_properties"]["MainPID"] == str(meta["pid"])
            and meta["unit_properties"]["ActiveState"] == "active"
            and meta["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and meta["unit_properties"]["KillMode"] == "control-group",
            "Managed recorder receipt differs",
        )
        live_service(meta, deadline_utc)
        capture = Path(receipt[f"{label}_pcap"])
        fd = Path(f"/proc/{meta['pid']}/fd/{meta['fd']}")
        require(
            fd.stat().st_ino == capture.stat().st_ino
            and fd.stat().st_dev == capture.stat().st_dev,
            "Managed recorder lost writable capture FD",
        )
        flags = int(
            next(
                line.split()[1]
                for line in Path(f"/proc/{meta['pid']}/fdinfo/{meta['fd']}")
                .read_text()
                .splitlines()
                if line.startswith("flags:")
            ),
            8,
        )
        require(
            flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR),
            "Capture FD is not writable",
        )
    lock = receipt["managed_lock"]
    require(
        lock["pid"] > 0
        and lock["fd"] >= 0
        and lock["busy_exit"] == 1
        and lock["unit_properties"]["ActiveState"] == "active"
        and lock["unit_properties"]["MainPID"] == str(lock["pid"]),
        "Managed oracle lease not proven busy",
    )
    live_service(lock, deadline_utc)
    expected_lock = Path(receipt["oracle_lock"])
    lock_fd = Path(f"/proc/{lock['pid']}/fd/{lock['fd']}")
    require(
        (lock_fd.stat().st_dev, lock_fd.stat().st_ino)
        == (expected_lock.stat().st_dev, expected_lock.stat().st_ino),
        "Managed lock FD inode changed",
    )
    busy = subprocess.run(
        ["flock", "--exclusive", "--nonblock", str(expected_lock), "true"], check=False
    ).returncode
    require(busy == 1, "Canonical oracle mutex is not busy")


def run_case(plan: dict, name: str, output: Path, epoch_deadline: datetime) -> dict:
    """Run one case; preserve partial events and every read byte on failure."""
    output.mkdir(parents=True, exist_ok=False)
    recorder = Recorder(plan)
    completed = 0
    status = "completed"
    error = ""
    try:
        for index, step in enumerate(plan["steps"]):
            remaining = min(
                (epoch_deadline - datetime.now(timezone.utc)).total_seconds(),
                MAX_WINDOW_SECONDS - (time.monotonic_ns() - recorder.started) / 1e9,
            )
            require(remaining > 0, "Epoch or case exceeded12min")
            step = {**step, "timeout": min(step.get("timeout", 2), remaining)}
            encoded = step.get("hex")
            if (
                step["op"] == "send"
                and isinstance(encoded, str)
                and encoded.startswith("0000006e00000021")
            ):
                identity_before_110(
                    recorder.frames,
                    recorder.variables.get("target_uid", b""),
                    protected=name == "protected",
                )
            recorder.execute(index, step)
            completed += 1
    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        IndexError,
        TimeoutError,
        KeyboardInterrupt,
    ) as failure:
        status, error = "failed", f"{type(failure).__name__}: {failure}"
    finally:
        for label, sock in list(recorder.sockets.items()):
            sock.close()
            recorder.event(completed, label, "close")
    result = {
        "schema_version": 1,
        "status": status,
        "case": name,
        "profile": "control-only",
        "full_file_baseline": "not_exercised",
        "oracle_sha256": ORACLE_SHA256,
        "started_at_utc": recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "completed_actions": completed,
        "error": error,
        "variables": {key: value.hex() for key, value in recorder.variables.items()},
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }
    if status == "completed":
        try:
            outcome_gate(result, name)
        except (ValueError, KeyError, IndexError) as failure:
            result["status"] = "failed"
            result["error"] = f"{type(failure).__name__}: {failure}"
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")
    (output / "report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def ban_timing(report: dict, receipt: dict) -> TimingBounds:
    """Return the time bracket of the temporary ban's request and acknowledgement."""
    require(
        report["case"] == "tempban" and report["status"] == "completed",
        "No completed option-one case",
    )
    steps = cases.plans()["tempban"]
    request_index = next(
        i
        for i, s in enumerate(steps)
        if s["op"] == "send" and s["hex"].startswith("0000006e00000021")
    )
    ack_index = next(
        i
        for i, s in enumerate(steps)
        if i > request_index
        and s["op"] == "read_frame"
        and s.get("match_frame", {}).get("id") == 33
    )
    sends = [
        e
        for e in report["events"]
        if e["action"] == request_index and e["event"] == "send"
    ]
    receives = [
        e
        for e in report["events"]
        if e["action"] == ack_index and e["event"] == "receive"
    ]
    require(bool(sends and receives), "Missing wire request/ACK bracket")
    origin = utc(report["started_at_utc"])
    result = TimingBounds(
        request_utc=origin
        + timedelta(microseconds=min(e["elapsed_ns"] for e in sends) // 1000),
        ack_utc=origin
        + timedelta(microseconds=max(e["elapsed_ns"] for e in receives) // 1000),
        image_inode=receipt["owned_working_image_inode"],
        emulator_pid=receipt["emulator_pid"],
        emulator_start_ticks=receipt["emulator_starttime"],
        emulator_sha256=receipt["emulator_sha256"],
        namespace_inode=receipt["emulator_netns_inode"],
    )
    return TimingBounds.from_json(result.to_json())


def run_epoch(
    phase: str,
    plans_dir: Path,
    readiness_dir: Path | None,
    receipt_path: Path,
    binary: Path,
    output: Path,
    *,
    bounds_path: Path | None = None,
) -> dict:
    """Run the cases of one expiry epoch under the gates and write the result."""
    require(phase in EPOCH_CASES, "Unknown expiry epoch")
    receipt = load(receipt_path)
    first = load(plans_dir / f"{EPOCH_CASES[phase][0]}.json")
    deadline = utc(receipt["deadline_utc"])
    runtime_gate(receipt, first["environment"], deadline)
    require(
        digest(binary.read_bytes()) == ORACLE_SHA256, "Native binary identity differs"
    )
    readiness_sha = None
    if phase == "first":
        if readiness_dir is None:
            raise ValueError("First epoch requires full18 readiness")
        ready_plan = load(readiness_dir / "plan.json")
        ready_report = verify_capture(readiness_dir)
        require(
            ready_plan == load(plans_dir / "readiness.json"),
            "Control-only readiness plan changed",
        )
        require(
            ready_report["oracle_sha256"] == ORACLE_SHA256,
            "Readiness oracle differs",
        )
        readiness(ready_report)
        readiness_sha = digest((readiness_dir / "report.json").read_bytes())
    else:
        require(
            readiness_dir is None,
            "Later epoch must not perform a prior Login107 readiness",
        )
    bounds = None
    timing_result = None
    if phase != "first":
        if bounds_path is None:
            raise ValueError("Later probe requires frozen ban time bracket")
        bounds = TimingBounds.from_json(load(bounds_path))
        timing_result = bounds.gate(phase, datetime.now(timezone.utc), receipt)
    output.mkdir(parents=True, exist_ok=False)
    summary = {
        "phase": phase,
        "status": "completed",
        "full_file_baseline": "not_exercised",
        "capture_receipt_sha256": digest(receipt_path.read_bytes()),
        "readiness_report_sha256": readiness_sha,
        "preprobe_baseline": {
            "first": "full18_control_only",
            "pre": "not_exercised_ban_active",
            "post": "not_exercised_preserve_first_lookup",
        }[phase],
        "cases": {},
        "timing_gate": timing_result,
    }
    try:
        if phase == "first":
            settle_first_epoch(summary, deadline)
        for name in EPOCH_CASES[phase]:
            runtime_gate(receipt, first["environment"], deadline)
            planned, actual = plan_gate(plans_dir / f"{name}.json")
            require(
                actual == name and planned["environment"] == first["environment"],
                "Case order/runtime differs",
            )
            report = run_case(planned, name, output / name, deadline)
            summary["cases"][name] = {
                "status": report["status"],
                "error": report["error"],
                "plan_sha256": digest((plans_dir / f"{name}.json").read_bytes()),
            }
            require(report["status"] == "completed", f"{name}: {report['error']}")
            if name == "tempban":
                bracket = ban_timing(report, receipt)
                (output / "ban-clock.json").write_text(
                    json.dumps(bracket.to_json(), indent=2) + "\n"
                )
    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        IndexError,
        TimeoutError,
        KeyboardInterrupt,
    ) as failure:
        summary["status"] = "failed"
        summary["error"] = f"{type(failure).__name__}: {failure}"
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return summary


def main() -> None:
    """Parse the command line, run the epoch and print the result."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--phase", choices=tuple(EPOCH_CASES), required=True)
    parser.add_argument("--plans", type=Path, required=True)
    parser.add_argument("--readiness-dir", type=Path)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--ban-clock", type=Path)
    args = parser.parse_args()
    result = run_epoch(
        args.phase,
        args.plans,
        args.readiness_dir,
        args.capture_receipt,
        args.binary,
        args.output,
        bounds_path=args.ban_clock,
    )
    print(json.dumps(result, indent=2))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
