#!/usr/bin/env python3
"""One-use isolated Classic Login107 ACK proxy with fixed local routes."""

import argparse
import hashlib
import json
import os
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path

from native_plan import packet, payload
from protocol_capture import decode_frame

CLIENT_HELLO = bytes.fromhex("54525450484f544c00010002")
SERVER_HELLO = bytes.fromhex("5452545000000000")
VARIANTS = ("baseline", "omit-161", "one-byte-161", "four-byte-161")
MAX_FRAME = 65535
IP_BIN = "/usr/sbin/ip"
DEADLINE_SECONDS = 180
OBSERVATION_SECONDS = 28
MAX_OBSERVATION_NS = 30_000_000_000
BACKENDS = {"control": 15500, "data": 15501}
LISTENERS = {"control": 15652, "data": 15653}


def parse_frame(raw: bytes) -> dict:
    if len(raw) < 22:
        raise ValueError("Short control frame")
    _, reply, _, _, _, total, size = struct.unpack(">BBHIIII", raw[:20])
    if (
        reply not in (0, 1)
        or total != size
        or size > MAX_FRAME
        or len(raw) != 20 + size
    ):
        raise ValueError("Fragmented, oversized or malformed control frame")
    frame = decode_frame(raw)
    fields = frame.get("fields", [])
    if frame.get("declared_field_count") != len(fields) or frame.get("unconsumed_hex"):
        raise ValueError("Malformed control TLV sequence")
    frame["fields"] = [(item["id"], bytes.fromhex(item["hex"])) for item in fields]
    return frame


def transform_ack(raw: bytes, login_id: int, variant: str) -> bytes:
    if variant not in VARIANTS:
        raise ValueError("Unknown variant")
    frame = parse_frame(raw)
    if (frame["is_reply"], frame["type"], frame["id"], frame["error"]) != (
        1,
        0,
        login_id,
        0,
    ):
        raise ValueError("First server frame is not successful Login107 ACK")
    values = [value for key, value in frame["fields"] if key == 161]
    if values != [b"\x00\x00"]:
        raise ValueError("Native 161 source is not exactly two zero bytes")
    replacement = {
        "baseline": b"\x00\x00",
        "omit-161": None,
        "one-byte-161": b"\x00",
        "four-byte-161": b"\x00" * 4,
    }[variant]
    if replacement is None:
        frame["fields"] = [(key, value) for key, value in frame["fields"] if key != 161]
    else:
        frame["fields"] = [
            (key, replacement if key == 161 else value)
            for key, value in frame["fields"]
        ]
    result = bytes.fromhex(
        packet(
            frame["type"],
            frame["id"],
            payload(frame["fields"]),
            flags=frame["flags"],
            reply=frame["is_reply"],
            error=frame["error"],
        )
    )
    if variant == "baseline" and result != raw:
        raise ValueError("Baseline ACK reconstruction differs")
    return result


class Audit:
    def __init__(self, deadline: float, max_log: int = 800_000) -> None:
        self.deadline = deadline
        self.max_log = max_log
        self.entries: list[dict] = []
        self.used = 0
        self.lock = threading.Lock()
        self.abort = threading.Event()
        self.cutoff = threading.Event()

    def check(self) -> None:
        if self.cutoff.is_set():
            raise ObservationCutoff("Intentional observation cutoff")
        if time.monotonic() >= self.deadline:
            raise TimeoutError("Proxy process deadline exceeded")
        if self.abort.is_set():
            raise RuntimeError("Proxy stopped after peer failure")

    def record(self, event: str, raw: bytes, forwarded: bytes) -> None:
        self.check()
        entry = {
            "event": event,
            "timestamp_us": time.time_ns() // 1000,
            "raw_hex": raw.hex(),
            "forwarded_hex": forwarded.hex(),
        }
        cost = len(json.dumps(entry).encode()) + 2
        with self.lock:
            if self.used + cost > self.max_log:
                raise ValueError("Aggregate proxy log exceeds bound")
            self.entries.append(entry)
            self.used += cost


class ObservationCutoff(RuntimeError):
    """Owned sockets were intentionally closed at the observation deadline."""


class ObservationWatchdog:
    def __init__(self, audit: Audit, close_owned, clock_ns=time.monotonic_ns) -> None:
        self.audit = audit
        self.close_owned = close_owned
        self.clock_ns = clock_ns
        self.lock = threading.Lock()
        self.state = "waiting"
        self.ack_ns: int | None = None
        self.due_ns: int | None = None
        self.actual_ns: int | None = None
        self.closed_ns: int | None = None
        self.teardown_ns: int | None = None
        self.raw_sha256: str | None = None
        self.forwarded_sha256: str | None = None
        self.error: str | None = None

    def arm(self, raw: bytes, forwarded: bytes) -> None:
        self.audit.check()
        with self.lock:
            if self.state != "waiting":
                raise ValueError("Observation watchdog armed twice")
            self.ack_ns = self.clock_ns()
            self.due_ns = self.ack_ns + OBSERVATION_SECONDS * 1_000_000_000
            self.raw_sha256 = hashlib.sha256(raw).hexdigest()
            self.forwarded_sha256 = hashlib.sha256(forwarded).hexdigest()
            self.state = "armed"

    def tick(self) -> bool:
        with self.lock:
            if (
                self.state != "armed"
                or self.due_ns is None
                or self.clock_ns() < self.due_ns
            ):
                return False
            self.state = "fired"
            self.actual_ns = self.clock_ns()
            self.audit.cutoff.set()
        try:
            self.close_owned()
        except Exception as exc:  # noqa: BLE001 - watchdog failure must invalidate run
            self.error = f"{type(exc).__name__}: {exc}"
            self.audit.abort.set()
        finally:
            self.closed_ns = self.clock_ns()
        return True

    def cancel(self) -> None:
        with self.lock:
            if self.state in {"waiting", "armed"}:
                self.state = "cancelled"

    def mark_teardown(self) -> None:
        self.teardown_ns = self.clock_ns()

    def run(self) -> None:
        while not self.audit.abort.is_set():
            if self.tick() or self.state == "cancelled":
                return
            time.sleep(0.05)

    def receipt(self) -> dict:
        valid = (
            self.ack_ns is not None
            and self.closed_ns is not None
            and self.teardown_ns is not None
            and self.teardown_ns - self.ack_ns <= MAX_OBSERVATION_NS
            and self.error is None
        )
        return {
            "state": self.state,
            "ack_sent_monotonic_ns": self.ack_ns,
            "cutoff_due_ns": self.due_ns,
            "cutoff_actual_ns": self.actual_ns,
            "last_owned_socket_close_ns": self.closed_ns,
            "relay_teardown_ns": self.teardown_ns,
            "valid_30_seconds": valid,
            "raw_ack_sha256": self.raw_sha256,
            "forwarded_ack_sha256": self.forwarded_sha256,
            "error": self.error,
        }


def read_exact(
    peer: socket.socket, size: int, audit: Audit, *, allow_eof: bool = False
) -> bytes | None:
    data = bytearray()
    while len(data) < size:
        audit.check()
        try:
            chunk = peer.recv(size - len(data))
        except TimeoutError:
            continue
        if not chunk:
            if allow_eof and not data:
                return None
            raise EOFError("Socket closed inside required bytes")
        data.extend(chunk)
    return bytes(data)


def read_frame(peer: socket.socket, audit: Audit) -> bytes | None:
    header = read_exact(peer, 20, audit, allow_eof=True)
    if header is None:
        return None
    size = int.from_bytes(header[16:20], "big")
    if size > MAX_FRAME:
        raise ValueError("Control frame exceeds bound")
    body = read_exact(peer, size, audit)
    assert body is not None
    raw = header + body
    parse_frame(raw)
    return raw


def relay_frames(
    source: socket.socket,
    destination: socket.socket,
    audit: Audit,
    label: str,
    login_id: int | None,
    variant: str,
    ack_forwarded: threading.Event | None = None,
    on_ack=None,
) -> None:
    first = True
    while raw := read_frame(source, audit):
        forwarded = raw
        if label == "server" and first:
            if login_id is None:
                raise ValueError("Missing observed login ID")
            forwarded = transform_ack(raw, login_id, variant)
        audit.record(label, raw, forwarded)
        destination.sendall(forwarded)
        if label == "server" and first:
            if on_ack is not None:
                on_ack(raw, forwarded)
            if ack_forwarded is not None:
                ack_forwarded.set()
        first = False
    if label == "server" and first:
        raise ValueError("Missing successful Login107 ACK")
    destination.shutdown(socket.SHUT_WR)


def relay_data(
    source: socket.socket, destination: socket.socket, audit: Audit, label: str
) -> None:
    while True:
        audit.check()
        try:
            chunk = source.recv(4096)
        except TimeoutError:
            continue
        if not chunk:
            destination.shutdown(socket.SHUT_WR)
            return
        audit.record(label, chunk, chunk)
        destination.sendall(chunk)


def namespace_guard(expected_netns: int, host_netns: int) -> int:
    if min(expected_netns, host_netns) <= 0 or expected_netns == host_netns:
        raise ValueError("Expected and host namespace inodes must be distinct")
    own = os.stat("/proc/self/ns/net").st_ino
    if own != expected_netns or own == host_netns:
        raise ValueError("Proxy network namespace identity differs")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        raise ValueError("Namespace has non-loopback interface")
    for family in ([], ["-6"]):
        result = subprocess.run(
            [IP_BIN, "-j", *family, "route", "show", "table", "main"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        if json.loads(result.stdout) != []:
            raise ValueError("Namespace has nonlocal route")
    return own


def accept_one(
    listener: socket.socket, audit: Audit, stop: threading.Event | None = None
) -> socket.socket | None:
    while True:
        audit.check()
        if stop is not None and stop.is_set():
            return None
        try:
            client, _ = listener.accept()
            client.settimeout(0.25)
            return client
        except TimeoutError:
            continue


def serve(variant: str, output: Path, expected_netns: int, host_netns: int) -> dict:
    if variant not in VARIANTS:
        raise ValueError("Unknown variant")
    netns = namespace_guard(expected_netns, host_netns)
    output.mkdir(parents=True, exist_ok=False)
    audit = Audit(time.monotonic() + DEADLINE_SECONDS)
    sockets: list[socket.socket] = []
    sockets_lock = threading.Lock()
    errors: list[str] = []
    control_done = threading.Event()
    ack_forwarded = threading.Event()

    def close_owned() -> None:
        with sockets_lock:
            owned = tuple(sockets)
        for peer in owned:
            peer.close()

    watchdog = ObservationWatchdog(audit, close_owned)

    def track(peer: socket.socket) -> socket.socket:
        with sockets_lock:
            if audit.cutoff.is_set() or audit.abort.is_set():
                peer.close()
                raise ObservationCutoff("Owned socket created after cutoff")
            sockets.append(peer)
        peer.settimeout(0.25)
        return peer

    def guarded(action) -> None:
        try:
            action()
        except Exception as exc:  # noqa: BLE001 - thread failure must invalidate run
            if audit.cutoff.is_set() and isinstance(exc, (ObservationCutoff, OSError)):
                return
            errors.append(f"{type(exc).__name__}: {exc}")
            audit.abort.set()
            close_owned()

    def pair(
        source: socket.socket,
        target: socket.socket,
        raw: bool,
        login_id: int | None = None,
    ) -> None:
        def forward(src: socket.socket, dst: socket.socket, index: int) -> None:
            if raw:
                relay_data(src, dst, audit, ("data-client", "data-server")[index])
            else:
                relay_frames(
                    src,
                    dst,
                    audit,
                    ("client", "server")[index],
                    login_id if index else None,
                    variant,
                    ack_forwarded,
                    watchdog.arm if index else None,
                )

        actions = (
            lambda: forward(source, target, 0),
            lambda: forward(target, source, 1),
        )
        threads = [
            threading.Thread(target=guarded, args=(action,), daemon=True)
            for action in actions
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(max(0, audit.deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads) or errors:
            raise RuntimeError("Relay failed or exceeded process deadline")

    def data(listener: socket.socket) -> None:
        client = accept_one(listener, audit, control_done)
        if client is None:
            return
        track(client)
        listener.close()
        if not ack_forwarded.is_set():
            raise ValueError("Data connection preceded successful Login107 ACK")
        backend = track(
            socket.create_connection(("127.0.0.1", BACKENDS["data"]), timeout=2)
        )
        pair(client, backend, True)

    report = {
        "status": "failed",
        "variant": variant,
        "netns_inode": netns,
        "expected_netns_inode": expected_netns,
        "host_netns_inode": host_netns,
        "routes": BACKENDS,
        "listeners": LISTENERS,
        "deadline_seconds": DEADLINE_SECONDS,
    }
    data_thread: threading.Thread | None = None
    timer_thread = threading.Thread(target=guarded, args=(watchdog.run,), daemon=True)
    timer_thread.start()
    try:
        listeners = {}
        for name, port in LISTENERS.items():
            listener = track(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind(("127.0.0.1", port))
            listener.listen(1)
            listeners[name] = listener
        (output / "ready.json").write_text(
            json.dumps(report | {"status": "ready"}) + "\n"
        )
        client = accept_one(listeners["control"], audit)
        if client is None:
            raise ValueError("Missing control connection")
        track(client)
        listeners["control"].close()
        data_thread = threading.Thread(
            target=guarded, args=(lambda: data(listeners["data"]),), daemon=True
        )
        data_thread.start()
        try:
            backend = track(
                socket.create_connection(("127.0.0.1", BACKENDS["control"]), timeout=2)
            )
            hello = read_exact(client, 12, audit)
            if hello != CLIENT_HELLO:
                raise ValueError("Classic handshake differs")
            audit.record("client-handshake", hello, hello)
            backend.sendall(hello)
            answer = read_exact(backend, 8, audit)
            if answer != SERVER_HELLO:
                raise ValueError("Native handshake differs")
            audit.record("server-handshake", answer, answer)
            client.sendall(answer)
            login = read_frame(client, audit)
            if login is None:
                raise ValueError("Missing Login107 request")
            parsed = parse_frame(login)
            if parsed["type"] != 107 or parsed["is_reply"] != 0 or parsed["error"] != 0:
                raise ValueError("First client frame is not Login107")
            audit.record("login-request", login, login)
            backend.sendall(login)
            pair(client, backend, False, parsed["id"])
        finally:
            control_done.set()
            if watchdog.state != "fired":
                watchdog.cancel()
        data_thread.join(max(0, audit.deadline - time.monotonic()))
        timer_thread.join(1)
        if (
            data_thread.is_alive()
            or timer_thread.is_alive()
            or not ack_forwarded.is_set()
            or errors
            or watchdog.error
        ):
            raise RuntimeError("Proxy relay, watchdog or controlled ACK incomplete")
        report["status"] = "completed"
    except (OSError, ValueError, EOFError, RuntimeError) as exc:
        errors.append(f"{type(exc).__name__}: {exc}")
        audit.abort.set()
    finally:
        watchdog.cancel()
        close_owned()
        timer_thread.join(1)
        if data_thread is not None:
            data_thread.join(1)
            if data_thread.is_alive():
                errors.append("Data relay still alive after teardown")
                report["status"] = "failed"
        watchdog.mark_teardown()
        if report["status"] == "completed" and watchdog.state == "fired":
            report["status"] = (
                "intentional-observation-cutoff"
                if watchdog.receipt()["valid_30_seconds"]
                else "timing-invalid"
            )
        report["errors"] = errors
        report["observation"] = watchdog.receipt()
        report["pid"] = os.getpid()
        report["entries"] = audit.entries
        encoded = json.dumps(report, indent=2) + "\n"
        if len(encoded.encode()) > 1_000_000:
            raise ValueError("Final log exceeds 1 MiB")
        (output / "report.json").write_text(encoded)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--variant", choices=VARIANTS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--expected-netns-inode", type=int, required=True)
    parser.add_argument("--host-netns-inode", type=int, required=True)
    args = parser.parse_args()
    result = serve(
        args.variant, args.output, args.expected_netns_inode, args.host_netns_inode
    )
    print(result["status"])
    raise SystemExit(
        result["status"] not in {"completed", "intentional-observation-cutoff"}
    )


if __name__ == "__main__":
    main()
