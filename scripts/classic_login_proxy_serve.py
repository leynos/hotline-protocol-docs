"""Run one isolated Classic Login107 proxy session from listeners to backends."""

import json
import os
import socket
import threading
import time
import typing as typ

from classic_login_proxy_constants import (
    BACKENDS,
    CLIENT_HELLO,
    DEADLINE_SECONDS,
    FINAL_LOG_LIMIT,
    LISTENERS,
    SERVER_HELLO,
)
from classic_login_proxy_errors import fail
from classic_login_proxy_frames import parse_frame
from classic_login_proxy_relay import (
    accept_one,
    present_bytes,
    read_exact,
    read_frame,
    relay_data,
    relay_frames,
)
from classic_login_proxy_state import (
    Audit,
    ObservationCutoff,
    ObservationWatchdog,
    RosterState,
    capture_failure,
)
from native_wire_names import HANDSHAKE_REPLY_BYTES, TYPE_LOGIN

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

LOOPBACK = "127.0.0.1"
CONTROL_HELLO_BYTES = 12


class ProxyRun:
    """Hold the state of one proxy session and run its steps in their fixed order."""

    def __init__(self, variant: str, output: Path, report: dict[str, typ.Any]) -> None:
        """Create the audit log, watchdog and thread bookkeeping of a session.

        Parameters
        ----------
        variant : str
            The variant that governs the controlled ACK.
        output : pathlib.Path
            The directory that receives ``ready.json`` and ``report.json``.
        report : dict[str, typing.Any]
            The report with its initial keys, which the run completes.
        """
        self.variant = variant
        self.output = output
        self.report = report
        self.audit = Audit(time.monotonic() + DEADLINE_SECONDS)
        self.sockets: list[socket.socket] = []
        self.sockets_lock = threading.Lock()
        self.errors: list[str] = []
        self.control_done = threading.Event()
        self.ack_forwarded = threading.Event()
        self.roster = RosterState() if variant == "roster-subject-115" else None
        self.watchdog = ObservationWatchdog(self.audit, self.close_owned)
        self.timer = threading.Thread(
            target=self.guarded, args=(self.watchdog.run,), daemon=True
        )
        self.data_thread: threading.Thread | None = None
        self.login_id: int | None = None

    def run(self) -> dict[str, typ.Any]:
        """Run the session to its end and write its report.

        Returns
        -------
        dict[str, typing.Any]
            The completed report.
        """
        self.timer.start()
        try:
            self._serve_control()
        except (OSError, ValueError, EOFError, RuntimeError) as exc:
            self.errors.append(f"{type(exc).__name__}: {exc}")
            self.audit.abort.set()
        finally:
            self._teardown()
        return self.report

    def track(self, peer: socket.socket) -> socket.socket:
        """Register a socket as owned by this run, closing it after a cutoff.

        Parameters
        ----------
        peer : socket.socket
            The socket to own.

        Returns
        -------
        socket.socket
            The same socket, with its read timeout set.
        """
        with self.sockets_lock:
            if self.audit.cutoff.is_set() or self.audit.abort.is_set():
                peer.close()
                fail(ObservationCutoff, "Owned socket created after cutoff")
            self.sockets.append(peer)
        peer.settimeout(0.25)
        return peer

    def close_owned(self) -> None:
        """Close every socket that this run owns."""
        with self.sockets_lock:
            owned = tuple(self.sockets)
        for peer in owned:
            peer.close()

    def guarded(self, action: cabc.Callable[[], None]) -> None:
        """Run one thread action and record any failure that it raises.

        Parameters
        ----------
        action : collections.abc.Callable[[], None]
            The thread action to run.
        """
        failure = capture_failure(action)
        if failure is None:
            return
        if self.audit.cutoff.is_set() and isinstance(
            failure, (ObservationCutoff, OSError)
        ):
            return
        self.errors.append(f"{type(failure).__name__}: {failure}")
        self.audit.abort.set()
        self.close_owned()

    def _serve_control(self) -> None:
        """Listen, accept the control connection and run the session's relays."""
        listeners = self._listen()
        (self.output / "ready.json").write_text(
            json.dumps(self.report | {"status": "ready"}) + "\n"
        )
        client = accept_one(listeners["control"], self.audit)
        if client is None:
            fail(ValueError, "Missing control connection")
        self.track(client)
        listeners["control"].close()
        data_thread = threading.Thread(
            target=self.guarded,
            args=(lambda: self._data(listeners["data"]),),
            daemon=True,
        )
        self.data_thread = data_thread
        data_thread.start()
        try:
            self._control_session(client)
        finally:
            self.control_done.set()
            if self.watchdog.state != "fired":
                self.watchdog.cancel()
        data_thread.join(max(0, self.audit.deadline - time.monotonic()))
        self.timer.join(1)
        if self._incomplete(data_thread):
            fail(RuntimeError, "Proxy relay, watchdog or controlled ACK incomplete")
        self.report["status"] = "completed"

    def _listen(self) -> dict[str, socket.socket]:
        """Open and bind the fixed local listeners.

        Returns
        -------
        dict[str, socket.socket]
            The listening sockets, keyed by their names.
        """
        listeners: dict[str, socket.socket] = {}
        for name, port in LISTENERS.items():
            listener = self.track(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            listener.bind((LOOPBACK, port))
            listener.listen(1)
            listeners[name] = listener
        return listeners

    def _control_session(self, client: socket.socket) -> None:
        """Run the handshake, the Login107 exchange and the control relay.

        Parameters
        ----------
        client : socket.socket
            The accepted control connection from the client.
        """
        backend = self.track(
            socket.create_connection((LOOPBACK, BACKENDS["control"]), timeout=2)
        )
        hello = present_bytes(read_exact(client, CONTROL_HELLO_BYTES, self.audit))
        if hello != CLIENT_HELLO:
            fail(ValueError, "Classic handshake differs")
        self.audit.record("client-handshake", hello, hello)
        backend.sendall(hello)
        answer = present_bytes(read_exact(backend, HANDSHAKE_REPLY_BYTES, self.audit))
        if answer != SERVER_HELLO:
            fail(ValueError, "Native handshake differs")
        self.audit.record("server-handshake", answer, answer)
        client.sendall(answer)
        login = read_frame(client, self.audit)
        if login is None:
            fail(ValueError, "Missing Login107 request")
        parsed = parse_frame(login)
        if (parsed["type"], parsed["is_reply"], parsed["error"]) != (TYPE_LOGIN, 0, 0):
            fail(ValueError, "First client frame is not Login107")
        self.audit.record("login-request", login, login)
        backend.sendall(login)
        self.login_id = parsed["id"]
        self._pair(client, backend, self._forward_frames)

    def _data(self, listener: socket.socket) -> None:
        """Accept the data connection and relay its raw bytes.

        Parameters
        ----------
        listener : socket.socket
            The data listener.
        """
        client = accept_one(listener, self.audit, self.control_done)
        if client is None:
            return
        self.track(client)
        listener.close()
        if not self.ack_forwarded.is_set():
            fail(ValueError, "Data connection preceded successful Login107 ACK")
        backend = self.track(
            socket.create_connection((LOOPBACK, BACKENDS["data"]), timeout=2)
        )
        self._pair(client, backend, self._forward_data)

    def _pair(
        self,
        source: socket.socket,
        target: socket.socket,
        forward: cabc.Callable[[socket.socket, socket.socket, int], None],
    ) -> None:
        """Relay both directions of one connection in two threads.

        Parameters
        ----------
        source : socket.socket
            The client side of the connection.
        target : socket.socket
            The backend side of the connection.
        forward : collections.abc.Callable[[socket.socket, socket.socket, int], None]
            The relay for one direction; the index is 0 for client to
            server and 1 for server to client.
        """
        actions = (
            lambda: forward(source, target, 0),
            lambda: forward(target, source, 1),
        )
        threads = [
            threading.Thread(target=self.guarded, args=(action,), daemon=True)
            for action in actions
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(max(0, self.audit.deadline - time.monotonic()))
        if any(thread.is_alive() for thread in threads) or self.errors:
            fail(RuntimeError, "Relay failed or exceeded process deadline")

    def _forward_data(self, src: socket.socket, dst: socket.socket, index: int) -> None:
        """Relay raw bytes in one direction of the data connection.

        Parameters
        ----------
        src : socket.socket
            The socket that bytes are read from.
        dst : socket.socket
            The socket that bytes are sent to.
        index : int
            0 for client to server, 1 for server to client.
        """
        relay_data(src, dst, self.audit, ("data-client", "data-server")[index])

    def _forward_frames(
        self, src: socket.socket, dst: socket.socket, index: int
    ) -> None:
        """Relay control frames in one direction, with the controlled ACK.

        Parameters
        ----------
        src : socket.socket
            The socket that frames are read from.
        dst : socket.socket
            The socket that frames are sent to.
        index : int
            0 for client to server, 1 for server to client.
        """
        relay_frames(
            src,
            dst,
            self.audit,
            ("client", "server")[index],
            self.login_id if index else None,
            self.variant,
            self.ack_forwarded,
            self.watchdog.arm if index else None,
            self.roster,
        )

    def _incomplete(self, data_thread: threading.Thread) -> bool:
        """Tell whether the controlled session finished without a clean ACK.

        Parameters
        ----------
        data_thread : threading.Thread
            The data relay thread.

        Returns
        -------
        bool
            True when a thread is alive or any failure was recorded.
        """
        if data_thread.is_alive() or self.timer.is_alive():
            return True
        if not self.ack_forwarded.is_set() or bool(self.errors):
            return True
        return bool(self.watchdog.error)

    def _teardown(self) -> None:
        """Tear the session down, classify it and write its report."""
        self.watchdog.cancel()
        self.close_owned()
        self.timer.join(1)
        if self.data_thread is not None:
            self.data_thread.join(1)
            if self.data_thread.is_alive():
                self.errors.append("Data relay still alive after teardown")
                self.report["status"] = "failed"
        self.watchdog.mark_teardown()
        if self.report["status"] == "completed" and self.watchdog.state == "fired":
            self.report["status"] = self._cutoff_status()
        self.report["errors"] = self.errors
        self.report["observation"] = self.watchdog.receipt()
        self.report["pid"] = os.getpid()
        self.report["entries"] = self.audit.entries
        encoded = json.dumps(self.report, indent=2) + "\n"
        if len(encoded.encode()) > FINAL_LOG_LIMIT:
            fail(ValueError, "Final log exceeds 1 MiB")
        (self.output / "report.json").write_text(encoded)

    def _cutoff_status(self) -> str:
        """Name the status of a run whose observation window fired.

        Returns
        -------
        str
            The intentional cutoff status when the window was valid, else the
            timing-invalid status.
        """
        if self.watchdog.receipt()["valid_30_seconds"]:
            return "intentional-observation-cutoff"
        return "timing-invalid"
