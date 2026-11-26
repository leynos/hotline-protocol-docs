#!/usr/bin/env python3
"""Fixed-target AF_UNIX bridge for an opt-in loopback-only Mac VM namespace."""

import argparse
import json
import os
import re
import select
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SYNTHETIC_PORTS = range(15650, 15660)


def validate_target(port: int, *, synthetic: bool) -> tuple[str, int]:
    """Require a fixed loopback target port to be allowed and return its address."""
    if (synthetic and port not in SYNTHETIC_PORTS) or (
        not synthetic and port not in (15500, 15501)
    ):
        raise ValueError("Fixed loopback target port is not allowed")
    return "127.0.0.1", port


def abstract_x_address(display: str) -> bytes:
    """Return the abstract socket address of a local X display."""
    if re.fullmatch(r":[0-9]{1,3}", display) is None:
        raise ValueError("Expected one local X display number")
    return b"\0/tmp/.X11-unix/X" + display[1:].encode("ascii")


def bind_abstract_x(display: str) -> socket.socket:
    """Bind a listening socket to the abstract address of an X display."""
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(abstract_x_address(display))
        listener.listen(32)
        return listener
    except BaseException:
        listener.close()
        raise


def check_socket_path(path: Path) -> None:
    """Require the bridge socket to sit in a private existing directory below the state tree."""
    if not path.is_absolute() or not path.parent.resolve().is_relative_to(
        ROOT / "state"
    ):
        raise ValueError("Bridge socket parent must be under mothra/state")
    if path.name in ("", ".", "..") or not path.parent.is_dir():
        raise ValueError("Bridge socket needs an existing state directory")
    if path.parent.stat().st_mode & 0o077:
        raise ValueError("Bridge socket directory must be private")


def bind_unix(path: Path) -> tuple[socket.socket, int]:
    """Bind a new socket without replacing files or following a symlink."""
    check_socket_path(path)
    if os.path.lexists(path):
        raise FileExistsError(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        directory_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            listener.bind(f"/proc/self/fd/{directory_fd}/{path.name}")
        finally:
            os.close(directory_fd)
        os.chmod(path, 0o600)
        listener.listen(32)
        return listener, path.lstat().st_ino
    except BaseException:
        listener.close()
        raise


def connect_unix(path: Path) -> socket.socket:
    """Connect to a bridge socket through its checked parent directory descriptor."""
    check_socket_path(path)
    peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        directory_fd = os.open(path.parent, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            peer.connect(f"/proc/self/fd/{directory_fd}/{path.name}")
        finally:
            os.close(directory_fd)
        return peer
    except OSError:
        peer.close()
        raise


def safe_unlink(path: Path, inode: int) -> bool:
    """Remove only the socket inode this process created."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if info.st_ino != inode or not stat.S_ISSOCK(info.st_mode):
        return False
    path.unlink()
    return True


def wait_for_bridge(path: Path, timeout: float = 5) -> None:
    """Wait until the bridge socket and its ready record exist, or time out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if (path.parent / f"{path.stem}-ready.json").is_file() and path.is_socket():
            return
        time.sleep(0.05)
    raise TimeoutError(f"Fixed bridge did not become ready: {path.name}")


def relay_pair(left: socket.socket, right: socket.socket) -> None:
    """Copy both directions and preserve each peer's independent half-close."""
    left.settimeout(None)
    right.settimeout(None)

    def pump(source: socket.socket, destination: socket.socket) -> None:
        """Copy bytes from one socket to the other until the source closes, then shut down the destination's writing side."""
        try:
            while data := source.recv(65536):
                destination.sendall(data)
        except OSError:
            pass
        finally:
            try:
                destination.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    forward = threading.Thread(target=pump, args=(left, right), daemon=True)
    reverse = threading.Thread(target=pump, args=(right, left), daemon=True)
    forward.start()
    reverse.start()
    forward.join()
    reverse.join()


def serve(
    listener: socket.socket, dial: Callable[[], socket.socket], stop: threading.Event
) -> None:
    """Handle bounded concurrent streams; a failed dial closes that stream."""
    capacity = threading.BoundedSemaphore(32)
    listener.settimeout(0.2)

    def handle(client: socket.socket) -> None:
        """Relay one accepted client to a freshly dialled peer and release its capacity slot."""
        try:
            with client:
                remote = dial()
                with remote:
                    relay_pair(client, remote)
        except OSError:
            pass
        finally:
            capacity.release()

    while not stop.is_set():
        try:
            client, _ = listener.accept()
        except TimeoutError:
            continue
        except OSError:
            if stop.is_set():
                break
            raise
        if not capacity.acquire(blocking=False):
            client.close()
            continue
        threading.Thread(target=handle, args=(client,), daemon=True).start()


def run_host_bridge(
    path: Path, target: object, dial: Callable[[], socket.socket]
) -> None:
    """Listen on a socket path, write the ready record and relay every client to the fixed target."""
    listener, inode = bind_unix(path)
    ready = path.parent / f"{path.stem}-ready.json"
    stop = threading.Event()
    try:
        with ready.open("x") as output:
            json.dump(
                {
                    "pid": os.getpid(),
                    "socket": str(path),
                    "socket_inode": inode,
                    "fixed_target": target,
                    "netns": os.readlink("/proc/self/ns/net"),
                },
                output,
                indent=2,
            )
            output.write("\n")
        signal.signal(signal.SIGTERM, lambda _signum, _frame: stop.set())
        signal.signal(signal.SIGINT, lambda _signum, _frame: stop.set())
        serve(listener, dial, stop)
    finally:
        stop.set()
        listener.close()
        safe_unlink(path, inode)


def host_bridge(path: Path, target_port: int, *, synthetic: bool) -> None:
    """Run a host bridge to a validated loopback TCP port."""
    target = validate_target(target_port, synthetic=synthetic)
    run_host_bridge(
        path,
        {"kind": "tcp", "address": list(target), "synthetic": synthetic},
        lambda: socket.create_connection(target, timeout=5),
    )


def host_x_bridge(path: Path, display: str) -> None:
    """Run a host bridge to a local X display."""
    address = abstract_x_address(display)

    def dial() -> socket.socket:
        """Connect to the X display's abstract socket."""
        peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            peer.connect(address)
            return peer
        except OSError:
            peer.close()
            raise

    run_host_bridge(path, {"kind": "x-abstract", "display": display}, dial)


def check_namespace() -> None:
    """Require the network namespace to hold only the loopback interface and no routes."""
    ip = shutil.which("ip")
    if ip is None:
        raise FileNotFoundError("ip")
    links = json.loads(
        subprocess.run(
            [ip, "-j", "link"], check=True, capture_output=True, text=True
        ).stdout
    )
    if {item["ifname"] for item in links} != {"lo"}:
        raise ValueError("Namespace contains a non-loopback interface")
    for family in ("-4", "-6"):
        routes = subprocess.run(
            [ip, "-j", family, "route", "show", "table", "main"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        if json.loads(routes) != []:
            raise ValueError("Namespace has a nonlocal route")


def namespace_bootstrap(args: argparse.Namespace) -> None:
    """Bring up loopback, check the namespace and run the supervisor as the target identity."""
    if os.geteuid() != 0 or args.uid <= 0 or args.gid <= 0:
        raise ValueError("Bootstrap needs root and a non-root target identity")
    ip = shutil.which("ip")
    setpriv = shutil.which("setpriv")
    if ip is None or setpriv is None:
        raise FileNotFoundError("ip or setpriv")
    subprocess.run([ip, "link", "set", "lo", "up"], check=True)
    check_namespace()
    options = []
    if args.data_socket is not None:
        options += ["--data-socket", str(args.data_socket)]
    if args.synthetic:
        options.append("--synthetic")
    command = [
        setpriv,
        f"--reuid={args.uid}",
        f"--regid={args.gid}",
        "--init-groups",
        sys.executable,
        str(Path(__file__).resolve()),
        "namespace-supervise",
        "--socket",
        str(args.socket),
        "--listen-port",
        str(args.listen_port),
        "--display",
        args.display,
        *options,
        "--",
        *args.command,
    ]
    os.execv(setpriv, command)


def checked_bridge_pidfd(path: Path, expected_target: object | None = None) -> int:
    """Check a bridge's ready record against its socket and return a descriptor for its process."""
    check_socket_path(path)
    ready = json.loads((path.parent / f"{path.stem}-ready.json").read_text())
    if (
        ready["socket"] != str(path)
        or ready["socket_inode"] != path.lstat().st_ino
        or (expected_target is not None and ready["fixed_target"] != expected_target)
    ):
        raise ValueError("Host bridge socket identity differs")
    return os.pidfd_open(ready["pid"])


def tcp_target_record(port: int, *, synthetic: bool) -> dict:
    """Return the record that describes a TCP bridge target."""
    return {
        "kind": "tcp",
        "address": list(validate_target(port, synthetic=synthetic)),
        "synthetic": synthetic,
    }


def namespace_supervise(args: argparse.Namespace) -> int:
    """Run the namespace's listeners and bridges and supervise the child command."""
    check_namespace()
    if args.listen_port != 15500 or not args.command:
        raise ValueError("Namespace listener must be fixed at 15500 with a child")
    x_path = args.socket.parent / "x-bridge.sock"
    if (
        args.data_socket is not None
        and args.data_socket != args.socket.parent / "data-bridge.sock"
    ):
        raise ValueError("Data bridge socket path differs")
    stop = threading.Event()
    pidfds: list[int] = []
    listeners: list[socket.socket] = []
    workers: list[threading.Thread] = []
    try:
        pidfds.append(
            checked_bridge_pidfd(
                args.socket,
                tcp_target_record(
                    15650 if args.synthetic else 15500, synthetic=args.synthetic
                ),
            )
        )
        pidfds.append(
            checked_bridge_pidfd(
                x_path, {"kind": "x-abstract", "display": args.display}
            )
        )
        if args.data_socket is not None:
            pidfds.append(
                checked_bridge_pidfd(
                    args.data_socket,
                    tcp_target_record(
                        15651 if args.synthetic else 15501, synthetic=args.synthetic
                    ),
                )
            )
        control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listeners.append(control)
        control.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        control.bind(("127.0.0.1", 15500))
        control.listen(32)
        x_listener = bind_abstract_x(args.display)
        listeners.append(x_listener)
        pairs = [(control, args.socket), (x_listener, x_path)]
        if args.data_socket is not None:
            data = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listeners.append(data)
            data.bind(("127.0.0.1", 15501))
            data.listen(32)
            pairs.append((data, args.data_socket))
        for listener, path in pairs:
            worker = threading.Thread(
                target=serve,
                args=(listener, lambda path=path: connect_unix(path), stop),
                daemon=True,
            )
            worker.start()
            workers.append(worker)
        display = subprocess.run(
            ["xdpyinfo", "-display", args.display],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            check=False,
        )
        if display.returncode:
            raise RuntimeError("Xvfb abstract relay is unavailable inside namespace")
        child = subprocess.Popen(args.command)
        while child.poll() is None:
            if select.select(pidfds, [], [], 0)[0] or any(
                not worker.is_alive() for worker in workers
            ):
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
                raise RuntimeError("Host bridge or namespace relay exited")
            time.sleep(0.2)
        return child.returncode or 0
    finally:
        stop.set()
        for listener in listeners:
            listener.close()
        for worker in workers:
            worker.join(timeout=2)
        for pidfd in pidfds:
            os.close(pidfd)


def main() -> None:
    """Parse the command line and run the chosen bridge or namespace role."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="role", required=True)
    bridge = commands.add_parser("host-bridge")
    bridge.add_argument("--socket", type=Path, required=True)
    bridge.add_argument("--target-port", type=int, required=True)
    bridge.add_argument("--synthetic", action="store_true")
    x_bridge = commands.add_parser("host-x-bridge")
    x_bridge.add_argument("--socket", type=Path, required=True)
    x_bridge.add_argument("--display", required=True)
    bootstrap = commands.add_parser("bootstrap")
    bootstrap.add_argument("--socket", type=Path, required=True)
    bootstrap.add_argument("--listen-port", type=int, required=True)
    bootstrap.add_argument("--display", required=True)
    bootstrap.add_argument("--data-socket", type=Path)
    bootstrap.add_argument("--synthetic", action="store_true")
    bootstrap.add_argument("--uid", type=int, required=True)
    bootstrap.add_argument("--gid", type=int, required=True)
    bootstrap.add_argument("command", nargs=argparse.REMAINDER)
    supervise = commands.add_parser("namespace-supervise")
    supervise.add_argument("--socket", type=Path, required=True)
    supervise.add_argument("--listen-port", type=int, required=True)
    supervise.add_argument("--display", required=True)
    supervise.add_argument("--data-socket", type=Path)
    supervise.add_argument("--synthetic", action="store_true")
    supervise.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.role == "host-bridge":
        host_bridge(args.socket, args.target_port, synthetic=args.synthetic)
    elif args.role == "host-x-bridge":
        host_x_bridge(args.socket, args.display)
    else:
        if args.command[:1] == ["--"]:
            args.command = args.command[1:]
        if args.role == "bootstrap":
            namespace_bootstrap(args)
        else:
            sys.exit(namespace_supervise(args))


if __name__ == "__main__":
    main()
