"""Share a synthetic loopback peer and plan builder between capture tests."""

import contextlib
import hashlib
import json
import socket
import struct
import threading
import typing as typ

from protocol_capture import run_plan

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Steps = list[dict[str, typ.Any]]
type Handler = cabc.Callable[[socket.socket], None]

CONNECT: dict[str, str] = {"op": "connect", "connection": "main", "endpoint": "control"}
PEER_TIMEOUT_SECONDS = 2
JOIN_TIMEOUT_SECONDS = 3


def frame_of(
    payload: bytes, *, kind: int = 0, identifier: int = 7, is_reply: int = 1
) -> bytes:
    """Build one complete physical frame around ``payload``.

    Returns
    -------
    bytes
        The 20-byte header followed by the payload.
    """
    header = struct.pack(
        ">BBHIIII", 0, is_reply, kind, identifier, 0, len(payload), len(payload)
    )
    return header + payload


@contextlib.contextmanager
def peer(handler: Handler) -> cabc.Iterator[int]:
    """Run one bounded loopback peer and propagate failures to the test.

    Yields
    ------
    int
        The port the peer listens on.

    Raises
    ------
    AssertionError
        If the peer outlives the test or its handler failed.
    """
    errors: list[BaseException] = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(PEER_TIMEOUT_SECONDS)

        def serve() -> None:
            """Accept one connection and hand it to the handler."""
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(PEER_TIMEOUT_SECONDS)
                    handler(connection)
            except (OSError, AssertionError) as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1]
        finally:
            thread.join(JOIN_TIMEOUT_SECONDS)
            if thread.is_alive():
                message = "Synthetic peer did not terminate"
                raise AssertionError(message)
            if errors:
                raise AssertionError(str(errors))


class Harness:
    """A scratch directory with a synthetic oracle binary and plan builder."""

    def __init__(self, root: Path) -> None:
        """Create the synthetic binary below ``root``."""
        self.root = root
        self.binary = root / "synthetic.bin"
        self.binary.write_bytes(b"synthetic peer, not the native oracle")

    def plan(self, port: int, steps: Steps) -> Path:
        """Write a synthetic-profile plan that connects, then runs ``steps``.

        Returns
        -------
        pathlib.Path
            The plan file.
        """
        path = self.root / "plan.json"
        digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        path.write_text(
            json.dumps({
                "schema_version": 1,
                "profile": "synthetic-tool-test",
                "operator": "capture unit test",
                "oracle_sha256": digest,
                "gap_ids": ["GAP-084"],
                "endpoints": {"control": {"host": "127.0.0.1", "port": port}},
                "steps": [CONNECT, *steps],
            })
        )
        return path

    def capture(self, port: int, steps: Steps) -> dict[str, typ.Any]:
        """Record ``steps`` into ``capture/`` and return the report.

        Returns
        -------
        dict[str, typing.Any]
            The report ``run_plan`` returned.
        """
        return run_plan(self.plan(port, steps), self.binary, self.root / "capture")


def reseal(directory: Path, report: dict[str, typ.Any]) -> None:
    """Rewrite a report and recompute the checksum inventory to match."""
    (directory / "report.json").write_text(json.dumps(report))
    (directory / "checksums.sha256").write_text(
        "".join(
            f"{hashlib.sha256((directory / name).read_bytes()).hexdigest()}  {name}\n"
            for name in ["plan.json", "report.json"]
        )
    )


def read_frame_step(**options: object) -> Steps:
    """Build a single ``read_frame`` step with the given options.

    Returns
    -------
    list[dict[str, typing.Any]]
        A one-step plan tail.
    """
    return [{"op": "read_frame", "connection": "main", **options}]
