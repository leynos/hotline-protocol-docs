"""Support for the alias controls: a reply frame builder and a scripted wire."""

import time
import typing as typ

import native_missing_alias_cases as cases
import native_missing_alias_control as control
from native_plan import packet, payload
from protocol_capture import decode_frame

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

ENV = {
    "fixture_profile": "control-only",
    "emulator_pid": 123,
    "emulator_starttime": 456,
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 789,
    "owned_working_image": "/owned/native-alias-live-05/working.dsk",
    "owned_working_image_inode": 321,
    "owned_runtime": "/owned/native-alias-live-05",
    "initial_finf_sha256": cases.digest(b"U54TM54X" + bytes(24)),
}
PRESTAGED_FINFO = b"U54TM54X" + b"\x01" + bytes(23)


def stage_owned_files(runtime: Path) -> None:
    """Write the owned target and its pre-staged Finder sidecar under a runtime.

    Both files are written with mode 0600, as the control expects.
    """
    shared = runtime / "shared"
    (shared / ".finf").mkdir(parents=True)
    for path, data in (
        (shared / cases.TARGET.decode(), cases.TARGET_DATA),
        (shared / ".finf" / cases.TARGET.decode(), PRESTAGED_FINFO),
    ):
        path.write_bytes(data)
        path.chmod(0o600)


def reply(
    identifier: int,
    values: list[tuple[int, bytes]],
    kind: int = 0,
    answer: int = 1,
) -> dict[str, typ.Any]:
    """Build one decoded reply frame on the main connection.

    Returns
    -------
    dict[str, typing.Any]
        The decoded frame, with its raw hexadecimal bytes and its connection.
    """
    raw = packet(kind, identifier, payload(values), reply=answer)
    return {"connection": "main", "raw_hex": raw, **decode_frame(bytes.fromhex(raw))}


def row(name: bytes) -> bytes:
    """Build one file-list row that names an entry.

    Returns
    -------
    bytes
        Sixteen zero bytes, the name length as four big-endian bytes, and the name.
    """
    return bytes(16) + len(name).to_bytes(4, "big") + name


class FakeWire:
    """A scripted wire that answers the control from a fixed list of frames."""

    def __init__(self) -> None:
        """Script the three frames of the duplicate-row case."""
        self.frames: list[dict[str, typ.Any]] = [
            reply(1, [(160, b"\0\xbe"), (161, b"\0\0")]),
            reply(2, [(110, control.ADMIN)], 354, 0),
            reply(3, [(101, b"x")], 109, 0),
        ]
        self.buffers: dict[str, bytearray] = {}
        self.partial: dict[str, typ.Any] = {}
        self.request_count = 0
        self.deadline = time.monotonic() + 2

    def execute(self, step: dict[str, typ.Any]) -> None:
        """Accept one scripted step without any effect."""

    def send(self, name: str, raw: str, label: str) -> None:
        """Accept one request without any effect."""

    def wait_for(
        self, predicate: cabc.Callable[[], bool], seconds: float, label: str
    ) -> None:
        """Accept one wait without any effect."""

    def match(
        self, name: str, kind: int, identifier: int, answer: int
    ) -> list[dict[str, typ.Any]]:
        """Return the scripted frames of one reply type.

        Returns
        -------
        list[dict[str, typing.Any]]
            The frames whose type is ``kind``, in script order.
        """
        return [f for f in self.frames if f["type"] == kind]

    def poll(self, seconds: float) -> None:
        """Accept one poll without any effect."""
