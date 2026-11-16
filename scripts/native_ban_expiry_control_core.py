"""Name the bounds, helpers and timing record of the ban-expiry controller.

Part of the ban-expiry controller (``native_ban_expiry_control``), which
re-exports every public name below. These are the pieces that the gates, the
runtime checks and the epoch runner share, with no capture of their own.
"""

import dataclasses as dc
import datetime as dt
import hashlib
import json
import typing as typ

import native_ban_expiry_cases as cases
from protocol_capture import validate_plan

if typ.TYPE_CHECKING:
    from pathlib import Path

EPOCH_CASES = {
    "first": cases.FIRST,
    "pre": ("pre-probe",),
    "post": ("post-probe",),
}
MAX_WINDOW_SECONDS = 720
ALIAS_WINDOW = "native-missing-alias-ui-30m-v1"
ALIAS_PURPOSE = "native-missing-alias-positive"
# The capture windows in seconds: the epoch, then the managed service cap.
DEFAULT_WINDOW = (720, 900)
ALIAS_WINDOW_BOUNDS = (1800, 2100)
MAX_BRACKET_SECONDS = 20
PRE_EARLIEST = 1600
PRE_LATEST = 1700
POST_EARLIEST = 1900
POST_LATEST = 2400
SECONDS_PER_MINUTE = 60
LATER_PHASES = frozenset({"pre", "post"})
PLAN_PORT = 15800
NATIVE_NOTE = (
    "Host UTC brackets one guest GetDateTime call; one-second guest clock "
    "progression is an unverified assumption until read-only guest witness."
)
NATIVE_INTERPRETATION = (
    "host-relative bracket only; guest clock progression requires separately "
    "retained read-only witness"
)

type Report = dict[str, typ.Any]


def require(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # called as require(ok, reason) throughout
    reason: str,
) -> None:
    """Fail closed unless a condition holds.

    Parameters
    ----------
    ok : bool
        The condition.
    reason : str
        The message of the failure.

    Raises
    ------
    ValueError
        If the condition is false.
    """
    if not ok:
        raise ValueError(reason)


def digest(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> Report:
    """Read a JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed value.
    """
    return json.loads(path.read_text())


def utc(value: str) -> dt.datetime:
    """Parse a timestamp that carries an offset and convert it to UTC.

    Returns
    -------
    datetime.datetime
        The instant, in UTC.
    """
    result = dt.datetime.fromisoformat(value)
    require(result.tzinfo is not None, "Missing UTC offset")
    return result.astimezone(dt.UTC)


def capture_window_bounds(
    receipt: Report, env: Report, selected: str | None
) -> tuple[int, int]:
    """Say how long an epoch and its managed services may run.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The runtime receipt.
    env : dict[str, typing.Any]
        The plan environment.
    selected : str | None
        The capture window profile that the caller selected.

    Returns
    -------
    tuple[int, int]
        The epoch seconds and the managed service cap in seconds.
    """
    profile = receipt.get("capture_window_profile")
    require(
        profile == env.get("capture_window_profile") == selected,
        "Capture window profile differs",
    )
    purpose = receipt.get("capture_window_purpose")
    require(
        purpose == env.get("capture_window_purpose"), "Capture window purpose differs"
    )
    if profile is None:
        require(purpose is None, "Unexpected capture window purpose")
        return DEFAULT_WINDOW
    require(
        profile == ALIAS_WINDOW and purpose == ALIAS_PURPOSE,
        "Unknown capture window profile or purpose",
    )
    return ALIAS_WINDOW_BOUNDS


def runtime_cap_seconds(value: str) -> int:
    """Read a systemd runtime cap such as ``35min`` or ``900s``.

    Returns
    -------
    int
        The cap in seconds.

    Raises
    ------
    ValueError
        If the cap is in neither form.
    """
    if value.endswith("min") and value[:-3].isdigit():
        return int(value[:-3]) * SECONDS_PER_MINUTE
    if value.endswith("s") and value[:-1].isdigit():
        return int(value[:-1])
    message = "Unrecognised managed runtime cap"
    raise ValueError(message)


@dc.dataclass(frozen=True, slots=True)
class TimingBounds:
    """The host-time bracket of one ban insertion and the runtime that made it."""

    request_utc: dt.datetime
    ack_utc: dt.datetime
    image_inode: int
    emulator_pid: int
    emulator_start_ticks: int
    emulator_sha256: str
    namespace_inode: int

    @classmethod
    def from_json(cls, value: Report) -> TimingBounds:
        """Read a recorded bracket and check how long it was.

        Returns
        -------
        TimingBounds
            The parsed bracket.
        """
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

    def to_json(self) -> Report:
        """Write the bracket as the record that a later epoch reads.

        Returns
        -------
        dict[str, typing.Any]
            The recorded fields, with the note about the guest clock.
        """
        return {
            "request_utc": self.request_utc.isoformat(),
            "ack_utc": self.ack_utc.isoformat(),
            "image_inode": self.image_inode,
            "emulator_pid": self.emulator_pid,
            "emulator_start_ticks": self.emulator_start_ticks,
            "emulator_sha256": self.emulator_sha256,
            "namespace_inode": self.namespace_inode,
            "native_getdatetime_note": NATIVE_NOTE,
        }

    def gate(self, phase: str, now: dt.datetime, receipt: Report) -> Report:
        """Check that the same guest is still running and the window is open.

        Parameters
        ----------
        phase : str
            ``pre`` or ``post``.
        now : datetime.datetime
            The host time of the check.
        receipt : dict[str, typing.Any]
            The runtime receipt that must still name the same guest.

        Returns
        -------
        dict[str, typing.Any]
            The timing record of the gate.
        """
        require(phase in LATER_PHASES, "Only later probes use timing gate")
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
            "interpretation": NATIVE_INTERPRETATION,
        }


def plan_gate(plan_path: Path) -> tuple[Report, str]:
    """Require a prepared plan to be the one the generator makes.

    Returns
    -------
    tuple[dict[str, typing.Any], str]
        The plan and the name of its case.
    """
    raw = plan_path.read_bytes()
    value = load(plan_path)
    name = value["expectation"]["case"]
    require(
        name in cases.plans() and plan_path.name == f"{name}.json",
        "Unexpected plan case",
    )
    validate_plan(value)
    require(
        value == cases.plan(name, cases.plans()[name], value["environment"], PLAN_PORT),
        "Prepared plan changed",
    )
    hashes = load(plan_path.parent / "source-hashes.json")
    require(hashes[name] == digest(raw), "Prepared source plan hash changed")
    return value, name
