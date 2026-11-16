"""Share the helpers of the report tests of the 121 and transition capture drivers.

A recorder that connects to nothing runs a plan, so no socket is opened and no
capture is made. The helpers prepare the observation plan of a planner, list a
capture directory, and check how a report names the scripts that made it
(decision D31).
"""

import hashlib
import json
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

type Plan = dict[str, typ.Any]
type Report = dict[str, typ.Any]

ROOT = Path(__file__).resolve().parents[1]
BASELINE = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
CAPTURE_FILES = ["checksums.sha256", "plan.json", "report.json", "stage-gates.json"]


class QuietRecorder:
    """A recorder that runs every step without a connection."""

    def __init__(self, plan: Plan) -> None:
        """Start empty.

        Parameters
        ----------
        plan : dict[str, typing.Any]
            The plan, which is not read.
        """
        del plan
        self.events: list[Report] = []
        self.frames: list[Report] = []
        self.sockets: dict[str, typ.Any] = {}
        self.started_at_utc = "offline"
        self.executed: list[int] = []

    def execute(self, index: int, step: Report) -> None:
        """Run one step without effect, and remember its index."""
        del step
        self.executed.append(index)

    def event(self, action: int, name: str, kind: str) -> None:
        """Keep an event."""
        self.events.append({"action": action, "connection": name, "event": kind})

    def streams(self) -> Report:
        """Give no streams.

        Returns
        -------
        dict[str, typing.Any]
            An empty mapping.
        """
        return dict.fromkeys(self.sockets)


def prepared(module: types.ModuleType) -> Plan:
    """Prepare the observation plan of a planner.

    Returns
    -------
    dict[str, typing.Any]
        The plan.
    """
    raw = BASELINE.read_bytes()
    return module.plans(json.loads(raw)["environment"], raw)["observe"]


def listing(directory: Path) -> list[str]:
    """List the files of a capture directory.

    Returns
    -------
    list[str]
        The names, sorted.
    """
    return sorted(path.name for path in directory.iterdir())


def oracle_digest(oracle: str) -> cabc.Callable[[bytes], str]:
    """Make a ``digest`` that gives the oracle's hash for the offline binary.

    Returns
    -------
    collections.abc.Callable[[bytes], str]
        A function that hashes bytes, except ``b"offline"``, which it takes for
        the oracle binary.
    """

    def digest(data: bytes) -> str:
        """Hash bytes.

        Returns
        -------
        str
            The oracle's hash for the offline binary, otherwise the SHA-256.
        """
        if data == b"offline":
            return oracle
        return hashlib.sha256(data).hexdigest()

    return digest


def driver_problems(report: Report, driver: types.ModuleType) -> list[str]:
    """Find what is wrong with the way a report names the scripts that made it.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The report that the driver wrote.
    driver : types.ModuleType
        The driver. A report of the earlier form holds the hash of its one file;
        one made after decision D31 holds the digest of the module set and the
        record, which begins with the driver's own file.

    Returns
    -------
    list[str]
        The faults; empty when the report names the scripts rightly.
    """
    path = Path(typ.cast("str", driver.__file__))
    if "driver_identity" not in report:
        held = hashlib.sha256(path.read_bytes()).hexdigest()
        return [] if report["driver_sha256"] == held else ["the file's hash differs"]
    record = report["driver_identity"]
    found = []
    if Path(record["files"][0]["path"]).name != path.name:
        found.append("the record does not begin with the driver")
    for item in record["files"]:
        held = hashlib.sha256((path.parent / Path(item["path"]).name).read_bytes())
        if item["sha256"] != held.hexdigest():
            found.append(f"{item['path']} differs")
    if report["driver_sha256"] != record["digest"]:
        found.append("driver_sha256 is not the digest of the record")
    return found
