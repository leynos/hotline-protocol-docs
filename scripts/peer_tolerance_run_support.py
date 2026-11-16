"""Layout, plans, commands and freezing for ``peer_tolerance_run``.

Part of the runner's module set (``peer_tolerance_run.CAPTURE_MODULES``). Nothing
here starts a process, opens a socket or reads the clock, which the runner keeps
in its own module. ``peer_tolerance_run`` re-exports :func:`sha`.
"""

import dataclasses as dc
import hashlib
import json
import shutil
import sys
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

import capture_identity

FIXTURE_MODULES = ("peer_tolerance_fixture.py",)
FIRST_PORT = 15600
OLD_PORT = ":15510"
EVIDENCE_DAY = "evidence/gap-remediation/2026-11-13"

type Json = dict[str, typ.Any]
type HomeState = tuple[str, int, int] | None


def sha(path: Path) -> str:
    """Hash a file.

    Returns
    -------
    str
        The SHA-256 of its bytes in lower-case hexadecimal.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dc.dataclass(frozen=True, slots=True)
class Layout:
    """Where one run reads and writes.

    Attributes
    ----------
    root : pathlib.Path
        The checkout.
    evidence : pathlib.Path
        The tree whose ``scripts/`` are run and copied.
    work : pathlib.Path
        The private run directory.
    destination : pathlib.Path
        The owned evidence directory that receives the frozen run.
    """

    root: Path
    evidence: Path
    work: Path
    destination: Path

    @property
    def binary(self) -> Path:
        """The compiled peer.

        Returns
        -------
        pathlib.Path
            Its path.
        """
        return self.root / "tools/shx-peer/source/hx"

    @property
    def oracle(self) -> Path:
        """The oracle binary.

        Returns
        -------
        pathlib.Path
            Its path.
        """
        return self.root / "evidence/hotline-server-1.9/inputs/HLserver19.pef"

    @property
    def profile(self) -> Path:
        """The peer profile.

        Returns
        -------
        pathlib.Path
            Its path.
        """
        return self.root / f"{EVIDENCE_DAY}/native-shx-02/peer-profile.json"


def check_outputs(layout: Layout) -> Path:
    """Require owned, fresh output paths.

    Returns
    -------
    pathlib.Path
        The evidence directory that the run will own.

    Raises
    ------
    ValueError
        If the work directory is outside the private root, the destination is
        not the owned one, or either already exists.
    """
    private_root = layout.root / "state/delegation/peer"
    owned = layout.root / f"{EVIDENCE_DAY}/delegated-peer-01"
    if not layout.work.is_relative_to(private_root) or layout.destination != owned:
        message = "Output paths must be owned private or evidence paths"
        raise ValueError(message)
    if layout.work.exists() or layout.destination.exists():
        message = "Run and evidence outputs must be fresh"
        raise ValueError(message)
    return owned


def home_state() -> HomeState:
    """Describe the real ``.hxvars``, which the run must not change.

    Returns
    -------
    tuple[str, int, int] | None
        Its hash, size and modification time, or ``None`` if it is absent.
    """
    own_home = Path.home() / ".hxvars"
    if not own_home.exists():
        return None
    return (sha(own_home), own_home.stat().st_size, own_home.stat().st_mtime_ns)


def case_plan(template: Json, case: str, port: int) -> Json:
    """Specialise the control plan for one case and port.

    Returns
    -------
    dict[str, typing.Any]
        A copy of the plan with the case's environment and port.
    """
    plan = json.loads(json.dumps(template))
    plan["environment"] = {
        "controlled_receiver_fixture": {
            "profile": "controlled-receiver-fixture",
            "case": case,
            "source_peer": "shx 0.1.48 modern terminal build",
        }
    }
    command = plan["steps"][1]["command"]
    plan["steps"][1]["command"] = command.replace(OLD_PORT, f":{port}")
    return plan


def fixture_command(layout: Layout, case: str, port: int) -> list[str]:
    """Build the command that starts one case's receiver fixture.

    Returns
    -------
    list[str]
        The command.
    """
    return [
        sys.executable,
        str(layout.evidence / "scripts/peer_tolerance_fixture.py"),
        "--evidence",
        str(layout.root / EVIDENCE_DAY),
        "--case",
        case,
        "--port",
        str(port),
        "--output",
        str(layout.work / "fixtures" / case),
    ]


def session_command(layout: Layout, case: str, plan_file: Path) -> list[str]:
    """Build the command that captures one case's peer session.

    Returns
    -------
    list[str]
        The command.
    """
    return [
        sys.executable,
        str(layout.evidence / "scripts/capture_shx_session.py"),
        str(plan_file),
        "--binary",
        str(layout.binary),
        "--peer-profile",
        str(layout.profile),
        "--oracle-binary",
        str(layout.oracle),
        "--output",
        str(layout.work / "captures" / case),
    ]


def source_fields(layout: Layout, runner_modules: tuple[str, ...]) -> Json:
    """Identify the runner and the fixture that made the run.

    The fixture is the one in the tree whose scripts were run, as before; the
    runner is this script.

    Parameters
    ----------
    layout : Layout
        The paths of the run.
    runner_modules : tuple[str, ...]
        The runner's declared module set.

    Returns
    -------
    dict[str, typing.Any]
        The digest and the record of each module set.
    """
    fixture = capture_identity.identity(
        FIXTURE_MODULES, directory=layout.evidence / "scripts"
    )
    runner = capture_identity.identity(runner_modules)
    return {
        "source_fixture_sha256": fixture["digest"],
        "source_runner_sha256": runner["digest"],
        "source_fixture_identity": fixture,
        "source_runner_identity": runner,
    }


def freeze(
    layout: Layout,
    copied: tuple[Path, tuple[str, ...]],
    manifest: cabc.Callable[[], Json],
) -> None:
    """Copy the sources, write the manifest and sums, and freeze the run.

    Parameters
    ----------
    layout : Layout
        The paths of the run.
    copied : tuple[pathlib.Path, tuple[str, ...]]
        The evidence directory that the run owns, and the names of the scripts to
        copy into the corpus, in order.
    manifest : collections.abc.Callable[[], dict[str, typing.Any]]
        Builds the manifest once the sources are copied.
    """
    owned, names = copied
    work = layout.work
    (work / "sources").mkdir()
    for name in names:
        shutil.copy2(layout.evidence / "scripts" / name, work / "sources" / name)
    (work / "manifest.json").write_text(
        json.dumps(manifest(), indent=2) + "\n", encoding="utf-8"
    )
    (work / "SHA256SUMS").write_text(
        "".join(
            f"{sha(path)}  {owned.relative_to(layout.root) / path.relative_to(work)}\n"
            for path in sorted(work.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        ),
        encoding="utf-8",
    )
    layout.destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(work, layout.destination)
    print(f"Frozen evidence: {layout.destination}")
