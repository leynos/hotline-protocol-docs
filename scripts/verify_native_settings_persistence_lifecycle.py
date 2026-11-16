"""Check the operator's shutdown, the capture gates and the emulator lifecycle."""

import dataclasses as dc
import datetime as dt
import typing as typ

from protocol_capture import digest
from verify_native_settings_persistence_core import Json, read_json, require

if typ.TYPE_CHECKING:
    from pathlib import Path

PHASE_ACTIONS = ((1, 66), (2, 28))  # the phases and the actions each completed
SHOT_KEYS = "quit_prompt_image after_quit_image special_menu_image shutdown_image"
QUIT_PROMPT_STAMP = 2  # the stamps are the journal start, the hold, then one per shot
AFTER_QUIT_STAMP = 3
GATE_NAMES = (
    "host-ready-boot host-ready-readiness host-ready-phase "
    "namespace-ready-readiness namespace-ready-phase"
)
CAPTURE_DROPS = 2  # the host and the namespace recorder each report no drops
UNIT_COUNT = 4  # the managed units, each stopped with a zero main PID
UNPRIVILEGED_UID = 1000
EMULATOR_EXE_SHA = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
WORKING_IMAGE = "native-settings-persistence-01/working.dsk"
GUEST_CAPTURES = {1: 45, 2: 48}  # the phase's guest capture is named for its batch
SOCKETS = ["main", "subject"]


@dc.dataclass(frozen=True, slots=True)
class Phase:
    """One phase of the corpus, with its operator timeline.

    Attributes
    ----------
    corpus : pathlib.Path
        The corpus directory.
    number : int
        The phase number, 1 or 2.
    actions : int
        The number of actions that the phase's report must have completed.
    events : dict[str, typing.Any]
        The operator timeline of the phase.
    """

    corpus: Path
    number: int
    actions: int
    events: Json

    @property
    def directory(self) -> Path:
        """The phase's directory.

        Returns
        -------
        pathlib.Path
            ``phase1`` or ``phase2`` below the corpus.
        """
        return self.corpus / f"phase{self.number}"


def shutdown_shots(phase: Phase, boot_journal: str) -> list[Json]:
    """Check the boot journal and the shutdown screens, and list the screens.

    Parameters
    ----------
    phase : Phase
        The phase.
    boot_journal : str
        The text of the user session's journal.

    Returns
    -------
    list[dict[str, typing.Any]]
        The screenshot records, in the order of ``SHOT_KEYS``.
    """
    events = phase.events
    require(events["journal_start_utc"] in boot_journal, "Boot journal start missing")
    status = events["machine_journal_exit_status"]
    require(status.startswith("not recorded"), "Missing exit-status caveat")
    shots = [events["screenshots"][key] for key in SHOT_KEYS.split()]
    require(
        all(
            digest((phase.corpus / shot["path"]).read_bytes()) == shot["sha256"]
            for shot in shots
        ),
        "Shutdown screen binding differs",
    )
    return shots


def chronology(events: Json, shots: list[Json]) -> list[str]:
    """Check that the operator's shutdown steps are in time order.

    Parameters
    ----------
    events : dict[str, typing.Any]
        The operator timeline of the phase.
    shots : list[dict[str, typing.Any]]
        The screenshot records.

    Returns
    -------
    list[str]
        The timestamps, in the order that they are checked.
    """
    stamps = [
        events["journal_start_utc"],
        events["hold_ready_utc"],
        *(shot["source_mtime_utc"] for shot in shots),
        events["operator_pid_absent_by_utc"],
        events["capture_stop_utc"],
        events["fork_extraction_completed_utc"],
    ]
    times = [dt.datetime.fromisoformat(stamp) for stamp in stamps]
    require(times == sorted(times), "Operator shutdown chronology differs")
    return stamps


def read_deadline(directory: Path) -> dt.datetime:
    """Read the phase's deadline.

    Returns
    -------
    datetime.datetime
        The deadline, with its timezone.
    """
    deadline_text = (directory / "deadline.txt").read_text().strip()
    return dt.datetime.fromisoformat(deadline_text)


def check_hold(phase: Phase, stamps: list[str], deadline: dt.datetime) -> Json:
    """Check the hold-ready record, the quit timeline and the phase report.

    Parameters
    ----------
    phase : Phase
        The phase.
    stamps : list[str]
        The timestamps from :func:`chronology`.
    deadline : datetime.datetime
        The phase's deadline.

    Returns
    -------
    dict[str, typing.Any]
        The phase's capture report.
    """
    parse = dt.datetime.fromisoformat
    case = phase.directory / f"phase{phase.number}"
    hold = read_json(case / "hold-ready.json")
    observed = read_json(case / "report.json")
    require(
        phase.events["hold_ready_utc"] == hold["utc"], "Hold-ready timeline differs"
    )
    require(
        parse(stamps[QUIT_PROMPT_STAMP])
        < parse(observed["recorded_at_utc"])
        < parse(stamps[AFTER_QUIT_STAMP]),
        "Quit/EOF timeline differs",
    )
    require(
        hold["sockets"] == SOCKETS
        and dt.datetime.fromisoformat(hold["utc"]) < deadline,
        "Owned sockets/deadline differ",
    )
    require(
        observed["completed_actions"] == phase.actions
        and dt.datetime.fromisoformat(observed["recorded_at_utc"]) < deadline,
        "Phase report exceeded deadline",
    )
    return observed


def check_gates(directory: Path, deadline: dt.datetime, observed: Json) -> None:
    """Check that each capture gate was ready before the deadline and its capture.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    deadline : datetime.datetime
        The phase's deadline.
    observed : dict[str, typing.Any]
        The phase's capture report.
    """
    for name in (f"{gate}.json" for gate in GATE_NAMES.split()):
        gate = read_json(directory / name)
        target = (
            observed
            if name.endswith("-phase.json")
            else read_json(directory / "readiness/report.json")
        )
        require(
            dt.datetime.fromisoformat(gate["utc"]) < deadline
            and dt.datetime.fromisoformat(gate["utc"])
            < dt.datetime.fromisoformat(target["started_at_utc"])
            and gate["deadline_utc"] == deadline.isoformat(),
            "Capture gate readiness/deadline differs",
        )


def check_units(directory: Path) -> None:
    """Check the capture journal and the terminal state of every managed unit.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    """
    journal = (directory / "capture-journal.txt").read_text()
    require(
        journal.count("0 packets dropped by kernel") == CAPTURE_DROPS
        and "0 packets captured" in journal,
        "Capture drops/primary zero differ",
    )
    units = (directory / "system-units-terminal.txt").read_text()
    require(
        units.count("MainPID=0") == UNIT_COUNT
        and units.count("Result=success") == UNIT_COUNT,
        "Managed system unit terminal state differs",
    )
    user = (directory / "user-units-terminal.txt").read_text()
    require(user.count("MainPID=0") == UNIT_COUNT, "User unit terminal state differs")


def check_emulator(phase: Phase) -> None:
    """Check the emulator's identity, its file descriptors and the shutdown screens.

    Parameters
    ----------
    phase : Phase
        The phase.
    """
    directory = phase.directory
    identity = read_json(directory / "emulator-identity.json")
    require(
        identity["uid"] == UNPRIVILEGED_UID
        and identity["exe_sha256"] == EMULATOR_EXE_SHA,
        "Emulator identity differs",
    )
    require(
        identity["working_image_fd6"].endswith(WORKING_IMAGE)
        and identity["guest_pcap_fd16"].endswith(
            f"native-settings-persistence-a{GUEST_CAPTURES[phase.number]}/guest.pcap"
        ),
        "Emulator FD identity differs",
    )
    require(
        (directory / "screenshots" / "special-menu-hold2.png").is_file()
        and (directory / "screenshots" / "after-quit-confirm.png").is_file(),
        "Shutdown/quit screen missing",
    )


def phase_lifecycle(phase: Phase, boot_journal: str) -> None:
    """Check one phase's shutdown, gates, units and emulator.

    Parameters
    ----------
    phase : Phase
        The phase.
    boot_journal : str
        The text of the user session's journal.
    """
    shots = shutdown_shots(phase, boot_journal)
    stamps = chronology(phase.events, shots)
    deadline = read_deadline(phase.directory)
    observed = check_hold(phase, stamps, deadline)
    check_gates(phase.directory, deadline, observed)
    check_units(phase.directory)
    check_emulator(phase)


def lifecycle(corpus: Path) -> None:
    """Check the operator's shutdown and the emulator lifecycle of both phases.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    timeline = read_json(corpus / "baseline/operator-timeline.json")
    boot_journal = (corpus / "baseline/user-sheep-journal.txt").read_text()
    scope = timeline["scope"]
    require("not a machine exit attestation" in scope, "Shutdown proof scope differs")
    for number, actions in PHASE_ACTIONS:
        events = timeline["phases"][f"phase{number}"]
        phase_lifecycle(Phase(corpus, number, actions, events), boot_journal)
    first = read_json(corpus / "phase1/emulator-identity.json")
    second = read_json(corpus / "phase2/emulator-identity.json")
    require(
        (first["pid"], first["start_ticks"], first["netns"])
        != (second["pid"], second["start_ticks"], second["netns"]),
        "Same emulator instance reused",
    )
