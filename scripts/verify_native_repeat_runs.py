"""Check one lab run of the repeated A7 transfer corpus.

A run is the frozen A7 plan on its own lab ports. Its capture must have the
expected outcome, both packet views must carry the recorded bytes, and its lab
must have been retired as recorded.
"""

import dataclasses as dc
import datetime as dt
import hashlib
import json
import typing as typ

from pcap_tcp import lifetime, read_packets, stream
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Json = dict[str, typ.Any]

# Hashes of the frozen inputs: the A7 plan, the capture driver, the complete and
# the prefix-only download bodies, the lab assets and the emulator preferences.
PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
DRIVER_SHA = "2fba0972f4d9a8e3845c4204dce150dd7c90da0e19a9e5720d5289e2c94faf01"
FULL_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
PREFIX_SHA = "b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c"
ROM_SHA = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
BASE_SHA = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
EXE_SHA = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
APP_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
PREFS_SHA = "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196"
NORMAL_PREFS_SHA = "f8809e5435f85ee17d5ca2c61b29c71b4fdca0db881f9b6b2a9e24b1fda1d6e2"

COMPLETE_RUN = "c32"  # the other two stop after a bounded prefix
STEPS = 29  # the A7 plan has this many steps
COMPLETE_BYTES = 1049073
PREFIX_BYTES = 98304
PREFIX_ACTIONS = 21
LOOPBACK = "127.0.0.1"
LIMITS = (5500, 100, 10, 5)  # port, global and per-client downloads, per-IP connections
GUEST_PORT = 5501
GUEST_PREFS_BYTES = 175
PRIMARY_PORTS = range(15500, 15502)  # the primary lab's bridge ports
TCP_SYN = 2
TCP_ACK = 16
MICROSECONDS_PER_SECOND = 1_000_000
NANOSECONDS_PER_MICROSECOND = 1000
PROVENANCE_EXEMPT = {"manifest.json", "SHA256SUMS"}
LAB_ENDPOINT_OFFSET = 1  # the data port follows the control port
UNKNOWN_DROPS = "0 packets dropped by kernel"


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 digest in hexadecimal.
    """
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> Json:
    """Read a JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


@dc.dataclass(frozen=True, slots=True)
class Run:
    """One lab run of the corpus.

    Attributes
    ----------
    name : str
        The run name, such as ``c32``.
    root : pathlib.Path
        The directory of the run.
    frontend : int
        The control port of the run's lab.
    """

    name: str
    root: Path
    frontend: int

    @property
    def complete(self) -> bool:
        """Whether this run downloaded the whole file."""
        return self.name == COMPLETE_RUN

    @property
    def expected_bytes(self) -> int:
        """The length of the body that the run received."""
        return COMPLETE_BYTES if self.complete else PREFIX_BYTES

    @property
    def expected_sha(self) -> str:
        """The hash of the body that the run received."""
        return FULL_SHA if self.complete else PREFIX_SHA


def check_plan(run: Run) -> None:
    """Check that the as-run plan is the frozen A7 plan on this run's ports."""
    original = load(run.root / "original-plan.json")
    plan = load(run.root / "a7-as-run-plan.json")
    require(
        sha((run.root / "original-plan.json").read_bytes()) == PLAN_SHA,
        f"{run.name} source A7 differs",
    )
    require(
        len(original["steps"]) == STEPS and original["steps"] == plan["steps"],
        f"{run.name} A7 steps differ",
    )
    for key in original.keys() - {"operator", "environment", "endpoints"}:
        require(original[key] == plan[key], f"{run.name} A7 {key} differs")
    require(
        plan["endpoints"]
        == {
            "control": {"host": LOOPBACK, "port": run.frontend},
            "data": {"host": LOOPBACK, "port": run.frontend + LAB_ENDPOINT_OFFSET},
        },
        f"{run.name} endpoint differs",
    )
    options = plan["environment"]["original_options"]
    limits = (
        options["server_port"],
        options["global_max_downloads"],
        options["per_client_max_downloads"],
        options["max_connections_per_ip"],
    )
    require(limits == LIMITS, f"{run.name} recorded options differ")
    require(
        plan["environment"]["captured_options"] is False,
        f"{run.name} lab GUI-options observation changed",
    )


def check_outcome(run: Run, report: Json) -> bytes:
    """Check the status, driver and body of a run's capture.

    Returns
    -------
    bytes
        The bytes that the download connection received.
    """
    observed = (report["status"], report["completed_actions"], report["error"])
    expected = (
        ("completed", STEPS, "")
        if run.complete
        else ("failed", PREFIX_ACTIONS, "TimeoutError: timed out")
    )
    require(observed == expected, f"{run.name} A7 outcome differs")
    require(report["driver_sha256"] == DRIVER_SHA, f"{run.name} capture driver differs")
    require(report["oracle_sha256"] == APP_SHA, f"{run.name} native app differs")
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(
        len(received) == run.expected_bytes and sha(received) == run.expected_sha,
        f"{run.name} recorder body differs",
    )
    return received


class View(typ.NamedTuple):
    """A packet capture of one side of the transfer.

    Attributes
    ----------
    name : str
        ``namespace`` or ``guest``.
    client : str
        The client address.
    server : str
        The server address.
    port : int
        The server's data port.
    filename : str
        The capture's file name in the run's ``boot`` directory.
    """

    name: str
    client: str
    server: str
    port: int
    filename: str


@dc.dataclass(frozen=True, slots=True)
class Flow:
    """The download connection of a run as the capture reports it.

    Attributes
    ----------
    run : Run
        The run.
    received : bytes
        The bytes the recorder received.
    sent : bytes
        The bytes the recorder sent.
    local : int
        The recorder's local port.
    when : int
        The connection time, in microseconds since the epoch.
    """

    run: Run
    received: bytes
    sent: bytes
    local: int
    when: int


def read_flow(run: Run, report: Json, received: bytes) -> Flow:
    """Locate the download connection of a capture.

    Returns
    -------
    Flow
        Its endpoints and start time.
    """
    event = next(
        e
        for e in report["events"]
        if e["connection"] == "download" and e["event"] == "connect"
    )
    require(
        event["peer_address"] == [LOOPBACK, run.frontend + LAB_ENDPOINT_OFFSET],
        f"{run.name} data peer differs",
    )
    started = dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
    return Flow(
        run,
        received,
        bytes.fromhex(report["streams"]["download"]["sent_hex"]),
        event["local_address"][1],
        int(started * MICROSECONDS_PER_SECOND)
        + event["elapsed_ns"] // NANOSECONDS_PER_MICROSECOND,
    )


def check_view(flow: Flow, view: View, prior: Json) -> int:
    """Check one packet view against the recorder and the frozen comparison.

    Returns
    -------
    int
        The number of server bytes the view carries.
    """
    run = flow.run
    path = run.root / "boot" / view.filename
    packets = read_packets(path)
    if view.name == "namespace":
        require(
            not any(
                p["src_port"] in PRIMARY_PORTS or p["dst_port"] in PRIMARY_PORTS
                for p in packets
            ),
            f"{run.name} primary bridge used",
        )
    client, server = (view.client, flow.local), (view.server, view.port)
    packets = lifetime(packets, client, server, flow.when)
    syns = sum(
        bool(p["flags"] & TCP_SYN and (not p["flags"] & TCP_ACK)) for p in packets
    )
    require(syns == 1, f"{run.name} {view.name} SYN association differs")
    actual = stream(packets, server, client)
    require(actual == flow.received, f"{run.name} {view.name} payload differs")
    require(
        stream(packets, client, server) == flow.sent,
        f"{run.name} {view.name} HTXF differs",
    )
    require(
        len(actual) == run.expected_bytes and sha(actual) == run.expected_sha,
        f"{run.name} {view.name} length differs",
    )
    require(
        prior["pcap_sha256"] == sha(path.read_bytes()),
        f"{run.name} {view.name} source PCAP differs",
    )
    require(
        prior["server_bytes"] == len(actual) and prior["server_sha256"] == sha(actual),
        f"{run.name} {view.name} comparison differs",
    )
    return len(actual)


def check_assets(run: Run, config: Json) -> None:
    """Check the lab assets, emulator and guest preferences of a run."""
    assets = load(run.root / "assets.json")
    require(
        assets["rom_sha256"] == ROM_SHA and assets["base_disk_sha256"] == BASE_SHA,
        f"{run.name} source assets differ",
    )
    require(
        config["source_assets"] == assets
        and config["emulator_exe_sha256"] == EXE_SHA
        and config["native_oracle_sha256"] == APP_SHA,
        f"{run.name} binary identity differs",
    )
    require(
        config["guest_prefs_sha256"] == PREFS_SHA
        and config["guest_prefs_bytes"] == GUEST_PREFS_BYTES,
        f"{run.name} offline guest prefs differ",
    )
    prefs = (run.root / "sheep-prefs.txt").read_text()
    require(
        sha(prefs.encode()) == config["sheep_prefs_sha256"]
        and config["sheep_prefs_normalized_sha256"] == NORMAL_PREFS_SHA,
        f"{run.name} emulator prefs differ",
    )
    require(
        "ramsize 536870912" in prefs and "ether slirp" in prefs,
        f"{run.name} RAM or network mode differs",
    )


def check_launch(run: Run) -> None:
    """Check the readiness record and launch line of a run's lab."""
    ready = load(run.root / "boot/readiness.json")
    require(
        (ready.get("exe_sha256") or ready.get("emulator_sha256")) == EXE_SHA,
        f"{run.name} ready executable differs",
    )
    launch = load(run.root / "boot/lab-launch.json")["argv"]
    require(
        "--isolate-network" in launch
        and "--service" in launch
        and (str(run.frontend) in launch),
        f"{run.name} launch differs",
    )


def check_terminal(run: Run) -> None:
    """Check how a run's lab was retired and that the primary saw no SYN."""
    terminal = load(run.root / "terminal.json")
    if run.name == "c45":
        require(
            terminal["actual_pid_gone"] and terminal["owned_frontend_absent"],
            "C45 lab retirement differs",
        )
        require(
            terminal["guard_seed_ban_probe"].startswith("not run"),
            "C45 option-two scope differs",
        )
        require(
            "/proc" in terminal["cleanup_anomaly"]
            and "exit5" in terminal["cleanup_anomaly"],
            "C45 cleanup anomaly lost",
        )
        require(
            all(
                v["primary_syn_count"] == 0
                for v in terminal["primary_syn_views"].values()
            ),
            "C45 primary SYN differs",
        )
        return
    require(
        terminal["processes"]["lab"]["exists"] is False,
        f"{run.name} lab retirement differs",
    )
    require(
        all(
            v.get("syn_count", v.get("syn_lines")) == 0
            for v in terminal["primary_syn"].values()
        ),
        f"{run.name} primary SYN differs",
    )
    if run.name == "c35":
        require(
            terminal["guard_seed_ban_probe_executed"] is False,
            "C35 option-two scope differs",
        )
