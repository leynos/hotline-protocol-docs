#!/usr/bin/env python3
"""Prepare and launch local Mac test runtimes from user-supplied assets."""

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from mac_network_isolation import wait_for_bridge

ROOT = Path(__file__).resolve().parent.parent


def service_command(
    directory: Path, kind: str, command: list[str]
) -> tuple[str, list[str]]:
    """Give a long-lived process explicit user-service ownership and local logs."""
    identity = hashlib.sha256(str(directory.resolve()).encode()).hexdigest()[:12]
    unit = f"mothra-{kind}-{identity}"
    log = directory.resolve() / f"{kind}-service.log"
    return unit, [
        "systemd-run",
        "--user",
        f"--unit={unit}",
        "--collect",
        "--service-type=exec",
        f"--property=WorkingDirectory={ROOT}",
        f"--property=StandardOutput=append:{log}",
        f"--property=StandardError=append:{log}",
        "--property=Restart=no",
        "--",
        *command,
    ]


def start_service(directory: Path, kind: str, command: list[str]) -> None:
    """Record the exact request; service acceptance does not certify readiness."""
    unit, launch = service_command(directory, kind, command)
    subprocess.run(launch, check=True)
    (directory / f"{kind}-service.json").write_text(
        json.dumps(
            {
                "unit": unit,
                "command": launch,
                "readiness": "Check systemctl --user show and the actual display/listener; no automatic restart",
            },
            indent=2,
        )
        + "\n"
    )
    print(unit)


def launch_display(args: argparse.Namespace) -> None:
    """Run an isolated X server under the user service manager."""
    if not args.display.startswith(":") or not args.display[1:].isdecimal():
        raise ValueError("Expected a local display such as :99")
    target = args.directory.resolve()
    if not target.is_relative_to(ROOT / "state"):
        raise ValueError("Display state must be under mothra/state")
    xvfb = shutil.which("Xvfb")
    if xvfb is None:
        raise FileNotFoundError("Xvfb")
    target.mkdir(parents=True, exist_ok=False)
    start_service(
        target,
        "display",
        [
            xvfb,
            args.display,
            "-screen",
            "0",
            "1024x768x24",
            "-nolisten",
            "tcp",
            "-ac",
            "-noreset",
        ],
    )


def managed_sheep(args: argparse.Namespace) -> None:
    """Use the ordinary locked/hash-checked launcher inside a managed process."""
    if getattr(args, "isolate_network", False):
        start_isolated_sheep(args)
    else:
        start_service(args.directory, "sheep", sheep_child_command(args))


def sheep_child_command(args: argparse.Namespace) -> list[str]:
    """Return the command line that starts the emulator child process."""
    command = [
        sys.executable,
        str(Path(__file__).resolve()),
        "sheep",
        str(args.directory),
        "--display",
        args.display,
        "--port",
        str(args.port),
    ]
    if args.guest_pcap is not None:
        command += ["--guest-pcap", str(args.guest_pcap.resolve())]
    return command


def isolated_sheep_command(args: argparse.Namespace, bridge_socket: Path) -> list[str]:
    """Put unshare inside the service child, preserving the normal VM launcher."""
    script = ROOT / "scripts/mac_network_isolation.py"
    data_socket = (
        ["--data-socket", str(bridge_socket.parent / "data-bridge.sock")]
        if getattr(args, "isolate_data_port", False)
        else []
    )
    return [
        "sudo",
        "-n",
        "unshare",
        "--net",
        "--",
        sys.executable,
        str(script),
        "bootstrap",
        "--socket",
        str(bridge_socket),
        "--listen-port",
        "15500",
        "--display",
        args.display,
        "--uid",
        str(os.getuid()),
        "--gid",
        str(os.getgid()),
        *data_socket,
        "--",
        *sheep_child_command(args),
    ]


def start_isolated_sheep(args: argparse.Namespace) -> None:
    """Start an exclusive fixed-target bridge before the isolated VM service."""
    target = args.directory.resolve()
    if not target.is_relative_to(ROOT / "state") or not target.is_dir():
        raise ValueError("Isolated runtime must be an existing mothra state directory")
    reserved = {15500, 15501} if getattr(args, "isolate_data_port", False) else {15500}
    if reserved.intersection(range(args.port, args.port + 4)):
        raise ValueError("Namespace relay port overlaps VM redirection ports")
    network = target / "isolated-network"
    network.mkdir(mode=0o700, exist_ok=False)
    bridge_socket = network / "bridge.sock"
    script = str(ROOT / "scripts/mac_network_isolation.py")
    bridge_command = [
        sys.executable,
        script,
        "host-bridge",
        "--socket",
        str(bridge_socket),
        "--target-port",
        "15500",
    ]
    bridge_unit, _ = service_command(network, "bridge", bridge_command)
    x_command = [
        sys.executable,
        script,
        "host-x-bridge",
        "--socket",
        str(network / "x-bridge.sock"),
        "--display",
        args.display,
    ]
    x_unit, _ = service_command(network, "xbridge", x_command)
    data_command = [
        sys.executable,
        script,
        "host-bridge",
        "--socket",
        str(network / "data-bridge.sock"),
        "--target-port",
        "15501",
    ]
    data_unit, _ = service_command(network, "dbridge", data_command)
    try:
        start_service(network, "bridge", bridge_command)
        wait_for_bridge(bridge_socket)
        start_service(network, "xbridge", x_command)
        wait_for_bridge(network / "x-bridge.sock")
        if getattr(args, "isolate_data_port", False):
            start_service(network, "dbridge", data_command)
            wait_for_bridge(network / "data-bridge.sock")
        start_service(target, "sheep", isolated_sheep_command(args, bridge_socket))
    except BaseException:
        if getattr(args, "isolate_data_port", False):
            subprocess.run(["systemctl", "--user", "stop", data_unit], check=False)
        subprocess.run(["systemctl", "--user", "stop", x_unit], check=False)
        subprocess.run(["systemctl", "--user", "stop", bridge_unit], check=False)
        raise


def sha256(path: Path) -> str:
    """Hash a disk or ROM without loading the entire asset into memory."""
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def prepare(args: argparse.Namespace) -> None:
    """Copy supplied assets into a new runtime; preserve existing runtimes."""
    target = args.directory.resolve()
    if not target.is_relative_to(ROOT / "state"):
        raise ValueError("Runtime directory must be under mothra/state")
    target.mkdir(parents=True, exist_ok=False)
    shutil.copyfile(args.rom, target / "rom")
    if zipfile.is_zipfile(args.disk):
        with zipfile.ZipFile(args.disk) as archive:
            members = [item for item in archive.infolist() if not item.is_dir()]
            if args.member:
                member = archive.getinfo(args.member)
            elif len(members) == 1:
                member = members[0]
            else:
                raise ValueError("Specify --member for an archive with multiple files")
            with (
                archive.open(member) as source,
                (target / "base.dsk").open("xb") as out,
            ):
                shutil.copyfileobj(source, out)
    else:
        shutil.copyfile(args.disk, target / "base.dsk")
    (target / "base.dsk").chmod(0o444)
    subprocess.run(
        [
            "cp",
            "--reflink=auto",
            "--sparse=always",
            str(target / "base.dsk"),
            str(target / "working.dsk"),
        ],
        check=True,
    )
    (target / "working.dsk").chmod(0o644)
    (target / "shared").mkdir()
    (target / "assets.json").write_text(
        json.dumps(
            {
                "rom_sha256": sha256(target / "rom"),
                "base_disk_sha256": sha256(target / "base.dsk"),
                "source_rom": str(args.rom.resolve()),
                "source_disk": str(args.disk.resolve()),
                "archive_member": args.member,
            },
            indent=2,
        )
        + "\n"
    )
    print(target)


def launch_sheep(args: argparse.Namespace) -> None:
    """Launch the pinned emulator with scoped low-memory mapping capability."""
    target = args.directory.resolve()
    if not target.is_relative_to(ROOT / "state"):
        raise ValueError("Runtime directory must be under mothra/state")
    for name in ["rom", "working.dsk", "shared"]:
        if not (target / name).exists():
            raise FileNotFoundError(target / name)
    if (
        sha256(target / "rom")
        != json.loads((target / "assets.json").read_text())["rom_sha256"]
    ):
        raise ValueError("ROM changed after preparation")
    vm = target / "machine.sheepvm"
    vm.mkdir(exist_ok=True)
    preferences = [
        f"disk {target / 'working.dsk'}",
        f"rom {target / 'rom'}",
        f"extfs {target / 'shared'}",
        "screen win/1024/768",
        "ramsize 536870912",
        "frameskip 0",
        "gfxaccel true",
        "nocdrom true",
        "nonet false",
        "nosound true",
        "nogui true",
        "jit false",
        "jit68k false",
        "idlewait true",
        "ether slirp",
    ]
    for offset in range(4):
        preferences.append(f"redir tcp:{args.port + offset}:10.0.2.15:{5500 + offset}")
    (vm / "prefs").write_text("\n".join(preferences) + "\n")
    built_binary = ROOT / "tools/macemu/SheepShaver/src/Unix/SheepShaver"
    build = json.loads((ROOT / "state/sheepshaver-build/manifest.json").read_text())
    if sha256(built_binary) != build["binary_sha256"]:
        raise ValueError("Emulator binary differs from recorded build")
    # Keep running mappings independent of a later source-tree rebuild.
    binary = target / ("SheepShaver-" + build["binary_sha256"])
    if not binary.exists():
        shutil.copyfile(built_binary, binary)
        binary.chmod(0o755)
    if sha256(binary) != build["binary_sha256"]:
        raise ValueError("Runtime emulator copy differs from recorded build")
    capture = ""
    if args.guest_pcap is not None:
        path = args.guest_pcap.resolve()
        if not path.is_relative_to(ROOT / "state"):
            raise ValueError("Guest packet capture must be under mothra/state")
        if path.exists():
            raise FileExistsError(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        capture = str(path)
    command = [
        "sudo",
        "-n",
        "setpriv",
        f"--reuid={os.getuid()}",
        f"--regid={os.getgid()}",
        "--init-groups",
        "--inh-caps=+sys_rawio",
        "--ambient-caps=+sys_rawio",
        "env",
        f"DISPLAY={args.display}",
        "SDL_VIDEODRIVER=x11",
        "SDL_AUDIODRIVER=dummy",
        f"MOTHRA_ETHERNET_PCAP={capture}",
        f"XDG_CACHE_HOME={target / 'cache'}",
        str(binary),
        str(vm),
    ]
    (target / "last-launch.json").write_text(
        json.dumps(
            {
                "command": command,
                "emulator_sha256": build["binary_sha256"],
                "host_ports": list(range(args.port, args.port + 4)),
                "tcp_bind": "127.0.0.1",
                "guest_address": "10.0.2.15",
                "guest_pcap": capture or None,
                "guest_pcap_scope": "SLiRP Ethernet boundary; host wall-clock timestamps",
            },
            indent=2,
        )
        + "\n"
    )
    subprocess.run(command, check=True)


def main() -> None:
    """Prepare a new disk copy or launch an existing prepared runtime."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("directory", type=Path)
    create.add_argument("--rom", type=Path, required=True)
    create.add_argument("--disk", type=Path, required=True)
    create.add_argument("--member")
    run = commands.add_parser("sheep")
    run.add_argument("directory", type=Path)
    run.add_argument("--display", default=os.environ.get("DISPLAY", ":0"))
    run.add_argument("--port", type=int, default=15500)
    run.add_argument("--guest-pcap", type=Path)
    run.add_argument("--service", action="store_true")
    run.add_argument("--isolate-network", action="store_true")
    run.add_argument("--isolate-data-port", action="store_true")
    display = commands.add_parser("display")
    display.add_argument("directory", type=Path)
    display.add_argument("--display", required=True)
    args = parser.parse_args()
    if args.command == "prepare":
        prepare(args)
    elif args.command == "display":
        launch_display(args)
    else:
        if not 1024 <= args.port <= 65532:
            parser.error("Four forwarded ports must fit in 1024–65535")
        args.directory = args.directory.resolve()
        if not args.directory.is_relative_to(ROOT / "state"):
            parser.error("Runtime directory must be under mothra/state")
        if args.isolate_network and not args.service:
            parser.error("--isolate-network requires --service")
        if args.isolate_data_port and not (args.isolate_network and args.service):
            parser.error("--isolate-data-port requires --isolate-network --service")
        if args.service:
            managed_sheep(args)
            return
        # Keep this parent alive: sudo closes inherited descriptors by default.
        with (args.directory / "runtime.lock").open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                parser.error("Runtime is already in use")
            launch_sheep(args)


if __name__ == "__main__":
    main()
