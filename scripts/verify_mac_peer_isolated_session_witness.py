"""Check the recorded namespace, bridge, emulator and asset witnesses of the session."""

import json
import typing as typ

from verify_mac_peer_first_session import require

if typ.TYPE_CHECKING:
    from pathlib import Path


def check_isolation(directory: Path) -> None:
    """Require the recorded namespace, bridge, emulator and asset witnesses to match."""
    host = (directory / "host-netns.txt").read_text().strip()
    guest = (directory / "emulator-netns.txt").read_text().strip()
    require(
        host.startswith("net:[") and guest.startswith("net:[") and host != guest,
        "Actual guest/host namespace witness differs",
    )
    require(
        not (directory / "namespace-v4-routes.txt").read_text()
        and not (directory / "namespace-v6-routes.txt").read_text(),
        "Guest namespace has nonlocal route",
    )
    require(
        (directory / "namespace-addresses.txt").read_text().strip()
        == "lo               UNKNOWN        127.0.0.1/8 ::1/128",
        "Guest namespace interface witness differs",
    )
    for name, target in (
        ("bridge-ready.json", ["127.0.0.1", 15500]),
        ("data-bridge-ready.json", ["127.0.0.1", 15501]),
    ):
        item = json.loads((directory / name).read_text())
        require(
            item["fixed_target"]
            == {"kind": "tcp", "address": target, "synthetic": False}
            and item["netns"] == host,
            "Fixed host bridge witness differs",
        )
    x = json.loads((directory / "x-bridge-ready.json").read_text())
    require(
        x["fixed_target"] == {"kind": "x-abstract", "display": ":107"}
        and x["netns"] == host,
        "Fixed X bridge witness differs",
    )
    fds = (directory / "emulator-fds.txt").read_text()
    require(
        "hotline-client-isolated-01/working.dsk" in fds
        and "mac-peer-isolated-01/client-guest.pcap" in fds,
        "Emulator FD witness missing",
    )
    require(
        "7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315"
        in (directory / "return-hashes.txt").read_text()
        and "f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b"
        in (directory / "return-hashes.txt").read_text(),
        "Finder fork witness differs",
    )
    assets = json.loads((directory / "assets.json").read_text())
    require(
        assets["rom_sha256"]
        == "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
        and assets["base_disk_sha256"]
        == "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910",
        "Stopped base/ROM identity witness differs",
    )
    require(
        (directory / "emulator-hash.txt")
        .read_text()
        .startswith("9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"),
        "Actual emulator hash witness differs",
    )
    require(
        "CapAmb:\t0000000000020000" in (directory / "emulator-status.txt").read_text()
        and "name of display:    :107"
        in (directory / "namespace-xdpyinfo.txt").read_text(),
        "Actual capability/X witness differs",
    )
    require(
        "length 32 type APPL creator HTLC"
        in (directory / "return-finder.txt").read_text(),
        "Finder type/creator witness differs",
    )
