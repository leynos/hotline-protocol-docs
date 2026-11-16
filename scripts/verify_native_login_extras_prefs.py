"""Read and check the native server preferences that the login extras set.

The order of the checks in each function is the order in which a corrupt record
is refused, so a function reads its evidence in the sequence that it always has.
"""

import json
import typing as typ

from native_banner_cases import URL
from native_login_extras_cases import CONFIGURED_URL, NAMES
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

PREFS_PATH = "/Hotline19/Prefs"
PREFS_MIN_BYTES = 86
PREFS_VERSION = b"\0\5"
GENERAL_START = 54  # the General configuration words start here
GENERAL = (5, 5500, 100, 10)
FLAGS_START = 60
FLAGS_END = 64
PASCAL_START = 76  # the ten Pascal strings start here
PASCAL_COUNT = 10
SERVER_NAME_INDEX = 3
SERVER_NAME_LIMIT = 31
LOCAL_BANNER_FLAG = 128
LOCAL_BANNER_STRINGS = [b"mothra-banner-b.gif", URL, b""]
REMOTE_BANNER_INDEX = 9
REMOTE_CONFIGURATIONS = {"url", "none"}


def preference_words(data: bytes) -> tuple[int, ...]:
    """Read the four General configuration words of a preferences record.

    Returns
    -------
    tuple[int, ...]
        The version, the port and the two limits, as the stored words.
    """
    return (
        int.from_bytes(data[GENERAL_START : GENERAL_START + 2], "big"),
        int.from_bytes(data[64:66], "big"),
        int.from_bytes(data[66:68], "big"),
        int.from_bytes(data[68:70], "big"),
    )


def pascal_strings(data: bytes) -> list[bytes]:
    """Read the ten Pascal strings that follow the General configuration.

    Returns
    -------
    list[bytes]
        The string contents, in order.
    """
    values = []
    position = PASCAL_START
    for _ in range(PASCAL_COUNT):
        require(position < len(data), "Missing native Pascal length")
        length = data[position]
        require(position + 1 + length <= len(data), "Truncated native Pascal content")
        values.append(data[position + 1 : position + 1 + length])
        position += 1 + length
    return values


def preferences(directory: Path) -> Report:
    """Read the native Prefs record of a retained extraction.

    Returns
    -------
    dict[str, typing.Any]
        The server name, the strings, the flag word and the whole record.
    """
    extraction = json.loads((directory / "extraction.json").read_text())
    records = [r for r in extraction["records"] if r["path"] == PREFS_PATH]
    require(
        len(records) == 1 and not records[0]["directory"],
        "Missing positive native Prefs record",
    )
    record = records[0]
    require(record["attributes"]["data"]["exit_code"] == 0, "Native Prefs read failed")
    data = (directory / (record["key"] + ".data")).read_bytes()
    require(
        len(data) >= PREFS_MIN_BYTES and data[:2] == PREFS_VERSION,
        "Native Prefs version/prefix differs",
    )
    require(preference_words(data) == GENERAL, "Native General configuration drifted")
    values = pascal_strings(data)
    require(
        len(values[SERVER_NAME_INDEX]) <= SERVER_NAME_LIMIT,
        "Native server-name destination exceeds31 bytes",
    )
    return {
        "name": values[SERVER_NAME_INDEX],
        "strings": values,
        "flags": int.from_bytes(data[FLAGS_START:FLAGS_END], "big"),
        "bytes": data,
    }


def check_configuration(name: str, prefs: Report) -> None:
    """Check one stored configuration's server name and banner settings."""
    require(prefs["name"] == NAMES[name], "Native stored server name differs")
    if name in REMOTE_CONFIGURATIONS:
        require(
            not prefs["flags"] & LOCAL_BANNER_FLAG
            and prefs["strings"][REMOTE_BANNER_INDEX]
            == (CONFIGURED_URL if name == "url" else b""),
            "Native remote banner configuration differs",
        )
    else:
        require(
            prefs["flags"] & LOCAL_BANNER_FLAG
            and prefs["strings"][7:10] == LOCAL_BANNER_STRINGS,
            "Native Local banner configuration differs",
        )


def check_configurations(directory: Path, manifest: Report) -> None:
    """Check every stored configuration, and that the original was restored."""
    require(
        set(manifest["configurations"]) == set(NAMES),
        "Native configuration inventory differs",
    )
    for name, path in manifest["configurations"].items():
        check_configuration(name, preferences(directory / path))
    original = preferences(directory / manifest["original_preferences"])
    restored = preferences(directory / manifest["configurations"]["restored"])
    require(
        original["name"] == restored["name"] == b"",
        "Original empty name was not restored",
    )
    require(
        original["bytes"] == restored["bytes"],
        "Full native preference bytes were not restored",
    )
