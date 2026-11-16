"""Check the operator's reviewed Finder receipt and its screenshots.

Part of the missing-alias runner (``native_missing_alias_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import re
import typing as typ

import native_missing_alias_cases as cases
from native_missing_alias_control_frames import SCREEN_KEYS, Report, digest, need

if typ.TYPE_CHECKING:
    from pathlib import Path

SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")
TARGET_SIZE = 20
MAX_ALIAS_NAME = 31
FORBIDDEN_NAME_BYTES = (0, 47, 58)
UI_FLAGS = (
    "finder_active",
    "unix_target_selected",
    "make_alias_enabled",
    "separate_alias",
    "copy_enabled",
    "paste_enabled",
)


def _target_and_destination(receipt: Report, plan: Report) -> None:
    """Require the receipt to name the planned target and destination."""
    need(
        receipt.get("schema_version") == 1
        and receipt.get("target_name_hex") == plan["target"]["basename_hex"]
        and receipt.get("target_size") == TARGET_SIZE
        and receipt.get("target_sha256") == plan["target"]["sha256"]
        and receipt.get("owned_destination_hex") == cases.ROOT.hex(),
        "Operator target/destination differs",
    )


def _ui_flags(receipt: Report) -> None:
    """Require every Finder state flag, no prompt and exactly one action."""
    need(
        all(receipt.get(key) is True for key in UI_FLAGS)
        and receipt.get("unexpected_prompt") is False
        and receipt.get("overwrite_prompt") is False
        and receipt.get("action_count") == 1,
        "Finder UI gate/one-alias action differs",
    )


def _screenshots(receipt: Report) -> None:
    """Require one screenshot hash for each screen the review names."""
    screens = receipt.get("screenshots")
    need(
        isinstance(screens, dict)
        and set(screens) == set(SCREEN_KEYS)
        and all(
            isinstance(value, str) and SHA256_PATTERN.fullmatch(value) is not None
            for value in screens.values()
        ),
        "Finder screenshots missing",
    )


def operator_gate(receipt: Report, plan: Report) -> bytes:
    """Check the operator's receipt and return the alias basename it names.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The operator's reviewed receipt.
    plan : dict[str, typing.Any]
        The prepared plan.

    Returns
    -------
    bytes
        The basename of the alias that the operator made.
    """
    _target_and_destination(receipt, plan)
    _ui_flags(receipt)
    _screenshots(receipt)
    name = bytes.fromhex(receipt["alias_name_hex"])
    need(
        1 <= len(name) <= MAX_ALIAS_NAME
        and name != cases.TARGET
        and not any(c in name for c in FORBIDDEN_NAME_BYTES),
        "Dynamic alias basename invalid",
    )
    return name


def check_screens(receipt: Report, directory: Path) -> None:
    """Require each screenshot file to exist and carry its recorded hash."""
    need(
        (directory / "screens").is_dir() and not (directory / "screens").is_symlink(),
        "Finder screenshot directory differs",
    )
    for key, expected in receipt["screenshots"].items():
        image = directory / "screens" / f"{key}.png"
        need(
            image.is_file()
            and not image.is_symlink()
            and digest(image.read_bytes()) == expected,
            f"Finder screenshot differs: {key}",
        )
