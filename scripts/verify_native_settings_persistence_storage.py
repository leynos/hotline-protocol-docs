"""Check the stopped storage of the persistence corpus: forks, images, inode."""

import dataclasses as dc
import re
import typing as typ

from protocol_capture import digest
from verify_native_settings_persistence_core import (
    FORKS,
    PHASES,
    Json,
    read_json,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

FIRST_IMAGE_SHA = "e7ff40564780c0eb4b3e5bfdb24f8c4d37c3d1dbb7b4a77216d71c7be616aafa"
FINAL_IMAGE_SHA = "be0b2c95c1ddd06e678bc31941bb01fb744d70fee50e28c82f2a71910c8f7d0a"
STATE = "state/mac-runtime/native-settings-persistence-01"
IMAGE_BYTES = 8388608000  # the working image's size


@dc.dataclass(frozen=True, slots=True)
class Assets:
    """The A41 baseline of the stopped assets.

    Attributes
    ----------
    base : dict[str, typing.Any]
        The baseline record.
    path : str
        The working image's path.
    inode : int
        The working image's inode.
    """

    base: Json
    path: str
    inode: int


def baseline_assets(corpus: Path) -> Assets:
    """Read the A41 baseline of the stopped assets and check its identity.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    Assets
        The baseline, and the path and inode of the working image.
    """
    base = read_json(corpus / "baseline/a41-assets.json")
    require(
        base["profile"] == "control-only" and not base["booted"],
        "A41 baseline identity differs",
    )
    return Assets(base, base["target_working"]["path"], base["target_working"]["inode"])


def stored_forks(directory: Path, phase: int, assets: Assets) -> None:
    """Check each stored fork against its path, its bytes and the A41 baseline.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    phase : int
        The phase number, 1 or 2.
    assets : Assets
        The A41 baseline.
    """
    paths = dict(
        line.split("\t", 1)
        for line in (directory / "stopped-path-ids.txt").read_text().splitlines()
    )
    for catalog, (name, size, value) in FORKS.items():
        fork = directory / f"stopped-fork-{catalog}.bin"
        require(paths[name] == str(catalog), f"Phase {phase} HFS path differs")
        require(
            fork.stat().st_size == size and digest(fork.read_bytes()) == value,
            f"Phase {phase} stored fork differs",
        )
        require(
            assets.base["objects"][name]
            == {"catalog": catalog, "data_size": size, "data_sha256": value},
            "A41 stored fork baseline differs",
        )


def stopped_image(directory: Path, phase: int, image_hash: str, assets: Assets) -> None:
    """Check the stopped image's hash, the immutable base's and the inode.

    Parameters
    ----------
    directory : pathlib.Path
        The phase directory.
    phase : int
        The phase number, 1 or 2.
    image_hash : str
        The working image's expected SHA-256.
    assets : Assets
        The A41 baseline.
    """
    hashes = (directory / "stopped-image-hashes.txt").read_text()
    require(
        f"{image_hash}  {STATE}/working.dsk" in hashes,
        f"Phase {phase} stopped image hash differs",
    )
    require(
        f"{assets.base['target_base']['sha256']}  {STATE}/base.dsk" in hashes,
        "Immutable base hash differs",
    )
    stat = (directory / "stopped-assets-stat.txt").read_text()
    require(
        assets.path.endswith(f"/{STATE}/working.dsk")
        and re.search(rf"{STATE}/working\.dsk \d+ {assets.inode} {IMAGE_BYTES}", stat)
        is not None,
        "Same working image inode differs",
    )


def stopped_storage(corpus: Path) -> Json:
    """Check that both phases stopped on the same image, with the forks unchanged.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The image identity and the unchanged-fork claim.
    """
    assets = baseline_assets(corpus)
    for phase, image_hash in zip(
        PHASES, (FIRST_IMAGE_SHA, FINAL_IMAGE_SHA), strict=True
    ):
        directory = corpus / f"phase{phase}"
        stored_forks(directory, phase, assets)
        stopped_image(directory, phase, image_hash, assets)
    preboot = (corpus / "phase2/preboot-hashes.txt").read_text()
    require(
        FIRST_IMAGE_SHA in preboot and assets.base["target_base"]["sha256"] in preboot,
        "A48 preboot was not A46 stopped image",
    )
    return {
        "same_working_inode": assets.inode,
        "phase1_image_sha256": FIRST_IMAGE_SHA,
        "phase2_image_sha256": FINAL_IMAGE_SHA,
        "forks_unchanged": True,
    }
