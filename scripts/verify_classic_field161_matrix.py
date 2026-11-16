"""Replay the finite B52 Classic field-161 matrix from portable PCAPs."""

import json
import typing as typ
from pathlib import Path

from classic_login_proxy import transform_ack
from mothra_root import mothra_root
from pcap_tcp import read_packets
from script_cli import run
from verify_classic_field161_matrix_capture import check_readiness, check_selection
from verify_classic_field161_matrix_case import check_case
from verify_classic_field161_matrix_common import (
    AGREEMENT_SHA,
    CAPTURE_VIEWS,
    EXPECTED_FIELDS,
    SOURCE_ACK_HEX,
    SOURCE_ACK_SHA,
    SOURCE_SHAS,
    VARIANTS,
    digest,
    inventory,
    require,
)
from verify_classic_native_baseline import verify_a7

# The test imports check_case, check_readiness, check_source_snapshot and verify.
# The other names are kept importable because the original module defined them
# or imported them at module level, so that code which reached them through
# this module still does. The helper modules hold the definitions.
__all__ = [
    "AGREEMENT_SHA",
    "EXPECTED_FIELDS",
    "SOURCE_ACK_HEX",
    "SOURCE_ACK_SHA",
    "SOURCE_SHAS",
    "VARIANTS",
    "check_case",
    "check_readiness",
    "check_selection",
    "check_source_snapshot",
    "digest",
    "inventory",
    "main",
    "require",
    "transform_ack",
    "verify",
]


def check_source_snapshot(base: Path, source: dict[str, typ.Any], key: str) -> None:
    """Check a frozen source snapshot against its recorded provenance and hash.

    Parameters
    ----------
    base : Path
        The corpus directory.
    source : dict[str, typing.Any]
        The ``source`` record of the manifest.
    key : str
        ``proxy`` or ``parser``.
    """
    names = {"proxy": "classic_login_proxy.py", "parser": "pcap_tcp.py"}
    require(key in names, "unknown source snapshot")
    name = names[key]
    require(
        source[f"{key}_path"] == f"../hotline-protocol-docs/scripts/{name}"
        and source[f"{key}_revision"] == "79d867dc80c0aea50ad77569aae89e1d0bf37915"
        and source[f"{key}_snapshot_path"] == f"as-run/{name}.txt",
        f"{key} source provenance",
    )
    require(
        source[f"{key}_sha256"] == SOURCE_SHAS[key],
        f"{key} source provenance",
    )
    require(
        digest((base / source[f"{key}_snapshot_path"]).read_bytes())
        == source[f"{key}_sha256"],
        f"{key} source snapshot",
    )


def verify(base: Path) -> dict[str, typ.Any]:
    """Replay the matrix corpus and return the verdict of each check group.

    Parameters
    ----------
    base : Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The A7 verdict, the capture readiness and the verdict of each case.
    """
    base = base.resolve()
    inventory(base)
    manifest = json.loads((base / "manifest.json").read_text())
    require(
        manifest["schema_version"] == 1 and set(manifest["cases"]) == set(VARIANTS),
        "manifest cases",
    )
    require(
        manifest["original_ack_hex"] == SOURCE_ACK_HEX
        and manifest["original_ack_sha256"] == SOURCE_ACK_SHA,
        "original two-zero ACK guard",
    )
    root = mothra_root()
    source = manifest["source"]
    for key in ("proxy", "parser"):
        check_source_snapshot(base, source, key)
    require(
        digest((root / "scripts/capture_readiness.py").read_bytes())
        == manifest["capture_gate_sha256"],
        "capture gate source identity",
    )
    require(
        source["client_data_sha256"].startswith("7f286e3f")
        and source["client_resource_sha256"].startswith("f762cfde")
        and source["client_vers_short"] == "1.9.1.0",
        "client identity record",
    )
    packets = {
        "pcaps/" + p.name: read_packets(p) for p in (base / "pcaps").glob("*.pcap")
    }
    require(len(packets) == CAPTURE_VIEWS, "four selected capture views")
    check_selection(base, manifest, packets)
    return {
        "a7": verify_a7(base),
        "capture": check_readiness(base, manifest),
        "cases": {
            name: check_case(base, name, manifest["cases"][name], packets)
            for name in VARIANTS
        },
    }


def show(corpus: str) -> None:
    """Replay a field-161 corpus and print its verdict as JSON.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    print(json.dumps(verify(Path(corpus)), indent=2))


def main() -> None:
    """Replay the field-161 matrix corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
