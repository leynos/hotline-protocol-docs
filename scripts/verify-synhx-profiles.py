#!/usr/bin/env python3
"""Verify bounded RCS identity, declared versions and tested-build applicability."""

import hashlib
import json
import re
import tarfile
import typing as typ
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECTORY = ROOT / "evidence/gap-remediation/2026-11-13/synhx-profile-01"
NAMES = {
    "README",
    "version.c",
    "configure.in",
    "config.h.in",
    "acconfig.h",
    "hxd_config.c",
}
FLAGS = [
    "--enable-tty",
    "--enable-hfs",
    "--enable-htxf-fork",
    "--disable-gtk",
    "--disable-hope",
    "--disable-cipher",
    "--disable-compress",
    "--disable-ipv6",
]
PEER = "8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0"
SERVER_METADATA_ARCHIVES = 6  # the server archives that the manifest declares
PROTOCOL_ARCHIVES = 14  # the original protocol-source archives
CONFIGURE_OPTIONS = 18  # the AC_ARG_ENABLE options that the manifest declares


def require(condition: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # the public signature takes the condition positionally
    """Raise a ValueError with ``message`` unless ``condition`` holds.

    Raises
    ------
    ValueError
        When the condition does not hold.
    """
    if not condition:
        raise ValueError(message)


def _present[T](value: T | None) -> T:
    """Return a value that the caller has already required to be present.

    Returns
    -------
    T
        The value, unchanged.

    Raises
    ------
    AssertionError
        When the value is absent, which the caller's requirement rules out.
    """
    if value is None:
        raise AssertionError
    return value


def selected(archive: str, revision: str) -> bytes:
    """Return the bounded text of one RCS revision.

    Returns
    -------
    bytes
        The Latin-1 bytes of the revision text, with doubled ``@`` unescaped.
    """
    match = re.search(
        r"\n"
        + re.escape(revision)
        + r"\s*\nlog\s*\n@(?:@@|[^@])*@\s*\ntext\s*\n@((?:@@|[^@])*)@",
        archive,
    )
    require(match is not None, "Missing bounded revision text")
    return _present(match)[1].replace("@@", "@").encode("latin1")


def check_archive(raw: bytes, snapshot: bytes) -> None:
    """Check one RCS archive against its selected trunk and empty vendor delta."""
    text = raw.decode("latin1")
    require(
        re.search(r"^head\s+1\.1;", text) is not None
        and re.search(r"^branch\s+1\.1\.1;", text, re.MULTILINE) is not None,
        "Unexpected RCS selected/default relationship",
    )
    require(selected(text, "1.1") == snapshot, "Selected trunk content differs")
    require(selected(text, "1.1.1.1") == b"", "Vendor delta is not empty")


def _check_server_archives(directory: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the server metadata inventory and every archive that it names."""
    require(
        {Path(r["selected"]).name for r in manifest["archives"]}
        == {n + ".txt" for n in NAMES}
        and len(manifest["archives"]) == SERVER_METADATA_ARCHIVES,
        "Server metadata inventory differs",
    )
    for record in manifest["archives"]:
        raw, snapshot = (
            (directory / record["archive"]).read_bytes(),
            (directory / record["selected"]).read_bytes(),
        )
        require(
            hashlib.sha256(raw).hexdigest() == record["archive_sha256"]
            and hashlib.sha256(snapshot).hexdigest() == record["selected_sha256"],
            "Server metadata identity differs",
        )
        check_archive(raw, snapshot)


def _check_server_version(directory: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the declared server source version."""
    version = (directory / "selected/version.c.txt").read_text()
    require(
        version == 'const char *hxd_version = "0.1.48.1";\n'
        and manifest["declared_server_version"] == "0.1.48.1",
        "Declared server source version differs",
    )


def _check_server_package(directory: Path) -> None:
    """Check that the server package is not confused with the client package."""
    readme = (directory / "selected/README.txt").read_text()
    require(
        "This is the server package." in readme
        and "hxd-0.1.41" in readme
        and "download\nshx" in readme,
        "Server/client package distinction lost",
    )


def _configure_options(configure: str) -> list[dict[str, str]]:
    """Return the declared default of each configure option, in file order.

    Returns
    -------
    list[dict[str, str]]
        The option name, declared default and source line of each option.
    """
    options: list[dict[str, str]] = []
    for line in configure.splitlines():
        if line.startswith("AC_ARG_ENABLE("):
            name = re.search(r"AC_ARG_ENABLE\(([^,]+),", line)
            default = re.search(r"enable_\w+=(\w+)\)", line)
            require(
                name is not None and default is not None,
                "Unrecognized configure option",
            )
            options.append({
                "option": _present(name)[1],
                "declared_default": _present(default)[1],
                "line": line,
            })
    return options


def _check_configure(directory: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the configure options and the two effective default branches."""
    configure = (directory / "selected/configure.in.txt").read_text()
    options = _configure_options(configure)
    require(
        options == manifest["configuration_options"]
        and len(options) == CONFIGURE_OPTIONS,
        "Declared configure defaults differ",
    )
    require(
        "if test $enable_hotline_server = no -a $enable_tracker_server = no; then\n"
        "\tenable_hotline_server=yes;" in configure,
        "Server effective default branch differs",
    )
    require(
        "\tif test $enable_htxf_clone = yes; then\n\t\tAC_DEFINE(CONFIG_HTXF_CLONE)\n"
        "\telse\n\t\tenable_htxf_fork=yes;" in configure,
        "Transfer-model fallback differs",
    )


def _check_original_lineage() -> None:
    """Check every original protocol-source archive against its selected snapshot."""
    old = json.loads(
        (
            ROOT
            / "evidence/gap-remediation/2026-11-12/batch-08/synhx-lineage-review.json"
        ).read_text()
    )
    require(
        len(old["archives"]) == PROTOCOL_ARCHIVES,
        "Original protocol-source inventory differs",
    )
    for record in old["archives"]:
        path = ROOT / record["archive"]
        raw = path.read_bytes()
        require(
            hashlib.sha256(raw).hexdigest() == record["sha256"],
            "Original source archive identity differs",
        )
        check_archive(raw, path.with_suffix("").read_bytes())


def _check_client_source(build_dir: Path, build: dict[str, typ.Any]) -> None:
    """Check the client source archive identity and its declared version."""
    client_archive = build_dir.parent / "inputs/source.tar.gz"
    require(
        hashlib.sha256(client_archive.read_bytes()).hexdigest()
        == build["source_archive_sha256"],
        "Client source archive identity differs",
    )
    with tarfile.open(client_archive, "r:gz") as archive:
        version_file = archive.extractfile("version.c")
        require(version_file is not None, "Missing client version source")
        require(
            _present(version_file).read() == b'const char *hxd_version = "0.1.48";\n',
            "Declared client source version differs",
        )


def _check_build_profile(build_dir: Path, build: dict[str, typ.Any]) -> None:
    """Check the compiled client profile, its macros and its configuration identity."""
    require(
        build["configuration_flags"] == FLAGS
        and build["binary_sha256"] == PEER
        and build["source_commit"] == "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b",
        "Compiled client profile differs",
    )
    config = (build_dir / "config.h").read_text()
    defines = set(re.findall(r"^#define (CONFIG_\w+) 1$", config, re.MULTILINE))
    require(
        {"CONFIG_HFS", "CONFIG_HTXF_FORK"} <= defines
        and not (
            {
                "CONFIG_HOPE",
                "CONFIG_CIPHER",
                "CONFIG_COMPRESS",
                "CONFIG_IPV6",
                "CONFIG_HTXF_PTHREAD",
                "CONFIG_HTXF_CLONE",
            }
            & defines
        ),
        "Effective client macros differ",
    )
    require(
        hashlib.sha256((build_dir / "config.h").read_bytes()).hexdigest()
        == build["config_h_sha256"],
        "Effective configuration identity differs",
    )


def _check_peer_corpora() -> None:
    """Check that each native shx corpus was observed against the tested peer."""
    for corpus in ["native-shx-01", "native-shx-02"]:
        current = json.loads(
            (
                ROOT / "evidence/gap-remediation/2026-11-13" / corpus / "manifest.json"
            ).read_text()
        )
        require(
            current["peer_binary_sha256"] == PEER,
            "Peer observations were assigned to another build",
        )


def _check_applicability(manifest: dict[str, typ.Any]) -> None:
    """Check that the three applicability scopes are kept apart."""
    require(
        {r["profile"] for r in manifest["applicability"]}
        == {
            "selected-server-source",
            "selected-client-source",
            "compiled-terminal-peer",
        },
        "Applicability scopes differ",
    )


def verify(directory: Path = DIRECTORY) -> dict[str, typ.Any]:
    """Verify the retained source, build and applicability records.

    Returns
    -------
    dict[str, typing.Any]
        The verified versions, the tested peer identity and the scope statement.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    _check_server_archives(directory, manifest)
    _check_server_version(directory, manifest)
    _check_server_package(directory)
    _check_configure(directory, manifest)
    _check_original_lineage()
    build_dir = ROOT / "evidence/gap-remediation/2026-11-13/shx-build-01/build"
    build = json.loads((build_dir / "manifest.json").read_text())
    _check_client_source(build_dir, build)
    _check_build_profile(build_dir, build)
    _check_peer_corpora()
    _check_applicability(manifest)
    return {
        "server_protocol_archives": PROTOCOL_ARCHIVES,
        "server_metadata_archives": SERVER_METADATA_ARCHIVES,
        "declared_server_source_version": "0.1.48.1",
        "client_source_version": "0.1.48",
        "tested_peer_sha256": PEER,
        "scope": "Selected static server source and conditional branches; "
        "separately identified client source and one modern configured executable. "
        "No released-tarball or deployed historical server identity inferred.",
    }


if __name__ == "__main__":
    print(json.dumps(verify(), indent=2))
