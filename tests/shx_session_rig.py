"""A synthetic checkout and a fake terminal for the ``capture_shx_session`` tests."""

import dataclasses as dc
import hashlib
import importlib
import json
import typing as typ
from pathlib import Path

from script_loading import ROOT, load_script
from shx_session_fakes import Terminal

if typ.TYPE_CHECKING:
    import types

    import pytest

SCRIPT = ROOT / "scripts/capture_shx_session.py"
COMMIT = "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b"
PEER_BYTES = b"peer binary"
ORACLE_BYTES = b"oracle binary"
STEPS = [
    {"command": "help", "expect": "Commands"},
    {"command": "quit", "expect_exit": 0},
]
REPLIES = {"help": b"\x1b[1mCommands\x1b[0m: a b\r\n", "quit": b"bye\r\n"}
EXITS = {"quit": 0}
BOUND = 8 * 1024 * 1024


def sha(data: bytes) -> str:
    """Hash some bytes.

    Returns
    -------
    str
        The hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


@dc.dataclass(slots=True)
class Rig:
    """A synthetic checkout, the loaded script and the fake terminal.

    Attributes
    ----------
    root : pathlib.Path
        The fake mothra checkout.
    home : pathlib.Path
        The fake home directory.
    plan : pathlib.Path
        The plan file.
    profile : pathlib.Path
        The peer profile file.
    binary : pathlib.Path
        The peer binary.
    oracle : pathlib.Path
        The oracle binary.
    output : pathlib.Path
        Where the capture is written.
    module : types.ModuleType
        The loaded script, with its boundaries faked.
    terminal : shx_session_fakes.Terminal
        The scripted child.
    environ : dict[str, str]
        The environment that the fake ``os`` shows.
    """

    root: Path
    home: Path
    plan: Path
    profile: Path
    binary: Path
    oracle: Path
    output: Path
    module: types.ModuleType
    terminal: Terminal
    environ: dict[str, str]

    def capture(self) -> dict[str, typ.Any]:
        """Run the capture with this rig's paths.

        Returns
        -------
        dict[str, typing.Any]
            The report that the driver returns.
        """
        return self.module.capture(
            self.plan, self.binary, self.profile, self.oracle, self.output
        )

    def write_plan(self, steps: list[dict[str, typ.Any]]) -> None:
        """Replace the plan's steps."""
        value = {"environment": {"case": "x"}, "steps": steps}
        self.plan.write_text(json.dumps(value), encoding="utf-8")

    def read_report(self) -> dict[str, typ.Any]:
        """Read the report that was written beside the capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json``.
        """
        return json.loads((self.output / "report.json").read_text(encoding="utf-8"))


def modules_of(module: types.ModuleType) -> list[types.ModuleType]:
    """List the modules of the driver, which share the faked boundaries.

    Returns
    -------
    list[types.ModuleType]
        The loaded script, then each module that it declares in
        ``CAPTURE_MODULES`` after itself, imported by name.
    """
    declared = getattr(module, "CAPTURE_MODULES", ())
    return [module, *(importlib.import_module(Path(n).stem) for n in declared[1:])]


def build_rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    """Build the synthetic checkout and load the script against fakes.

    Returns
    -------
    Rig
        The prepared rig.
    """
    root = tmp_path / "mothra"
    root.mkdir()
    binary = root / "hx"
    binary.write_bytes(PEER_BYTES)
    oracle = tmp_path / "oracle.pef"
    oracle.write_bytes(ORACLE_BYTES)
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"binary_sha256": sha(PEER_BYTES), "source_commit": COMMIT})
    )
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    module = load_script(SCRIPT, "capture_shx_session_under_test")
    terminal = Terminal(replies=dict(REPLIES), exits=dict(EXITS))
    environ = {"LANG": "C.UTF-8", "PATH": "/usr/bin"}
    for target in modules_of(module):
        for name, fake in terminal.namespaces(environ).items():
            if hasattr(target, name):
                monkeypatch.setattr(target, name, fake)
    monkeypatch.setattr(module, "mothra_root", lambda: root)
    monkeypatch.setattr(module, "ORACLE_SHA256", sha(ORACLE_BYTES))
    built = Rig(
        root=root,
        home=home,
        plan=tmp_path / "plan.json",
        profile=profile,
        binary=binary,
        oracle=oracle,
        output=root / "capture",
        module=module,
        terminal=terminal,
        environ=environ,
    )
    built.write_plan(STEPS)
    return built
