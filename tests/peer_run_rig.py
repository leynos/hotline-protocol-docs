"""A synthetic repository and fake boundaries for the ``peer_tolerance_run`` tests."""

import dataclasses as dc
import hashlib
import json
import typing as typ

from peer_run_fakes import Boundary
from script_loading import ROOT, load_script

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

    import pytest

SCRIPT = ROOT / "scripts/peer_tolerance_run.py"
PEER_BYTES = b"peer binary"
ORACLE_BYTES = b"oracle binary"
COPIED = (
    "peer_tolerance_fixture.py",
    "peer_tolerance_run.py",
    "verify_peer_tolerance.py",
    "capture_shx_session.py",
)
OWNED = "evidence/gap-remediation/2026-11-13/delegated-peer-01"
SHX = "evidence/gap-remediation/2026-11-13/native-shx-02"


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
    """A synthetic repository, the loaded script and the fake boundary.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    protocol : pathlib.Path
        The tree that holds the ``scripts/`` that are copied and run.
    work : pathlib.Path
        The private run directory.
    destination : pathlib.Path
        The owned evidence directory.
    module : types.ModuleType
        The loaded script, with its boundaries faked.
    boundary : peer_run_fakes.Boundary
        The recorded calls and scripted answers.
    home : pathlib.Path
        The fake home directory.
    """

    root: Path
    protocol: Path
    work: Path
    destination: Path
    module: types.ModuleType
    boundary: Boundary
    home: Path

    def run(self) -> None:
        """Run the script with this rig's paths."""
        self.module.run(self.root, self.protocol, self.work, self.destination)

    @property
    def cases(self) -> tuple[str, ...]:
        """The cases that the script runs.

        Returns
        -------
        tuple[str, ...]
            The case names.
        """
        return tuple(self.module.CASES)


def build_rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Rig:
    """Build the synthetic repository and load the script against fakes.

    Returns
    -------
    Rig
        The prepared rig.
    """
    root = tmp_path / "repo"
    files = {
        "tools/shx-peer/source/hx": PEER_BYTES,
        "evidence/hotline-server-1.9/inputs/HLserver19.pef": ORACLE_BYTES,
    }
    for name, data in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_bytes(data)
    shx = root / SHX
    (shx / "receivers/control").mkdir(parents=True)
    profile = {"binary_sha256": sha(PEER_BYTES), "source_commit": "c0ffee"}
    (shx / "peer-profile.json").write_text(json.dumps(profile))
    steps = [{"command": "hello"}, {"command": "connect 127.0.0.1:15510"}]
    plan = {"environment": {"old": True}, "steps": steps}
    (shx / "receivers/control/plan.json").write_text(json.dumps(plan))
    protocol = tmp_path / "protocol"
    (protocol / "scripts").mkdir(parents=True)
    for name in (*COPIED, "peer_tolerance_fixture.py"):
        (protocol / "scripts" / name).write_text(f"# {name}\n")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    module = load_script(SCRIPT, "peer_tolerance_run_under_test")
    boundary = Boundary()
    for name, fake in boundary.namespaces().items():
        monkeypatch.setattr(module, name, fake)
    monkeypatch.setattr(module, "PEER", sha(PEER_BYTES))
    monkeypatch.setattr(module, "ORACLE_SHA256", sha(ORACLE_BYTES))
    return Rig(
        root=root,
        protocol=protocol,
        work=root / "state/delegation/peer/run-1",
        destination=root / OWNED,
        module=module,
        boundary=boundary,
        home=home,
    )


def manifest_of(rig: Rig) -> dict[str, typ.Any]:
    """Read the manifest of the frozen evidence.

    Returns
    -------
    dict[str, typing.Any]
        The parsed manifest.
    """
    return json.loads((rig.destination / "manifest.json").read_text())
