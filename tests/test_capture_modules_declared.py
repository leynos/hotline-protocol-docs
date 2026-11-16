"""Test that each capture script declares exactly the modules split from it.

A script that records a capture identity (decision D31) names its module set in
a constant, ``CAPTURE_MODULES``: its own file first, then the modules split out
of it, each named ``<script>_*.py``. The identity then covers all of them. These
tests read the scripts as text, so adding a helper without declaring it, or
declaring one that is not imported, fails here and not in a later capture.
"""

import ast
import re
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
CONSTANT = "CAPTURE_MODULES"
CALLS_IDENTITY = re.compile(r"\bcapture_identity\.identity\(")


def declared(path: Path) -> tuple[str, ...] | None:
    """Read the module set a script declares.

    Parameters
    ----------
    path : pathlib.Path
        The script.

    Returns
    -------
    tuple[str, ...] | None
        The file names, or ``None`` when the script declares no set.
    """
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        match node:
            case ast.Assign(targets=[ast.Name(id=name)], value=ast.Tuple(elts=items)):
                if name == CONSTANT:
                    return tuple(ast.literal_eval(item) for item in items)
    return None


def imported(path: Path) -> set[str]:
    """List every module a file imports, at any depth.

    Returns
    -------
    set[str]
        Top-level module names.
    """
    found: set[str] = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        match node:
            case ast.Import():
                found.update(alias.name.split(".")[0] for alias in node.names)
            case ast.ImportFrom(level=0, module=str() as module):
                found.add(module.split(".")[0])
    return found


def split_out(scripts: Path, script: str) -> set[str]:
    """Find the modules split from a script, through any chain of imports.

    Parameters
    ----------
    scripts : pathlib.Path
        The directory of scripts.
    script : str
        The script's file name.

    Returns
    -------
    set[str]
        File names of the modules named ``<stem>_*.py`` that the script or one
        of them imports, excluding the script itself.
    """
    stem = script.removesuffix(".py")
    found: set[str] = set()
    pending = [script]
    while pending:
        for name in imported(scripts / pending.pop()):
            helper = f"{name}.py"
            if name.startswith(f"{stem}_") and (scripts / helper).is_file():
                if helper not in found:
                    pending.append(helper)
                found.add(helper)
    return found


def problems(scripts: Path) -> list[str]:
    """Check every script in a directory against its declaration.

    Returns
    -------
    list[str]
        One line per fault; empty when all declarations are right.
    """
    found: list[str] = []
    helpers = {
        name for path in scripts.glob("*.py") for name in (declared(path) or ())[1:]
    }
    for path in sorted(scripts.glob("*.py")):
        modules = declared(path)
        if modules is None:
            calls = CALLS_IDENTITY.search(path.read_text(encoding="utf-8"))
            if calls and path.name not in helpers:
                found.append(f"{path.name} records an identity but declares no set")
            continue
        if modules[:1] != (path.name,) or len(set(modules)) != len(modules):
            found.append(f"{path.name}: the set must start with the script, once each")
        elif set(modules[1:]) != split_out(scripts, path.name):
            found.append(
                f"{path.name}: declared {modules[1:]}, imports "
                f"{sorted(split_out(scripts, path.name))}"
            )
        missing = [name for name in modules if not (scripts / name).is_file()]
        if missing:
            found.append(f"{path.name}: no such file {missing}")
    return found


def test_every_declared_set_is_the_set_of_split_modules() -> None:
    """The scripts of this repository declare their sets rightly."""
    assert not problems(SCRIPTS), "expected no faults"


def build(tmp_path: Path, files: dict[str, str]) -> Path:
    """Write a directory of scripts.

    Returns
    -------
    pathlib.Path
        The directory.
    """
    for name, body in files.items():
        (tmp_path / name).write_text(body)
    return tmp_path


class TestTheCheck:
    """The check, on small directories."""

    def test_a_right_declaration_passes(self, tmp_path: Path) -> None:
        """The script, then the helper it imports."""
        scripts = build(
            tmp_path,
            {
                "run.py": (
                    "import run_part\nCAPTURE_MODULES = ('run.py', 'run_part.py')\n"
                ),
                "run_part.py": "import pcap_tcp\n",
                "pcap_tcp.py": "",
            },
        )
        assert not problems(scripts), "expected no faults"

    def test_a_helper_that_is_not_declared_fails(self, tmp_path: Path) -> None:
        """Adding a helper without declaring it is caught."""
        scripts = build(
            tmp_path,
            {
                "run.py": "import run_part\nCAPTURE_MODULES = ('run.py',)\n",
                "run_part.py": "",
            },
        )
        assert any("run.py" in line for line in problems(scripts)), (
            "expected any(run.py in line for line in problems(scripts))"
        )

    def test_a_helper_reached_through_another_helper_counts(
        self, tmp_path: Path
    ) -> None:
        """The chain of imports is followed."""
        scripts = build(
            tmp_path,
            {
                "run.py": "import run_a\nCAPTURE_MODULES = ('run.py', 'run_a.py')\n",
                "run_a.py": "import run_b\n",
                "run_b.py": "",
            },
        )
        assert any("run_b.py" in line for line in problems(scripts)), (
            "expected any(run_b.py in line for line in problems(scripts))"
        )

    def test_a_declared_module_that_is_not_imported_fails(self, tmp_path: Path) -> None:
        """A declaration of a file the script never loads is caught."""
        scripts = build(
            tmp_path,
            {"run.py": "CAPTURE_MODULES = ('run.py', 'run_x.py')\n", "run_x.py": ""},
        )
        assert problems(scripts), "expected problems(scripts)"

    def test_a_set_must_start_with_its_own_script(self, tmp_path: Path) -> None:
        """The first name is the script itself."""
        scripts = build(
            tmp_path, {"run.py": "CAPTURE_MODULES = ('other.py',)\n", "other.py": ""}
        )
        assert problems(scripts), "expected problems(scripts)"

    def test_a_script_that_records_an_identity_must_declare_a_set(
        self, tmp_path: Path
    ) -> None:
        """Importing the helper without a declaration is caught."""
        scripts = build(
            tmp_path,
            {
                "run.py": "import capture_identity\ncapture_identity.identity(())\n",
                "capture_identity.py": "",
            },
        )
        assert problems(scripts) == [
            "run.py records an identity but declares no set"
        ], "expected problems(scripts) == [run.py records an identity but declare"

    def test_a_declared_helper_may_call_identity_for_its_script(
        self, tmp_path: Path
    ) -> None:
        """A module of a set is not a script that must declare its own."""
        scripts = build(
            tmp_path,
            {
                "run.py": (
                    "import run_part\nCAPTURE_MODULES = ('run.py', 'run_part.py')\n"
                ),
                "run_part.py": (
                    "import capture_identity\ncapture_identity.identity(())\n"
                ),
                "capture_identity.py": "",
            },
        )
        assert not problems(scripts), "expected the helper to be exempt"

    def test_a_shared_library_is_not_part_of_a_set(self, tmp_path: Path) -> None:
        """A module without the script's prefix is covered by the commit."""
        scripts = build(
            tmp_path,
            {
                "run.py": "import pcap_tcp\nCAPTURE_MODULES = ('run.py',)\n",
                "pcap_tcp.py": "",
            },
        )
        assert not problems(scripts), "expected no faults"


def test_the_constant_is_read_only_from_a_literal_tuple(tmp_path: Path) -> None:
    """A computed value is not a declaration."""
    scripts = build(tmp_path, {"run.py": "CAPTURE_MODULES = tuple(['run.py'])\n"})
    assert declared(scripts / "run.py") is None, (
        "expected declared(scripts / run.py) is None"
    )
