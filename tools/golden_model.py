"""Shared pieces of the INV-SCRIPT golden tooling.

The goldens record what the inherited scripts do today, so that a later
refactoring can be compared against them. This module holds the parts that the
three oracles share: canonical JSON, digests, the output normaliser and the
record comparison. Nothing here runs a script.
"""

import dataclasses as dc
import hashlib
import json
import re
import shutil
import sys
import tempfile
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

SCHEMA_VERSION = 1
GOLDEN_DIR = "tests/goldens"
HEX64 = re.compile(r"\b[0-9a-f]{64}\b")
# unittest and the verifiers print wall-clock durations, which differ per run.
TIMING = re.compile(r"\b(in|took|elapsed:?) \d+(?:\.\d+)?s\b")
# A traceback: its header, the indented frame lines, then the exception line.
TRACEBACK = re.compile(
    r"^Traceback \(most recent call last\):\n(?:[ \t]+.*\n)*([^ \t\n].*)",
    re.MULTILINE,
)
TRACEBACK_MARKER = "<traceback>"
# A capture identity record (scripts/capture_identity.py) as a planner writes it:
# the commit, the files that differ from it, the listed files and the set digest.
IDENTITY = re.compile(
    r'("commit":\s*)(?:"[0-9a-f]{40}"|null)(,\s*"dirty":\s*)\[[^\]]*\]'
    r'(,\s*"files":\s*\[[^\]]*\],\s*"digest":\s*")([0-9a-f]{64})(")',
    re.DOTALL,
)
ZERO_COMMIT = "0" * 40
ZERO_DIGEST = "0" * 64
# The interpreter the Makefile recipes use, so the oracles see the same Python.
PYTHON3 = shutil.which("python3") or sys.executable
type Record = dict[str, typ.Any]


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 of ``data`` as lower-case hexadecimal.

    Returns
    -------
    str
        The digest.
    """
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> str:
    """Render ``value`` in the repository's canonical JSON layout.

    Returns
    -------
    str
        Indented JSON, unescaped non-ASCII text and a final newline.
    """
    return json.dumps(value, indent=2, ensure_ascii=False) + "\n"


def script_digests(root: Path) -> dict[str, str]:
    """Map the SHA-256 of each ``scripts/*.py`` file to its name.

    Returns
    -------
    dict[str, str]
        Digest to file name; the first name in sorted order wins a tie.
    """
    names: dict[str, str] = {}
    for path in sorted((root / "scripts").glob("*.py")):
        names.setdefault(sha256_hex(path.read_bytes()), path.name)
    return names


def settle(raw: bytes) -> bytes:
    """Replace what a capture identity records that differs between runs.

    A planner that records the identity of its scripts (decision D31) writes
    the Git commit, the files that differ from it and the digest of the set
    of modules. Each is replaced by a fixed value of the same length, as is
    every other occurrence of that digest, such as the old single-file field.
    Bytes that hold no identity record come back unchanged.

    Returns
    -------
    bytes
        The bytes with each identity record settled.
    """
    text = raw.decode("utf-8", errors="surrogateescape")
    digests = {found.group(4) for found in IDENTITY.finditer(text)}
    text = IDENTITY.sub(
        lambda found: (
            f'{found.group(1)}"{ZERO_COMMIT}"{found.group(2)}[]'
            f"{found.group(3)}{ZERO_DIGEST}{found.group(5)}"
        ),
        text,
    )
    for value in digests:
        text = text.replace(value, ZERO_DIGEST)
    return text.encode("utf-8", errors="surrogateescape")


@dc.dataclass(frozen=True, slots=True)
class Normaliser:
    """Removes only what differs between runs of the same code.

    Attributes
    ----------
    root : pathlib.Path
        The checkout; its absolute path becomes ``<ROOT>``.
    scratch : pathlib.Path
        The directory that holds this run's temporary trees; becomes
        ``<SCRATCH>``.
    scripts : collections.abc.Mapping[str, str]
        Digests of ``scripts/*.py`` files, as from :func:`script_digests`.
    """

    root: Path
    scratch: Path
    scripts: cabc.Mapping[str, str]

    def text(self, raw: bytes) -> str:
        """Normalise captured process output.

        Four things are replaced: the absolute path of the checkout, the
        random ``tmp.XXXXXXXXXX`` directories that ``mktemp`` creates for the
        legacy-layout recipes, wall-clock durations, and each Python traceback,
        which shrinks to a marker line and its final exception line so that
        restructuring a failing script cannot change the text.

        Returns
        -------
        str
            The output with those four replaced by fixed markers.
        """
        text = raw.decode("utf-8", errors="replace")
        text = text.replace(str(self.root), "<ROOT>")
        text = text.replace(str(self.scratch), "<SCRATCH>")
        temp = re.escape(str(Path(tempfile.gettempdir()) / "tmp."))
        text = re.sub(temp + "[A-Za-z0-9]+", "<TMP>", text)
        text = TIMING.sub(r"\1 <T>s", text)
        return TRACEBACK.sub(TRACEBACK_MARKER + r"\n\1", text)

    def plan(self, raw: bytes) -> tuple[bytes, list[str]]:
        """Replace embedded digests of ``scripts/`` files with their names.

        A planner may record the digest of its own source. That digest must
        change when the source is refactored, so it is compared by name. The
        commit and the set digest of a capture identity are settled first.

        Returns
        -------
        tuple[bytes, list[str]]
            The content with each such digest replaced by ``{scripts/NAME}``,
            and the sorted names that were replaced.
        """
        found: set[str] = set()

        def swap(match: re.Match[str]) -> str:
            """Name a digest that belongs to a script; keep any other.

            Returns
            -------
            str
                ``{scripts/NAME}`` or the unchanged digest.
            """
            name = self.scripts.get(match.group(0))
            if name is None:
                return match.group(0)
            found.add(name)
            return "{scripts/" + name + "}"

        text = HEX64.sub(swap, settle(raw).decode("utf-8", errors="surrogateescape"))
        return text.encode("utf-8", errors="surrogateescape"), sorted(found)


def select(keys: cabc.Iterable[str], filters: cabc.Sequence[str]) -> list[str]:
    """Pick the record keys that any filter names.

    Returns
    -------
    list[str]
        Every key when ``filters`` is empty; otherwise the keys that contain
        at least one filter as a substring.
    """
    return [k for k in keys if not filters or any(f in k for f in filters)]


def describe(old: object, new: object) -> str:
    """Summarise how two records differ, field by field.

    Returns
    -------
    str
        ``field: old -> new`` for each differing field, or the two values.
    """
    if isinstance(old, dict) and isinstance(new, dict):
        fields = sorted(set(old) | set(new))
        parts = [
            f"{f}: {old.get(f, '<absent>')!r} -> {new.get(f, '<absent>')!r}"
            for f in fields
            if old.get(f) != new.get(f)
        ]
        return "; ".join(parts)
    return f"{old!r} -> {new!r}"


def differences(
    golden: cabc.Mapping[str, Record],
    fresh: cabc.Mapping[str, Record],
    filters: cabc.Sequence[str],
) -> list[str]:
    """Compare the selected golden records with freshly captured ones.

    Returns
    -------
    list[str]
        One line per record that changed, vanished or appeared.
    """
    lines: list[str] = []
    for key in select(sorted(set(golden) | set(fresh)), filters):
        if key not in fresh:
            lines.append(f"missing: {key}")
        elif key not in golden:
            lines.append(f"unexpected: {key}")
        elif golden[key] != fresh[key]:
            lines.append(f"changed: {key}: {describe(golden[key], fresh[key])}")
    return lines


def write_golden(root: Path, name: str, document: object) -> Path:
    """Write one golden document below ``tests/goldens``.

    Returns
    -------
    pathlib.Path
        The file written.
    """
    target = root / GOLDEN_DIR / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(canonical_json(document), encoding="utf-8")
    return target


def read_golden(root: Path, name: str) -> dict[str, typ.Any]:
    """Read one golden document.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads((root / GOLDEN_DIR / name).read_text(encoding="utf-8"))
