"""Pin the order of the login-extras preference and corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
preference record or corpus is refused is held here, outside ``scripts/tests``,
whose tests are the golden keys. Every expectation was observed on the version
of the scripts before the verifier was split into ``verify_native_login_extras_*``
modules (commit 0b34126).

A record that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import dataclasses as dc
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_login_extras import preferences, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-login-extras-01"
)
BASE = "native-name-a-retry"
KEY = "catalog-11202"
HEAD_BYTES = 76
STRINGS_END = 160
WORDS_AT = 54
NAME_INDEX = 3
LONG_NAME = b"N" * 32
WRONG_WORD = b"\0\6"
WRONG_VERSION = b"\0\6"


@dc.dataclass(slots=True)
class Prefs:
    """One preference record, in the pieces that a check refuses."""

    head: bytearray
    strings: list[bytes]
    tail: bytes
    path: str = "/Hotline19/Prefs"
    exit_code: int = 0
    directory: bool = False
    cut: int = 0

    @classmethod
    def retained(cls) -> typ.Self:
        """Read the retained record that the others are cut from.

        Returns
        -------
        Prefs
            The record, which the verifier accepts.
        """
        data = (BATCH / BASE / f"{KEY}.data").read_bytes()
        strings, position = [], HEAD_BYTES
        for _ in range(10):
            length = data[position]
            strings.append(data[position + 1 : position + 1 + length])
            position += 1 + length
        return cls(bytearray(data[:HEAD_BYTES]), strings, data[position:])

    def data(self) -> bytes:
        """Assemble the record bytes, with the last ``cut`` bytes removed.

        Returns
        -------
        bytes
            The record.
        """
        body = b"".join(bytes([len(s)]) + s for s in self.strings)
        data = bytes(self.head) + body + self.tail
        return data[: len(data) - self.cut]

    def write(self, directory: Path) -> Path:
        """Write the extraction and the record into ``directory``.

        Returns
        -------
        pathlib.Path
            ``directory``.
        """
        extraction = json.loads((BATCH / BASE / "extraction.json").read_text())
        record = extraction["records"][0]
        record["path"] = self.path
        record["directory"] = self.directory
        record["attributes"]["data"]["exit_code"] = self.exit_code
        (directory / "extraction.json").write_text(json.dumps(extraction))
        (directory / f"{KEY}.data").write_bytes(self.data())
        return directory


type Break = cabc.Callable[[Prefs], None]


def another_path(prefs: Prefs) -> None:
    """Name another record than the Prefs record."""
    prefs.path = "/Hotline19/Other"


def failed_read(prefs: Prefs) -> None:
    """Record a failed read of the record."""
    prefs.exit_code = 1


def another_version(prefs: Prefs) -> None:
    """Give the record another version prefix."""
    prefs.head[:2] = WRONG_VERSION


def drifted_words(prefs: Prefs) -> None:
    """Change the first General configuration word."""
    prefs.head[WORDS_AT : WORDS_AT + 2] = WRONG_WORD


def long_name(prefs: Prefs) -> None:
    """Give the server name more than 31 bytes."""
    prefs.strings[NAME_INDEX] = LONG_NAME


CHAIN: list[tuple[str, str, Break]] = [
    ("record", "Missing positive native Prefs record", another_path),
    ("read", "Native Prefs read failed", failed_read),
    ("version", "Native Prefs version/prefix differs", another_version),
    ("words", "Native General configuration drifted", drifted_words),
    ("name", "Native server-name destination exceeds", long_name),
]


class PreferenceOrderTests:
    """Keep the preference checks in the order in which they have run."""

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        prefs = Prefs.retained()
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(prefs)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            preferences(prefs.write(tmp_path))

    def test_a_missing_string_is_reported_before_the_name(self, tmp_path: Path) -> None:
        """A record that ends before the tenth string is refused for that."""
        prefs = Prefs.retained()
        prefs.strings = prefs.strings[:9]
        prefs.tail = b""
        prefs.strings[NAME_INDEX] = LONG_NAME
        with pytest.raises(ValueError, match="Missing native Pascal length"):
            preferences(prefs.write(tmp_path))

    def test_a_missing_string_is_reported_after_the_words(self, tmp_path: Path) -> None:
        """A record that ends before the tenth string is refused after the words."""
        prefs = Prefs.retained()
        prefs.strings = prefs.strings[:9]
        prefs.tail = b""
        with pytest.raises(ValueError, match="Missing native Pascal length"):
            preferences(prefs.write(tmp_path))
        drifted_words(prefs)
        with pytest.raises(ValueError, match="General configuration drifted"):
            preferences(prefs.write(tmp_path))

    def test_truncated_content_is_reported_before_the_name(
        self, tmp_path: Path
    ) -> None:
        """A string that runs past the record is refused before the name."""
        prefs = Prefs.retained()
        prefs.strings[NAME_INDEX] = LONG_NAME
        prefs.strings[9] = b"abc"
        prefs.tail = b""
        prefs.cut = 1
        with pytest.raises(ValueError, match="Truncated native Pascal content"):
            preferences(prefs.write(tmp_path))


@dc.dataclass(slots=True)
class Staged:
    """A copy of the corpus files that ``verify`` reads before it reads packets."""

    root: Path
    manifest: Report

    @classmethod
    def build(cls, root: Path) -> typ.Self:
        """Copy the manifest, the agreement and the preference records.

        Returns
        -------
        Staged
            The copy, which ``verify`` accepts up to the packet records.
        """
        manifest = json.loads((BATCH / "manifest.json").read_text())
        directories = {*manifest["configurations"].values()}
        directories.add(manifest["original_preferences"])
        directories.add("native-short-name-b")
        for name in directories:
            shutil.copytree(BATCH / name, root / name)
        shutil.copy(BATCH / "original-agreement.data", root)
        return cls(root, manifest)

    def verify(self) -> None:
        """Verify the copy."""
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))
        verify(self.root)


def another_oracle(staged: Staged) -> None:
    """Name another oracle."""
    staged.manifest["oracle_sha256"] = "0" * 64


def fewer_cases(staged: Staged) -> None:
    """Leave one case out of the inventory."""
    staged.manifest["cases"].pop()


def fewer_configurations(staged: Staged) -> None:
    """Leave one configuration out of the inventory."""
    del staged.manifest["configurations"]["none"]


def swapped_name(staged: Staged) -> None:
    """Point the first configuration at the record of another name."""
    staged.manifest["configurations"]["name-a"] = "native-short-name-b"


def local_banner(staged: Staged) -> None:
    """Point the remote-banner configuration at a record with a local banner."""
    staged.manifest["configurations"]["url"] = "native-short-name-b"


def not_restored(staged: Staged) -> None:
    """Name an original record that carries a server name."""
    staged.manifest["original_preferences"] = "native-short-name-b"


def longer_agreement(staged: Staged) -> None:
    """Append a byte to the original agreement."""
    with (staged.root / "original-agreement.data").open("ab") as handle:
        handle.write(b"x")


VERIFY_CHAIN: list[tuple[str, str, cabc.Callable[[Staged], None]]] = [
    ("oracle", "Login-extra oracle differs", another_oracle),
    ("cases", "Login-extra case inventory differs", fewer_cases),
    ("configurations", "Native configuration inventory differs", fewer_configurations),
    ("name", "Native stored server name differs", swapped_name),
    ("banner", "Native remote banner configuration differs", local_banner),
    ("restored", "Original empty name was not restored", not_restored),
    ("agreement", "Original agreement length differs", longer_agreement),
]


class CorpusOrderTests:
    """Keep the corpus checks in the order in which they have run."""

    @pytest.mark.parametrize("first", range(len(VERIFY_CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        staged = Staged.build(tmp_path)
        for _label, _message, apply in reversed(VERIFY_CHAIN[first:]):
            apply(staged)
        _label, message, _apply = VERIFY_CHAIN[first]
        with pytest.raises(ValueError, match=message):
            staged.verify()

    def test_the_packet_records_are_read_after_the_checks_above(
        self, tmp_path: Path
    ) -> None:
        """A copy that passes every check above fails only on the packet records."""
        with pytest.raises(OSError, match="No such file"):
            Staged.build(tmp_path).verify()
