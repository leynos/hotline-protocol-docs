"""A linked, resealable copy of the retained private-message corpus.

``verify_native_pm_packet`` checks a corpus against its manifest and checksum
list, so a test that alters one file must record the new hash before the check
under test can be reached. This module links every manifest file below a scratch
directory, lets a test replace one, and rewrites the manifest and the checksum
list to match. Large files stay links to the retained bytes, which are never
written through.
"""

import hashlib
import json
import typing as typ
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "evidence/gap-remediation/2026-11-13/native-pm-01"
CAPTURES = ("preflight", "observe", "postflight")


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def dumps(value: object) -> bytes:
    """Serialise a value as the corpus files are: indented, with a final newline.

    Returns
    -------
    bytes
        The UTF-8 text.
    """
    return (json.dumps(value, indent=2) + "\n").encode()


class PmCorpus:
    """The corpus linked below ``root``, with its manifest held for editing.

    Attributes
    ----------
    root : pathlib.Path
        The scratch directory.
    manifest : dict[str, typing.Any]
        The manifest as it will be written by :meth:`seal`.
    """

    def __init__(self, root: Path) -> None:
        """Link every manifest file below ``root``.

        Parameters
        ----------
        root : pathlib.Path
            An empty scratch directory.
        """
        self.root = root
        self.manifest = json.loads((BATCH / "manifest.json").read_text())
        for path in self.manifest["files"]:
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(BATCH / path)

    def read_json(self, path: str) -> dict[str, typ.Any]:
        """Read a corpus file as JSON.

        Returns
        -------
        typing.Any
            The parsed document, a private copy.
        """
        return json.loads((self.root / path).read_text())

    def overwrite(self, path: str, data: bytes) -> None:
        """Replace a file without recording the new hash."""
        target = self.root / path
        target.unlink()
        target.write_bytes(data)

    def replace(self, path: str, data: bytes) -> None:
        """Replace a file and record its new hash in the manifest."""
        self.overwrite(path, data)
        self.manifest["files"][path] = sha(data)

    def seal(self) -> Path:
        """Rewrite the manifest and the checksum list to match the files.

        Returns
        -------
        pathlib.Path
            The corpus root.
        """
        data = dumps(self.manifest)
        (self.root / "manifest.json").write_bytes(data)
        checks = {**self.manifest["files"], "manifest.json": sha(data)}
        (self.root / "SHA256SUMS").write_text(
            "".join(f"{value}  {path}\n" for path, value in sorted(checks.items()))
        )
        return self.root

    def reseal_capture(
        self, label: str, *, plan: bytes | None = None, report: bytes | None = None
    ) -> None:
        """Replace the plan or report of a capture and rewrite its checksums.

        Parameters
        ----------
        label : str
            ``preflight``, ``observe`` or ``postflight``.
        plan : bytes | None
            New plan bytes, or ``None`` to keep the retained plan.
        report : bytes | None
            New report bytes, or ``None`` to keep the retained report.
        """
        for name, data in (("plan.json", plan), ("report.json", report)):
            if data is not None:
                self.replace(f"{label}/{name}", data)
        lines = "".join(
            f"{sha((self.root / label / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        )
        self.replace(f"{label}/checksums.sha256", lines.encode())

    def large_file(self, prefix: str, *, exclude: str = "-after-") -> str:
        """Find a manifest file by its name prefix, skipping one infix.

        Parameters
        ----------
        prefix : str
            The start of the file name.
        exclude : str
            A substring that the name must not contain.

        Returns
        -------
        str
            The manifest path.
        """
        return next(
            path
            for path in self.manifest["files"]
            if path.startswith(prefix) and exclude not in path
        )
