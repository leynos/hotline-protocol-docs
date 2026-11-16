"""Accept the current findings that a ``--known`` file lists.

The file is a JSON list of objects with ``rule``, ``path``, ``key`` and
``reason``. An entry matches every finding with the same rule, path and key.
An entry that matches no finding is itself a finding, so that the list shrinks
as the documents are corrected.
"""

import json
import typing as typ

from evidence_cites import Finding
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

KNOWN_RULE = "known"


def apply_known(
    root: Path, known: Path, findings: list[Finding]
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into those that remain and those that the file accepts.

    Parameters
    ----------
    root : pathlib.Path
        The repository root, for a relative ``known`` path.
    known : pathlib.Path
        The JSON file.
    findings : list[Finding]
        Every finding of the run.

    Returns
    -------
    tuple[list[Finding], list[Finding]]
        The findings that remain, including one for each stale entry, and the
        findings that the file accepts.

    Raises
    ------
    MissingInputError
        If the file is absent.
    """
    path = known if known.is_absolute() else root / known
    if not path.is_file():
        message = f"{known} is absent"
        raise MissingInputError(message)
    entries = json.loads(path.read_text(encoding="utf-8"))
    identities = [(e["rule"], e["path"], e["key"]) for e in entries]
    used: set[int] = set()
    remaining: list[Finding] = []
    accepted: list[Finding] = []
    for finding in findings:
        identity = (finding.rule, finding.path, finding.key)
        if identity in identities:
            used.add(identities.index(identity))
            accepted.append(finding)
        else:
            remaining.append(finding)
    for index, (rule, entry_path, key) in enumerate(identities):
        if index not in used:
            message = f"the entry for {rule} {entry_path} {key!r} matches no finding"
            remaining.append(Finding(known.as_posix(), 1, KNOWN_RULE, message, ""))
    return remaining, accepted
