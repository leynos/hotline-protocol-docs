"""Accept a capture's scripts in the earlier form or in the new one (decision D31).

A verifier used to compare ``report["driver_sha256"]`` with a hash recorded for
the corpus. It now calls :func:`driver_in` or :func:`driver_is` in the place of
that comparison, so its checks stay in the order they were. For a capture of the
earlier form the verdict is the verifier's own. For one made after the decision
the report carries ``driver_identity`` (see :mod:`capture_identity`), and the
verdict is whether that record is sound and ``driver_sha256`` is its digest.

The module imports under a bare ``python3`` and uses only the standard library.
"""

import typing as typ

from capture_identity import ROOT, problems

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path


def accepted(
    holder: cabc.Mapping[str, typ.Any],
    role: str,
    *,
    legacy_ok: bool,
    root: Path = ROOT,
) -> bool:
    """Accept the scripts named for a role in the earlier form or in the new one.

    A role is ``driver``, ``source_runner`` and so on: the report or manifest
    holds ``<role>_sha256``, and a capture made after decision D31 also holds
    ``<role>_identity``. A verifier computes ``legacy_ok`` as it always did,
    from the single-file hash, and passes it here. A capture of the earlier form
    stands or falls on that. One of the new form is accepted when its record is
    sound and ``<role>_sha256`` is that record's digest.

    Parameters
    ----------
    holder : collections.abc.Mapping[str, typing.Any]
        The capture's report or manifest.
    role : str
        The prefix of the two fields.
    legacy_ok : bool
        The verifier's own verdict on the single-file hash.
    root : pathlib.Path
        A directory inside the repository whose history holds the commit.

    Returns
    -------
    bool
        Whether the scripts are identified.
    """
    if legacy_ok:
        return True
    record = holder.get(f"{role}_identity")
    if record is None or problems(record, root=root):
        return False
    return holder.get(f"{role}_sha256") == record["digest"]


def driver_accepted(
    report: cabc.Mapping[str, typ.Any], *, legacy_ok: bool, root: Path = ROOT
) -> bool:
    """Accept a capture's driver in the earlier form or in the new one.

    Returns
    -------
    bool
        Whether the driver is identified; see :func:`accepted`.
    """
    return accepted(report, "driver", legacy_ok=legacy_ok, root=root)


def role_in(
    holder: cabc.Mapping[str, typ.Any],
    role: str,
    known: cabc.Container[str],
    *,
    root: Path = ROOT,
) -> bool:
    """Accept a role's hash named in a corpus's list of source hashes, or by a record.

    The earlier form compares ``holder["<role>_sha256"] in known``; a verifier
    calls this in its place and so keeps the position of the check. A missing
    field is still the caller's ``KeyError``.

    Returns
    -------
    bool
        Whether the scripts are identified; see :func:`accepted`.
    """
    legacy_ok = holder[f"{role}_sha256"] in known
    return accepted(holder, role, legacy_ok=legacy_ok, root=root)


def driver_in(
    report: cabc.Mapping[str, typ.Any],
    known: cabc.Container[str],
    *,
    root: Path = ROOT,
) -> bool:
    """Accept a driver named in a corpus's list of source hashes, or by a record.

    Stands where a verifier wrote ``report["driver_sha256"] in known``.

    Returns
    -------
    bool
        Whether the driver is identified; see :func:`role_in`.
    """
    return role_in(report, "driver", known, root=root)


def driver_is(
    report: cabc.Mapping[str, typ.Any], expected: str, *, root: Path = ROOT
) -> bool:
    """Accept a driver equal to a recorded hash, or named by a record.

    Stands where a verifier wrote ``report["driver_sha256"] == expected``; a
    missing field is still the caller's ``KeyError``.

    Returns
    -------
    bool
        Whether the driver is identified; see :func:`accepted`.
    """
    legacy_ok = report["driver_sha256"] == expected
    return accepted(report, "driver", legacy_ok=legacy_ok, root=root)
