"""Name the directory-creation cases as rows of data.

Each row gives a label, the name that the 205 request carries, the structured
path it carries in field 202, the view path of the readbacks, and the login
role. The rows are grouped by the boundary they test; ``specs`` keeps their
original order.
"""

import dataclasses as dc
import typing as typ

from native_folder_cases import path
from native_mkdir_steps import BASE, ROOT


@dc.dataclass(frozen=True, slots=True)
class Spec:
    """One directory-creation case; the defaults are the admin view of the base."""

    label: str
    name: bytes | None
    parent: bytes | None = BASE
    view: bytes = BASE
    role: str = "admin"

    def as_dict(self) -> dict[str, typ.Any]:
        """Return the case as the record that the planners and verifier read.

        Returns
        -------
        dict[str, typing.Any]
            The label, the hex of the name, the parent and the view, and the
            role, in that order; an absent name or parent is ``None``.
        """
        return {
            "case": self.label,
            "name_hex": None if self.name is None else self.name.hex(),
            "path_hex": None if self.parent is None else self.parent.hex(),
            "view_hex": self.view.hex(),
            "role": self.role,
        }


def name_cases() -> list[Spec]:
    """Plan the cases that vary the name in the admin view of the base.

    Returns
    -------
    list[Spec]
        The name rows, from ``ascii`` to ``dotdot-name``.
    """
    return [
        Spec("ascii", b"plain"),
        Spec("existing-directory", b"exists"),
        Spec("existing-file", b"ordinary"),
        Spec("case-collision", b"EXISTS"),
        Spec("name-absent", None),
        Spec("name-empty", b""),
        Spec("name-nul-only", b"\0"),
        Spec("name-nul-interior", b"nu\0l"),
        Spec("name-nul-leading", b"\0nul"),
        Spec("name-nul-trailing", b"nul\0"),
        Spec("name-colon", b"co:lon"),
        Spec("name-slash", b"sl/ash"),
        Spec("name-cr", b"cr\rname"),
        Spec("name-lf", b"lf\nname"),
        Spec("name-high-byte", b"hi-\x9a"),
        Spec("name31", b"n31-" + b"a" * 27),
        Spec("name32", b"n32-" + b"b" * 28),
        Spec("name255", b"n255-" + b"c" * 250),
        Spec("name256", b"n256-" + b"d" * 251),
        Spec("name65535", b"n65535-" + b"e" * (65535 - 7)),
        Spec("long-extension", b"ext-" + b"x" * 36 + b".txt"),
        Spec("dot-name", b"."),
        Spec("dotdot-name", b".."),
    ]


def parent_cases() -> list[Spec]:
    """Plan the cases whose parent is a nested folder, a file or a missing folder.

    Returns
    -------
    list[Spec]
        The nested, parent-file and parent-missing rows, in that order.
    """
    return [
        Spec(
            "nested",
            b"nested-child",
            path((ROOT, b"nest", b"leaf")),
            path((ROOT, b"nest", b"leaf")),
        ),
        Spec("parent-file", b"no-file-parent", path((ROOT, b"ordinary"))),
        Spec("parent-missing", b"no-missing-parent", path((ROOT, b"absent-parent"))),
    ]


def root_cases() -> list[Spec]:
    """Plan the cases whose structured path is absent, empty or truncated to a root.

    Returns
    -------
    list[Spec]
        The root and path-length rows, each with the view of a zero count.
    """
    return [
        Spec(label, ("m-fs19-" + label).encode(), parent, b"\0\0")
        for label, parent in [
            ("root-absent", None),
            ("root-empty", b""),
            ("root-zero-count", b"\0\0"),
            ("path-one-byte", b"\0"),
            ("path-count-only", b"\0\1"),
            ("path-five-bytes", b"\0\1\0\0\1"),
        ]
    ]


def path_cases() -> list[Spec]:
    """Plan the cases whose structured path is malformed or supplies the name.

    Returns
    -------
    list[Spec]
        The truncated, empty-component, word, trailing and count rows, then the
        two rows whose path supplies the name, in that order.
    """
    return [
        Spec(
            "path-truncated-last",
            b"truncated-last",
            b"\0\2" + BASE[2:] + b"\0\0\5ab",
        ),
        Spec(
            "path-empty-component",
            b"empty-component",
            b"\0\2" + BASE[2:] + b"\0\0\0",
        ),
        Spec("path-word-ffff", b"word-ffff", b"\0\1\xff\xff" + BASE[4:]),
        Spec("path-trailing", b"trailing", BASE + b"\xde\xad"),
        Spec(
            "path-count-zero-trailing",
            b"m-fs19-zero-trailing",
            b"\0\0" + BASE[2:],
            b"\0\0",
        ),
        Spec("path-count-too-high", b"count-too-high", b"\0\2" + BASE[2:]),
        Spec(
            "path-supplies-name",
            None,
            path((ROOT, b"nest", b"via-path")),
            path((ROOT, b"nest")),
        ),
        Spec(
            "empty-name-path-supplies",
            b"",
            path((ROOT, b"nest", b"via-empty")),
            path((ROOT, b"nest")),
        ),
    ]


def role_cases() -> list[Spec]:
    """Plan the cases that log in as the low-permission account.

    Returns
    -------
    list[Spec]
        The new-folder and conflicting-name rows for the low role.
    """
    return [
        Spec("low-permission-new", b"denied-new", role="low"),
        Spec("low-permission-conflict", b"exists", role="low"),
    ]


def component_cases() -> list[Spec]:
    """Plan the cases whose path component is a name with a special byte.

    Returns
    -------
    list[Spec]
        One row per special component; the colon component's view is the
        ``co-lon`` path.
    """
    rows = []
    for label, parent, child in [
        ("path-dot-component", b".", b"literal-dot"),
        ("path-dotdot-component", b"..", b"literal-dotdot"),
        ("path-colon-component", b"co:lon", b"inside-colon"),
        ("path-high-component", b"hi-\x9a", b"inside-high"),
        ("path-nul-component", b"\0nul", b"inside-nul"),
    ]:
        view_parent = b"co-lon" if parent == b"co:lon" else parent
        rows.append(
            Spec(
                label,
                child,
                path((ROOT, parent)),
                path((ROOT, view_parent)),
            )
        )
    return rows


def specs() -> list[dict[str, typ.Any]]:
    """Plan the directory-creation case records, in their original order.

    Returns
    -------
    list[dict[str, typing.Any]]
        One record for each case, from the name, parent, path and role rows.
    """
    rows = [
        *name_cases(),
        *parent_cases(),
        *root_cases(),
        *path_cases(),
        *role_cases(),
        *component_cases(),
    ]
    return [row.as_dict() for row in rows]
