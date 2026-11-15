"""Plan the table of account writes that the native metadata corpus varies.

Each row fixes the name, the new name or none, the comment or none, and the
account role that makes the write. ``specs`` is the one place the table is
written down; the planners and the verifier both read it.
"""

import typing as typ


def new_name(name: bytes, new: bytes | None) -> bytes | None:
    """Resolve the new name of a table row, where ``SAME`` and ``NEW`` stand in.

    Returns
    -------
    bytes | None
        ``name`` for ``SAME``, ``n-`` followed by ``name`` for ``NEW``, and
        otherwise the row's own new name.
    """
    match new:
        case b"SAME":
            return name
        case b"NEW":
            return b"n-" + name
        case _:
            return new


def specs() -> list[dict[str, typ.Any]]:
    """Plan the table rows, for files and then for folders.

    Returns
    -------
    list[dict[str, typing.Any]]
        One row per case, with its hexadecimal name, new name and comment.
    """
    patterns = [
        ("both-omitted", None, None, "admin"),
        ("empty-name", b"", None, "admin"),
        ("same-name", b"SAME", None, "admin"),
        ("name-only", b"NEW", None, "admin"),
        ("empty-comment", None, b"", "admin"),
        ("nul-comment", None, b"\0", "admin"),
        ("new-comment", None, b"new-comment", "admin"),
        ("both-new", b"NEW", b"new-comment", "admin"),
        ("comment-before-conflict", b"occupied", b"partial-comment", "admin"),
        ("comment-only-privilege-combined", b"NEW", b"partial-comment", "comment"),
        ("rename-only-privilege-combined", b"NEW", b"blocked-comment", "rename"),
        ("rename-only-privilege-name", b"NEW", None, "rename"),
        ("comment-only-privilege-name", b"NEW", None, "comment"),
        ("neither-noop", None, None, "neither"),
        ("neither-empty-comment", None, b"", "neither"),
        ("comment255", None, b"x" * 255, "admin"),
        ("comment256", None, b"x" * 256, "admin"),
        ("comment-interior-nul", None, b"aa\0bb", "admin"),
    ]
    result = []
    for folder in [False, True]:
        for index, (label, new, comment, role) in enumerate(patterns):
            name = (b"d" if folder else b"f") + str(index).encode().rjust(2, b"0")
            new = new_name(name, new)
            result.append({
                "case": ("dir-" if folder else "file-") + label,
                "folder": folder,
                "name_hex": name.hex(),
                "new_hex": None if new is None else new.hex(),
                "comment_hex": None if comment is None else comment.hex(),
                "role": role,
            })
    return result


def final_name(spec: dict[str, typ.Any]) -> bytes:
    """Return the name that a table row leaves the owned entry with.

    Returns
    -------
    bytes
        The new name for a row whose rename succeeds, otherwise the original name.
    """
    renamed = spec["case"].split("-", 1)[1] in {
        "name-only",
        "both-new",
        "rename-only-privilege-name",
    }
    return bytes.fromhex(spec["new_hex"] if renamed else spec["name_hex"])
