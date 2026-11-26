"""Show the retained verifiers and tests each evidence ``.py`` file as captured.

The verifiers and tests hash the evidence ``.py`` files they read, and compare
the result with the hashes recorded at capture. ``scripts/pinned-evidence.json``
lets those files gain docstrings, so the bytes on disk are no longer the bytes
the records name. :func:`install` makes every read, size, copy and hard link of
a pinned file return the bytes at its capture commit instead. The verifiers and
tests themselves are unchanged and reach the same verdict as before.

A path is pinned when it ends in a path of the record, starting at an
``evidence`` directory, and it is this checkout's own file or a link to it: a
symbolic link is followed, and the hard links of the scratch tree that the
Makefile's ``in_legacy_layout`` recipe builds are recognised. A test's own
scratch corpus, which may reuse a real corpus name, is therefore left alone. A
write, an append or an update is never redirected.

The Makefile loads this through ``tools/pinview/sitecustomize.py`` for every
recipe, so the subprocesses that verifiers start see the same view. The root
``conftest.py`` calls :func:`install` too, for a run that bypasses ``make``.
"""

import builtins
import io
import os
import shutil
import stat
import sys
import threading
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    import pinned_evidence

ROOT = Path(__file__).resolve().parents[1]
# Where a checkout, or a copy of its scripts, holds the pin record.
RECORD_RELATIVE = "scripts/pinned-evidence.json"
WRITE_MODES = frozenset("wax+")
# The named fields of a stat result that are also sequence items. The three
# integer times are unnamed sequence items; the named times are floats.
SEQUENCE = frozenset({
    "st_mode",
    "st_ino",
    "st_dev",
    "st_nlink",
    "st_uid",
    "st_gid",
    "st_size",
})


class _Thread(threading.local):
    """The state that belongs to one thread: its own lookups and record load.

    Both flags guard re-entrancy, which only the thread that is inside the call
    can cause, so another thread must never see them set.
    """

    busy = False
    loading = False


class _View:
    """The state of the view: its record, its lock, and whether it is installed."""

    def __init__(self) -> None:
        """Start with no record loaded and nothing installed."""
        self.record: pinned_evidence.PinRecord | None = None
        self.loaded = False
        self.installed = False
        self.lock = threading.Lock()
        self.local = _Thread()


_view = _View()


def _load_record() -> pinned_evidence.PinRecord | None:
    """Import the record loader on first use, so that start-up stays light.

    Returns
    -------
    pinned_evidence.PinRecord | None
        The record, or ``None`` when this checkout has none. A record that
        exists but cannot be read or is malformed raises instead, so that no
        reader falls back to the live bytes.
    """
    tools = str(Path(__file__).resolve().parent)
    sys.path.insert(0, tools)
    try:
        import pinned_evidence
        from tool_support import MissingInputError

        try:
            return pinned_evidence.load_record(ROOT)
        except MissingInputError:
            return None
    finally:
        sys.path.remove(tools)


def _record() -> pinned_evidence.PinRecord | None:
    """Load the record once; ``None`` when this checkout has none.

    Returns
    -------
    pinned_evidence.PinRecord | None
        The record.
    """
    if _view.loaded:
        return _view.record
    if _view.local.loading:
        return None  # the loading thread's own reads of the record
    with _view.lock:
        if not _view.loaded:
            _view.local.loading = True
            try:
                _view.record = _load_record()
                _view.loaded = True  # only a complete load; a failure is retried
            finally:
                _view.local.loading = False
    return _view.record


def _is_checkout_file(path: Path, relative: str) -> bool:
    """Say whether ``path`` is in a checkout's ``evidence`` directory.

    A checkout is this one, or a legacy layout that the Makefile's
    ``in_legacy_layout`` recipe builds (hard links or copies of ``evidence/``
    beside a copy of ``scripts/``, which holds the pin record, and no ``.git``).
    A test's own scratch corpus holds no such record, and another checkout has
    its own history and bytes.

    Returns
    -------
    bool
        ``True`` for a file of a checkout or of a legacy layout.
    """
    root = path.parents[len(Path(relative).parts) - 1]
    if root == ROOT:
        return True
    return (root / RECORD_RELATIVE).is_file() and not (root / ".git").exists()


def _lookup(name: str, record: pinned_evidence.PinRecord) -> str | None:
    """Find the record path that ``name`` or its resolved form ends in.

    Returns
    -------
    str | None
        The repository-relative path, or ``None``.
    """
    for resolved in (Path(name).absolute(), Path(name).resolve()):
        parts = resolved.parts
        for index in range(1, len(parts)):
            candidate = "/".join(parts[index:])
            if parts[index] != "evidence" or candidate not in record.pins:
                continue
            if _is_checkout_file(resolved, candidate):
                return candidate
    return None


def pinned_path(file: object) -> str | None:
    """Return the record path that ``file`` names, if it is pinned.

    Parameters
    ----------
    file : object
        An argument of ``open``.

    Returns
    -------
    str | None
        The repository-relative path, or ``None``.
    """
    name = os.fspath(file) if isinstance(file, str | os.PathLike) else None
    record = _record()
    if not isinstance(name, str) or not name.endswith(".py"):
        return None
    if record is None or _view.local.busy:
        return None
    # The lookup itself stats files, so it must not be redirected in turn.
    _view.local.busy = True
    try:
        return _lookup(name, record)
    finally:
        _view.local.busy = False


def pinned_bytes(file: object) -> bytes | None:
    """Return the capture-time bytes of ``file`` when it is pinned.

    Returns
    -------
    bytes | None
        The bytes at the capture commit, or ``None`` for any other file.
    """
    path = pinned_path(file)
    record = _record()
    if path is None or record is None:
        return None
    return record.read(path)


def _opener(real_open: cabc.Callable[..., object]) -> cabc.Callable[..., object]:
    """Wrap ``open`` so that a pinned file is served from its capture commit.

    Returns
    -------
    collections.abc.Callable[..., object]
        The replacement, with the signature of ``open``.
    """

    def view_open(
        file: object, mode: str = "r", *args: object, **kwargs: object
    ) -> object:
        """Open a file, serving a pinned one from its capture commit.

        Returns
        -------
        object
            The file object.
        """
        data = None if WRITE_MODES & set(mode) else pinned_bytes(file)
        if data is None:
            return real_open(file, mode, *args, **kwargs)
        raw = io.BytesIO(data)
        if "b" in mode:
            return raw
        encoding = kwargs.get("encoding") or (args[1] if len(args) > 1 else None)
        return io.TextIOWrapper(
            raw,
            encoding=str(encoding or "utf-8"),
            errors=typ.cast("str | None", kwargs.get("errors")),
            newline=typ.cast("str | None", kwargs.get("newline")),
        )

    return view_open


def _copier(
    real_copyfile: cabc.Callable[..., object],
    real_open: cabc.Callable[..., typ.IO[bytes]],
) -> cabc.Callable[..., object]:
    """Wrap ``shutil.copyfile`` so that a pinned source is copied as captured.

    Returns
    -------
    collections.abc.Callable[..., object]
        The replacement.
    """

    def view_copyfile(
        src: object, dst: object, *args: object, **kwargs: object
    ) -> object:
        """Copy a file, copying the capture-time bytes of a pinned one.

        Returns
        -------
        object
            The destination.
        """
        data = pinned_bytes(src)
        if data is None:
            return real_copyfile(src, dst, *args, **kwargs)
        with real_open(dst, "wb") as handle:
            handle.write(data)
        return dst

    return view_copyfile


def _linker(
    real_link: cabc.Callable[..., object], real_open: cabc.Callable[..., typ.IO[bytes]]
) -> cabc.Callable[..., object]:
    """Wrap ``os.link`` so that a pinned source is copied, not linked.

    Returns
    -------
    collections.abc.Callable[..., object]
        The replacement.
    """

    def view_link(src: object, dst: object, *args: object, **kwargs: object) -> None:
        """Link a file, copying the capture-time bytes of a pinned one instead."""
        data = pinned_bytes(src)
        if data is None:
            real_link(src, dst, *args, **kwargs)
            return
        with real_open(dst, "xb") as handle:
            handle.write(data)

    return view_link


def _sizer(
    real_stat: cabc.Callable[..., os.stat_result],
) -> cabc.Callable[..., os.stat_result]:
    """Wrap ``os.stat`` or ``os.lstat`` so that a pinned file reports its captured size.

    Returns
    -------
    collections.abc.Callable[..., os.stat_result]
        The replacement.
    """

    def view_stat(path: object, *args: object, **kwargs: object) -> os.stat_result:
        """Return the stat of a file, with the size of a pinned file as captured.

        Returns
        -------
        os.stat_result
            The stat.
        """
        result = real_stat(path, *args, **kwargs)
        data = pinned_bytes(path) if kwargs.get("dir_fd") is None else None
        if data is None:
            return result
        fields = list(result)
        fields[stat.ST_SIZE] = len(data)
        named = {name for name in dir(result) if name.startswith("st_")}
        extra = {name: getattr(result, name) for name in named if name not in SEQUENCE}
        return os.stat_result(fields, extra)

    return view_stat


def install() -> None:
    """Redirect reads of pinned files; calling it again changes nothing."""
    if _view.installed:
        return
    _view.installed = True
    real_open = io.open
    view_open = _opener(real_open)
    patches = (
        (io, "open", view_open),
        (builtins, "open", view_open),
        (shutil, "copyfile", _copier(shutil.copyfile, real_open)),
        (os, "link", _linker(os.link, real_open)),
        (os, "stat", _sizer(os.stat)),
        (os, "lstat", _sizer(os.lstat)),
    )
    for owner, name, value in patches:
        setattr(owner, name, value)
