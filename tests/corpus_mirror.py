"""Mirror a retained corpus so that single files can be replaced in a test.

The verifiers read a corpus directory. A test that needs one unsound file makes a
mirror of the corpus in which every directory is real and every file is a symbolic
link to the retained one, then replaces the file it needs with a real, changed
copy. The retained evidence is never written to.
"""

import json
import sys
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    import pytest


class Mirror:
    """A mirror of a corpus whose files can be replaced one by one."""

    def __init__(self, corpus: Path, root: Path) -> None:
        """Link each entry of ``corpus`` into the empty directory ``root``."""
        self.corpus = corpus
        self.root = root
        for source in sorted(corpus.rglob("*")):
            target = root / source.relative_to(corpus)
            if source.is_dir() and not source.is_symlink():
                target.mkdir(exist_ok=True)
            else:
                target.symlink_to(source)

    def thaw(self, relative: str) -> Path:
        """Make one file of the mirror a real file that can be changed.

        Returns
        -------
        pathlib.Path
            The file's path in the mirror.
        """
        leaf = self.root / relative
        if leaf.is_symlink():
            content = leaf.read_bytes()
            leaf.unlink()
            leaf.write_bytes(content)
        return leaf

    def edit_json(self, relative: str, change: cabc.Callable[[typ.Any], None]) -> None:
        """Change the JSON in one file of the mirror."""
        path = self.thaw(relative)
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def edit_bytes(self, relative: str, change: cabc.Callable[[bytes], bytes]) -> None:
        """Change the bytes of one file of the mirror."""
        path = self.thaw(relative)
        path.write_bytes(change(path.read_bytes()))


def patch_everywhere(
    monkeypatch: pytest.MonkeyPatch, prefix: str, name: str, stand_in: object
) -> None:
    """Replace ``name`` in every loaded module whose name starts with ``prefix``."""
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith(prefix) and hasattr(module, name):
            monkeypatch.setattr(module, name, stand_in)
