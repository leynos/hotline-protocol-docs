"""Load a script of ``scripts/`` that cannot be imported by name.

Several inherited scripts have hyphens in their file names, so ``import`` cannot
reach them. The characterization tests load them from the path instead, which is
also how a copy of the tree with the script at its pinned bytes is exercised.
"""

import importlib.util
import sys
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import types

ROOT = Path(__file__).resolve().parents[1]


def load_script(path: Path, module_name: str) -> types.ModuleType:
    """Execute a script file as a module that is not registered globally.

    Parameters
    ----------
    path : pathlib.Path
        The script file.
    module_name : str
        A name for the module, which is not placed in ``sys.modules``.

    Returns
    -------
    types.ModuleType
        The executed module.

    Raises
    ------
    ImportError
        If the file cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        message = f"cannot load {path}"
        raise ImportError(message)
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(module_name, None)
    spec.loader.exec_module(module)
    return module
