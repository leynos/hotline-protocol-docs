"""Read the repository inputs that ``check_evidence`` works from."""

import dataclasses as dc
import json
import typing as typ

from evidence_cites import DocCites, scan_document
from evidence_families import FamilyTable, load_local, parse_families
from evidence_index import INDEX_NAME, IndexInputs, set_of
from evidence_rules import Known
from repo_files import repo_files
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

REGISTER = "gap-register.json"
CLAIMS = "evidence/hotline-server-1.9/claims.json"
GUIDE = "docs/native-evidence/recreating-evidence.md"
LEDGER = "docs/provenance/remaining-evidence-work.md"
LOCAL = "evidence/local-corpora.json"
SKIPPED = ("docs/execplans/", "docs/documentation-style-guide.md")
ROOT_DOCUMENTS = ("README.md", "AGENTS.md", "gap-analysis.md")
GENERATED_DEPTH = len(("docs", "set", INDEX_NAME))


@dc.dataclass(slots=True)
class Repo:
    """Everything that the rules read.

    Attributes
    ----------
    root : pathlib.Path
        The repository root.
    texts : dict[str, str]
        The text of each document that cites evidence.
    cites : dict[str, DocCites]
        The citations of each document.
    known : Known
        The identifiers that the register and the ledger define.
    guide : str
        The recreation guide's text.
    families : FamilyTable
        The corpus families that the guide defines.
    """

    root: Path
    texts: dict[str, str]
    cites: dict[str, DocCites]
    known: Known
    guide: str
    families: FamilyTable

    @property
    def citing(self) -> dict[str, DocCites]:
        """Select the documents whose citations an index lists.

        Returns
        -------
        dict[str, DocCites]
            The documents inside a set, set overviews excluded.
        """
        return {
            path: doc
            for path, doc in self.cites.items()
            if (name := set_of(path)) and path != f"docs/{name}/README.md"
        }

    def index_inputs(self) -> IndexInputs:
        """Gather the renderer's inputs.

        Returns
        -------
        IndexInputs
            The citing documents, the families and the link target of each
            corpus (its manifest if it has one, otherwise its directory or
            file).
        """
        links: dict[str, str] = {}
        for doc in self.citing.values():
            for occurrence in doc.corpora:
                corpus = occurrence.value
                if (self.root / corpus / "manifest.json").is_file():
                    links[corpus] = f"{corpus}/manifest.json"
                elif (self.root / corpus).is_dir():
                    links[corpus] = f"{corpus}/"
                elif (self.root / corpus).is_file():
                    links[corpus] = corpus
        return IndexInputs(self.citing, self.families, links)


def read_required(root: Path, name: str) -> str:
    """Read a required text file.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    name : str
        The repository-relative path.

    Returns
    -------
    str
        The file's text.

    Raises
    ------
    MissingInputError
        If the file is absent.
    """
    path = root / name
    if not path.is_file():
        message = f"{name} is absent"
        raise MissingInputError(message)
    return path.read_text(encoding="utf-8")


def _is_generated(path: str) -> bool:
    """Say whether a path is a generated evidence index.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    bool
        ``True`` for ``docs/<set>/evidence.md``.
    """
    parts = path.split("/")
    return len(parts) == GENERATED_DEPTH and parts[-1] == INDEX_NAME


def _documents(root: Path) -> dict[str, str]:
    """Read every document that cites evidence.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    dict[str, str]
        Text by path, for every Markdown file below ``docs/`` and for the root
        documents, except execution plans, the style guide and the generated
        indexes.
    """
    found: dict[str, str] = {}
    for path in repo_files(root, ".md"):
        name = path.as_posix()
        listed = path.parts[0] == "docs" or name in ROOT_DOCUMENTS
        skipped = name.startswith(SKIPPED) or _is_generated(name)
        if listed and not skipped:
            found[name] = (root / path).read_text(encoding="utf-8")
    return found


def load_repo(root: Path) -> Repo:
    """Read the register, the ledger claims, the guide and every document.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.

    Returns
    -------
    Repo
        The inputs of the rules.
    """
    register = json.loads(read_required(root, REGISTER))
    claims = json.loads(read_required(root, CLAIMS))
    known = Known(
        frozenset(claim["id"] for claim in claims["claims"]),
        {gap["id"]: gap["status"] for gap in register["gaps"]},
    )
    guide = read_required(root, GUIDE)
    texts = _documents(root)
    return Repo(
        root,
        texts,
        {path: scan_document(path, text) for path, text in texts.items()},
        known,
        guide,
        parse_families(guide, load_local(root / LOCAL)),
    )
