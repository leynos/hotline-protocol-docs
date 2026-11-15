"""A small source tree, citing files and manifests for the curation tests."""

from pathlib import Path

from evidence_files import CitingRoot
from withheld_helpers import FORK, entry, manifest_text

PM1 = "evidence/gap-remediation/2026-11-13/native-pm-01"
PM2 = "evidence/gap-remediation/2026-11-13/native-pm-02"
NOISE = "evidence/gap-remediation/2026-11-14/noise-01"
REV70 = "evidence/protocol-gap-analysis/2026-11-14/revision-70"
LOOSE = "evidence/protocol-gap-analysis/2026-11-12/manifest.json"
QUERIES = "evidence/hotline-server-1.9/queries"
PSEUDO = "evidence/hotline-server-1.9/(root)"
INPUTS = "evidence/hotline-server-1.9/inputs"
WITHHELD_PATH = f"{INPUTS}/HLserver19.pef"
ODD_NAME = f"{PM2}/odd\x03\r"
BAD_NAME = f"{PM2}/bad\udcff"

SOURCE: dict[str, str | bytes] = {
    f"{PM1}/manifest.json": f'{{"see": "{REV70}/r.txt"}}\n',
    f"{PM1}/data.bin": b"\r\n\x00binary\xff",
    f"{PM1}/SHA256SUMS": "",
    f"{PM2}/data.json": "{}\n",
    ODD_NAME: b"odd",
    BAD_NAME: b"not utf-8",
    f"{NOISE}/x.txt": "noise\n",
    f"{REV70}/r.txt": "revision\n",
    LOOSE: "{}\n",
    f"{QUERIES}/q.json": "{}\n",
    "evidence/hotline-server-1.9/claims.json": "{}\n",
    WITHHELD_PATH: FORK,
    f"{INPUTS}/notes.txt": "notes\n",
    "evidence/runtime-network/2026-11-13/x.txt": "another project\n",
}


def as_bytes(content: str | bytes) -> bytes:
    """Return ``content`` as bytes.

    Returns
    -------
    bytes
        UTF-8 text, or the bytes unchanged.
    """
    return content.encode("utf-8") if isinstance(content, str) else content


def write_withheld(root: Path) -> Path:
    """Write a withheld manifest that lists the fork in the source tree.

    Returns
    -------
    pathlib.Path
        The manifest.
    """
    target = root / "withheld.json"
    target.write_text(manifest_text([entry(WITHHELD_PATH, FORK)]), encoding="utf-8")
    return target


def write_tree(root: Path, files: dict[str, str | bytes]) -> None:
    """Write ``files`` below ``root`` without newline translation."""
    for name, content in files.items():
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(as_bytes(content))


MOTHRA_SCRIPTS = (
    "extract-synhxd-evidence.py",
    "verify-baseline-evidence.py",
    "verify-shx-login-fragment.py",
    "build-shx.py",
    "verify-synhx-profiles.py",
    "test_request500_client_source.py",
    "verify_request500_client_source.py",
    "package-protocol-evidence.py",
    "test_mxd_classic_login.py",
    "verify_mxd_classic_login.py",
    "test_classic_proxy_rehearsal.py",
    "verify_classic_proxy_rehearsal.py",
    "test_verify_classic_account_constructors.py",
    "verify_classic_account_constructors.py",
    "render-protocol-gap-analysis.py",
)


MOTHRA_DOCUMENTS = (
    "docs/native-clock-evidence.md",
    "shx-peer.md",
    "docs/delegation/mac-peer-candidate.md",
    "docs/delegation/classic-proxy-rehearsal.md",
    "docs/delegation/mxd-peer-runtime.md",
)


def real_citing(mothra: Path) -> tuple[CitingRoot, ...]:
    """List the citing roots of the real import decision.

    Returns
    -------
    tuple[CitingRoot, ...]
        This repository's documents, register and scripts, and mothra's ledger,
        recipe, linked documents and the scripts that are imported with them.
    """
    repo = Path(__file__).resolve().parents[1]
    roots = [
        CitingRoot("document", path)
        for path in sorted(repo.glob("*.md"))
        if path.name != "gap-analysis.md"
    ]
    roots.append(CitingRoot("register", repo / "gap-register.json"))
    roots += [CitingRoot("script", p) for p in sorted((repo / "scripts").glob("*.py"))]
    roots.append(CitingRoot("ledger", mothra / "docs/baseline-validity-ledger.md"))
    roots.append(CitingRoot("recipe", mothra / "Makefile"))
    roots += [CitingRoot("linked-document", mothra / name) for name in MOTHRA_DOCUMENTS]
    roots += [
        CitingRoot("script", mothra / "scripts" / name) for name in MOTHRA_SCRIPTS
    ]
    return tuple(roots)
