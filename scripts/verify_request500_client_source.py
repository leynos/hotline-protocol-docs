#!/usr/bin/env python3
"""Check frozen modern-client request 500 source without executing the client."""

import hashlib
import json
import re
from pathlib import Path

from script_cli import run

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT
    / "evidence/gap-remediation/2026-11-13/request500-client-source-01/manifest.json"
)


def require(source: str, pattern: str, label: str) -> None:
    """Require that ``pattern`` occurs in ``source``, naming ``label`` on failure.

    Parameters
    ----------
    source : str
        The source text to search.
    pattern : str
        The regular expression to find, where ``.`` also matches newlines.
    label : str
        The name of the check, reported when the pattern is absent.

    Raises
    ------
    ValueError
        When ``pattern`` does not occur in ``source``.
    """
    if re.search(pattern, source, re.DOTALL) is None:
        message = f"missing {label}"
        raise ValueError(message)


def check_chain(protocol: str, client: str, state: str) -> None:
    """Require every predicate of the pinned keep-alive source chain.

    Parameters
    ----------
    protocol : str
        The text of the protocol definitions.
    client : str
        The text of the client connection code.
    state : str
        The text of the connection state code.
    """
    require(protocol, r"case\s+connectionKeepAlive\s*=\s*500\b", "opcode 500")
    require(
        state,
        r"func\s+completeLogin\(\).*?client\.startKeepAlive\(\)",
        "post-login start",
    )
    require(
        client,
        r"performLogin\(login\).*?setServerInfo\(serverInfo\)",
        "login server info assignment",
    )
    require(
        client,
        r"reply\.getField\(type:\s*\.versionNumber\).*?getUInt16\(\)",
        "reply version",
    )
    require(
        client,
        r"keepAliveAfter:\s*Duration\s*=\s*\.seconds\(180\)",
        "180-second threshold",
    )
    require(
        client,
        r"func\s+startKeepAlive\(\).*?Task\.sleep\(for:\s*\.seconds\(15\)\)",
        "15-second check",
    )
    require(
        client,
        r"func\s+keepAliveIfQuiet\(\).*?lastTraffic\s*>=\s*Self\.keepAliveAfter.*?"
        r"sendKeepAlive\(\)",
        "quiet trigger",
    )
    require(
        client,
        r"func\s+sendKeepAlive\(\).*?version\s*>=\s*185.*?"
        r"type:\s*\.connectionKeepAlive.*?self\.send\(transaction\).*?"
        r"self\.getUserList\(\)",
        "version branch and send",
    )
    require(
        client,
        r"func\s+send\(_ transaction: HotlineTransaction\).*?"
        r"lastTraffic\s*=\s*\.now.*?transaction\.type\s*!=\s*\.connectionKeepAlive",
        "traffic versus activity",
    )
    require(
        client,
        r"func\s+handleTransaction\(.*?lastTraffic\s*=\s*\.now.*?"
        r"handleReply\(transaction\)",
        "reply traffic",
    )
    require(
        client,
        r"func\s+handleReply\(.*?"
        r"pendingTransactions\.removeValue\(forKey:\s*transaction\.id\).*?"
        r"Received reply for unknown transaction",
        "unawaited ACK",
    )
    require(
        client,
        r"func\s+disconnect\(\).*?keepAliveTask\?\.cancel\(\)",
        "disconnect cancel",
    )
    require(
        client,
        r"enableKeepAlive\s*=\s*true.*?keepAliveIdleTime\s*=\s*60",
        "separate TCP keepalive",
    )


def verify(source_dir: Path, manifest: Path = MANIFEST) -> dict[str, object]:
    """Verify the pinned source files and the keep-alive chain they contain.

    Parameters
    ----------
    source_dir : pathlib.Path
        The directory of locally retained pinned raw files.
    manifest : pathlib.Path
        The manifest that records the name, size and digest of each file.

    Returns
    -------
    dict[str, typing.Any]
        The status, the pinned commit and the number of files checked.

    Raises
    ------
    ValueError
        When a file differs from the manifest, or the chain is incomplete.
    """
    record = json.loads(manifest.read_text())
    contents: dict[str, str] = {}
    for item in record["files"]:
        path = source_dir / item["name"]
        data = path.read_bytes()
        if (
            len(data) != item["bytes"]
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            message = f"source identity mismatch: {item['name']}"
            raise ValueError(message)
        contents[item["name"]] = data.decode("utf-8")
    check_chain(
        contents["HotlineProtocol.swift"],
        contents["HotlineClient.swift"],
        contents["HotlineState+Connection.swift"],
    )
    return {
        "status": "verified-source-only",
        "commit": record["commit"],
        "files": len(contents),
    }


def show(*, source_dir: str) -> None:
    """Print the source-only verification of the pinned files as JSON.

    Parameters
    ----------
    source_dir : str
        The directory of locally retained pinned raw files.
    """
    print(json.dumps(verify(Path(source_dir)), sort_keys=True))


def main() -> None:
    """Check the pinned client source chain without executing the client."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
