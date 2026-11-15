#!/usr/bin/env python3
"""Check frozen modern-client request 500 source without executing the client."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = (
    ROOT
    / "evidence/gap-remediation/2026-11-13/request500-client-source-01/manifest.json"
)


def require(source: str, pattern: str, label: str) -> None:
    if re.search(pattern, source, re.DOTALL) is None:
        raise ValueError(f"missing {label}")


def check_chain(protocol: str, client: str, state: str) -> None:
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
        r"func\s+keepAliveIfQuiet\(\).*?lastTraffic\s*>=\s*Self\.keepAliveAfter.*?sendKeepAlive\(\)",
        "quiet trigger",
    )
    require(
        client,
        r"func\s+sendKeepAlive\(\).*?version\s*>=\s*185.*?type:\s*\.connectionKeepAlive.*?self\.send\(transaction\).*?self\.getUserList\(\)",
        "version branch and send",
    )
    require(
        client,
        r"func\s+send\(_ transaction: HotlineTransaction\).*?lastTraffic\s*=\s*\.now.*?transaction\.type\s*!=\s*\.connectionKeepAlive",
        "traffic versus activity",
    )
    require(
        client,
        r"func\s+handleTransaction\(.*?lastTraffic\s*=\s*\.now.*?handleReply\(transaction\)",
        "reply traffic",
    )
    require(
        client,
        r"func\s+handleReply\(.*?pendingTransactions\.removeValue\(forKey:\s*transaction\.id\).*?Received reply for unknown transaction",
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
    record = json.loads(manifest.read_text())
    contents: dict[str, str] = {}
    for item in record["files"]:
        path = source_dir / item["name"]
        data = path.read_bytes()
        if (
            len(data) != item["bytes"]
            or hashlib.sha256(data).hexdigest() != item["sha256"]
        ):
            raise ValueError(f"source identity mismatch: {item['name']}")
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-dir",
        type=Path,
        required=True,
        help="locally retained pinned raw files",
    )
    args = parser.parse_args()
    print(json.dumps(verify(args.source_dir), sort_keys=True))


if __name__ == "__main__":
    main()
