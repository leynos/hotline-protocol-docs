#!/usr/bin/env python3
"""Capture read-only MCP queries with target identity and replayable arguments."""

import argparse
import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def capture(plan_path: Path, output: Path) -> None:
    """Run the plan's Ghidra tool calls through the MCP server and record the program identity and results under the output directory."""
    root = Path(__file__).resolve().parent.parent
    plan = json.loads(plan_path.read_text())
    output.mkdir(parents=True, exist_ok=True)
    params = StdioServerParameters(command=str(root / "ghidra-mcp"))
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        before = await session.call_tool("get_program_info", {})
        if before.isError:
            raise RuntimeError(str(before.content))
        identity = before.structuredContent
        if identity is None:
            raise RuntimeError("Expected structured program identity")
        if (
            identity["sha256"]
            != "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
        ):
            raise RuntimeError("Loaded program is not the Hotline Server baseline")
        for query in plan:
            name = query["tool"]
            if not name.startswith(
                ("get_", "list_", "search_", "decompile_", "disassemble_", "read_")
            ):
                raise ValueError(f"Mutation is not permitted: {name}")
            target = output / (query["id"] + ".json")
            if target.exists():
                raise FileExistsError(target)
            result = await session.call_tool(name, query.get("arguments", {}))
            record = {
                "captured_at_utc": datetime.now(timezone.utc).isoformat(),
                "query": query,
                "program": identity,
                "mcp_server": init.serverInfo.model_dump(mode="json"),
                "result": result.model_dump(mode="json"),
            }
            target.write_text(json.dumps(record, indent=2) + "\n")
            data = result.structuredContent
            if data and "code" in data:
                target.with_suffix(".c").write_text(data["code"])
            print(query["id"], "ERROR" if result.isError else "OK", flush=True)
        after = await session.call_tool("get_program_info", {})
        if after.isError or after.structuredContent != identity:
            raise RuntimeError("Program identity changed during capture")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    asyncio.run(capture(args.plan, args.output))
