#!/usr/bin/env python3
"""Capture read-only MCP queries with target identity and replayable arguments."""

import asyncio
import dataclasses as dc
import datetime as dt
import json
import typing as typ
from pathlib import Path

import script_cli
from mcp import ClientSession, StdioServerParameters  # ty: ignore[unresolved-import]  # installed beside the bridge
from mcp.client.stdio import stdio_client  # ty: ignore[unresolved-import]  # as above

type Json = dict[str, typ.Any]


class Result(typ.Protocol):
    """The parts of an MCP tool result that this script reads."""

    isError: bool  # ruff: ignore[mixed-case-variable-in-class-scope]  # the library names this attribute
    content: object
    structuredContent: Json | None  # ruff: ignore[mixed-case-variable-in-class-scope]  # the library names this attribute

    def model_dump(self, *, mode: str) -> Json:
        """Dump the result; the script asks for ``mode="json"``."""
        ...


class ServerInfo(typ.Protocol):
    """The server description returned by ``initialize``."""

    def model_dump(self, *, mode: str) -> Json:
        """Dump the description; the script asks for ``mode="json"``."""
        ...


class Session(typ.Protocol):
    """The part of an MCP client session that this script uses."""

    async def call_tool(self, name: str, arguments: Json) -> Result:
        """Call a tool of the bridge."""
        ...


BASELINE_SHA256 = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
READ_ONLY_PREFIXES = (
    "get_",
    "list_",
    "search_",
    "decompile_",
    "disassemble_",
    "read_",
)


@dc.dataclass(frozen=True, slots=True)
class Capture:
    """One capture run: the session, where records go and what was loaded.

    Attributes
    ----------
    session : Session
        The MCP client session.
    output : pathlib.Path
        The directory that receives the records.
    identity : dict[str, typing.Any]
        The program identity reported before the first query.
    server : ServerInfo
        The server description returned by ``initialize``.
    """

    session: Session
    output: Path
    identity: Json
    server: ServerInfo

    async def query(self, query: Json) -> None:
        """Run one planned query, write its record and report the outcome.

        The tool name is checked before the record file is looked for, and both
        before the bridge is asked anything.

        Parameters
        ----------
        query : dict[str, typing.Any]
            The planned query: ``id``, ``tool`` and optional ``arguments``.

        Raises
        ------
        ValueError
            If the tool is not a read-only one.
        FileExistsError
            If the query's record file already exists.
        """
        name = query["tool"]
        if not name.startswith(READ_ONLY_PREFIXES):
            message = f"Mutation is not permitted: {name}"
            raise ValueError(message)
        target = self.output / (query["id"] + ".json")
        if target.exists():
            raise FileExistsError(target)
        result = await self.session.call_tool(name, query.get("arguments", {}))
        record = {
            "captured_at_utc": dt.datetime.now(dt.UTC).isoformat(),
            "query": query,
            "program": self.identity,
            "mcp_server": self.server.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
        }
        target.write_text(json.dumps(record, indent=2) + "\n")
        data = result.structuredContent
        if data and "code" in data:
            target.with_suffix(".c").write_text(data["code"])
        print(query["id"], "ERROR" if result.isError else "OK", flush=True)


async def program_identity(session: Session) -> Json:
    """Ask the bridge which program is loaded and require the baseline.

    Parameters
    ----------
    session : Session
        The MCP client session.

    Returns
    -------
    dict[str, typing.Any]
        The program identity.

    Raises
    ------
    RuntimeError
        If the reply is an error, is not structured, or names another program.
    """
    before = await session.call_tool("get_program_info", {})
    if before.isError:
        raise RuntimeError(str(before.content))
    identity = before.structuredContent
    if identity is None:
        message = "Expected structured program identity"
        raise RuntimeError(message)
    if identity["sha256"] != BASELINE_SHA256:
        message = "Loaded program is not the Hotline Server baseline"
        raise RuntimeError(message)
    return identity


def prepare(plan_path: Path, output: Path) -> tuple[list[Json], str]:
    """Read the plan, create the output directory and name the bridge command.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan: a JSON list of queries.
    output : pathlib.Path
        The directory for the records; created if absent.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], str]
        The plan, and the path of the ``ghidra-mcp`` launcher at the repository
        root.
    """
    root = Path(__file__).resolve().parent.parent
    plan = json.loads(plan_path.read_text())
    output.mkdir(parents=True, exist_ok=True)
    return plan, str(root / "ghidra-mcp")


async def capture(plan_path: Path, output: Path) -> None:
    """Run every query of a plan against the bridge and save the records.

    Parameters
    ----------
    plan_path : pathlib.Path
        The plan: a JSON list of queries.
    output : pathlib.Path
        The directory for the records; created if absent.

    Raises
    ------
    RuntimeError
        If the program identity is wrong before the queries or differs after.
    """
    plan, command = prepare(plan_path, output)
    params = StdioServerParameters(command=command)
    async with (
        stdio_client(params) as (read, write),
        ClientSession(read, write) as session,
    ):
        init = await session.initialize()
        identity = await program_identity(session)
        run = Capture(session, output, identity, init.serverInfo)
        for query in plan:
            await run.query(query)
        after = await session.call_tool("get_program_info", {})
        if after.isError or after.structuredContent != identity:
            message = "Program identity changed during capture"
            raise RuntimeError(message)


def command(plan: str, output: str) -> None:
    """Capture the queries of a plan.

    Parameters
    ----------
    plan
        The plan file: a JSON list of queries.
    output
        The directory that receives the records.
    """
    asyncio.run(capture(Path(plan), Path(output)))


if __name__ == "__main__":
    script_cli.run(command, __doc__)
