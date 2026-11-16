"""A fake of the Ghidra MCP client library, replaying retained query records.

``capture-ghidra-evidence.py`` imports ``mcp`` and talks to a bridge process
that needs Ghidra. These classes stand in for the library so that its requests
can be recorded and its responses scripted, with no bridge and no network. The
replies are normally the ``result`` of a retained record under
``evidence/hotline-server-1.9/queries``, which is what the real bridge returned
when those records were captured.
"""

import copy
import dataclasses as dc
import json
import sys
import types
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    import pytest

RETAINED = Path(__file__).resolve().parents[1] / "evidence/hotline-server-1.9"
BASELINE_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"


def require_json(mode: str) -> None:
    """Refuse any dump mode but the one the script passes.

    Raises
    ------
    AssertionError
        If ``mode`` is not ``"json"``.
    """
    if mode != "json":
        message = f"the script dumped in mode {mode!r}"
        raise AssertionError(message)


class FakeResult:
    """A tool result with the attributes that the script reads."""

    def __init__(self, payload: dict[str, typ.Any]) -> None:
        """Wrap a result dictionary as a retained record stores it.

        Parameters
        ----------
        payload : dict[str, typing.Any]
            The ``result`` of a record: ``isError``, ``structuredContent`` and
            optionally ``content``.
        """
        self.payload = payload

    def __getattr__(self, name: str) -> object:
        """Answer the library's result attributes from the payload.

        Parameters
        ----------
        name : str
            The attribute asked for.

        Returns
        -------
        object
            The payload's value, with ``content`` defaulting to an empty list.

        Raises
        ------
        AttributeError
            For any other name.
        """
        if name == "content":
            return self.payload.get("content", [])
        if name in {"isError", "structuredContent"}:
            return self.payload[name]
        raise AttributeError(name)

    def model_dump(self, mode: str) -> dict[str, typ.Any]:
        """Return the payload as the library's JSON-mode dump does.

        Parameters
        ----------
        mode : str
            Must be ``"json"``, as the script passes.

        Returns
        -------
        dict[str, typing.Any]
            A copy of the payload.
        """
        require_json(mode)
        return copy.deepcopy(self.payload)


class FakeServerInfo:
    """The server description whose dump the script stores in each record."""

    def __init__(self, info: dict[str, typ.Any]) -> None:
        """Hold the dictionary to dump."""
        self.info = info

    def model_dump(self, mode: str) -> dict[str, typ.Any]:
        """Return the description in JSON mode.

        Returns
        -------
        dict[str, typing.Any]
            A copy of the description.
        """
        require_json(mode)
        return copy.deepcopy(self.info)


@dc.dataclass(frozen=True, slots=True)
class FakeParams:
    """Stands in for ``StdioServerParameters``."""

    command: str


class FakeTransport:
    """Stands in for the object that ``stdio_client`` returns."""

    def __init__(self, bridge: Bridge, params: FakeParams) -> None:
        """Log the bridge command that the script chose."""
        self.bridge = bridge
        bridge.events.append(("stdio", params.command))

    async def __aenter__(self) -> tuple[str, str]:
        """Open the streams.

        Returns
        -------
        tuple[str, str]
            Stand-ins for the read and write streams.
        """
        return ("read-stream", "write-stream")

    async def __aexit__(self, *exc: object) -> None:
        """Log the close."""
        self.bridge.events.append(("stdio-exit",))


class FakeSession:
    """Stands in for ``ClientSession``."""

    def __init__(self, bridge: Bridge, read: str, write: str) -> None:
        """Log the streams that the script passed."""
        self.bridge = bridge
        bridge.events.append(("session", read, write))

    async def __aenter__(self) -> FakeSession:
        """Open the session.

        Returns
        -------
        FakeSession
            This session.
        """
        return self

    async def __aexit__(self, *exc: object) -> None:
        """Log the close."""
        self.bridge.events.append(("session-exit",))

    async def initialize(self) -> types.SimpleNamespace:
        """Log the handshake and describe the server.

        Returns
        -------
        types.SimpleNamespace
            An object whose ``serverInfo`` dumps the scripted description.
        """
        self.bridge.events.append(("initialize",))
        return types.SimpleNamespace(serverInfo=FakeServerInfo(self.bridge.info))

    async def call_tool(self, name: str, arguments: dict[str, typ.Any]) -> FakeResult:
        """Log a call and return the next scripted reply.

        Returns
        -------
        FakeResult
            The reply.
        """
        self.bridge.events.append(("call", name, copy.deepcopy(arguments)))
        return self.bridge.replies.pop(0)


class Bridge:
    """A scripted bridge: replies are consumed in call order, calls are logged.

    Attributes
    ----------
    events : list[tuple[typing.Any, ...]]
        Every observable step in order: ``("stdio", command)``,
        ``("session", read, write)``, ``("initialize",)``,
        ``("call", tool, arguments)`` and the exits.
    """

    def __init__(
        self, replies: cabc.Iterable[dict[str, typ.Any]], info: dict[str, typ.Any]
    ) -> None:
        """Script the replies and the server description.

        Parameters
        ----------
        replies : collections.abc.Iterable[dict[str, typing.Any]]
            Result dictionaries, one per ``call_tool``, in order.
        info : dict[str, typing.Any]
            The server description returned by ``initialize``.
        """
        self.replies = [FakeResult(reply) for reply in replies]
        self.info = info
        self.events: list[tuple[typ.Any, ...]] = []

    def calls(self) -> list[tuple[str, dict[str, typ.Any]]]:
        """List the tool calls made.

        Returns
        -------
        list[tuple[str, dict[str, typing.Any]]]
            Tool name and arguments, in order.
        """
        return [(event[1], event[2]) for event in self.events if event[0] == "call"]

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Place the fake ``mcp`` package in ``sys.modules``.

        Parameters
        ----------
        monkeypatch : pytest.MonkeyPatch
            The fixture that restores ``sys.modules`` afterwards.
        """

        def stdio_client(params: FakeParams) -> FakeTransport:
            """Stand in for ``stdio_client``.

            Returns
            -------
            FakeTransport
                The transport, bound to this bridge.
            """
            return FakeTransport(self, params)

        def client_session(read: str, write: str) -> FakeSession:
            """Stand in for ``ClientSession``.

            Returns
            -------
            FakeSession
                The session, bound to this bridge.
            """
            return FakeSession(self, read, write)

        mcp = types.ModuleType("mcp")
        stdio = types.ModuleType("mcp.client.stdio")
        vars(mcp).update(ClientSession=client_session, StdioServerParameters=FakeParams)
        vars(stdio).update(stdio_client=stdio_client)
        modules = {
            "mcp": mcp,
            "mcp.client": types.ModuleType("mcp.client"),
            "mcp.client.stdio": stdio,
        }
        for name, module in modules.items():
            monkeypatch.setitem(sys.modules, name, module)


def retained_record(identifier: str) -> dict[str, typ.Any]:
    """Read one retained query record.

    Returns
    -------
    dict[str, typing.Any]
        The parsed record.
    """
    path = RETAINED / "queries" / f"{identifier}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def ok(data: dict[str, typ.Any] | None) -> dict[str, typ.Any]:
    """Build a successful result around structured data.

    Returns
    -------
    dict[str, typing.Any]
        A result dictionary.
    """
    return {"isError": False, "structuredContent": data, "content": []}
