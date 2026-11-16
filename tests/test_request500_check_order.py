"""Pin the order of the request-500 source predicates.

``verify_request500_client_source.check_chain`` requires thirteen facts of three
frozen source files, one after another. This table holds, for each fact broken
alone and for each pair of facts broken together, the ending on the script as it
stood before it was brought to the standard (commit 8a3f8cd): the message of the
predicate that runs first. The cases are in ``data/request500_check_order.tsv``.
"""

import itertools
from pathlib import Path

import pytest
from characterize_support import Cases, record, replay
from verify_request500_client_source import check_chain

TABLE = Path(__file__).with_name("data") / "request500_check_order.tsv"
PROTOCOL = "case connectionKeepAlive = 500"
STATE = "func completeLogin() { await client.startKeepAlive() }"
CLIENT = "\n".join([
    "",
    "performLogin(login); setServerInfo(serverInfo)",
    "reply.getField(type: .versionNumber)?.getUInt16()",
    "private static let keepAliveAfter: Duration = .seconds(180)",
    "func startKeepAlive() { Task.sleep(for: .seconds(15)) }",
    "func keepAliveIfQuiet() { lastTraffic >= Self.keepAliveAfter; sendKeepAlive() }",
    (
        "func sendKeepAlive() { version >= 185; type: .connectionKeepAlive; "
        "self.send(transaction); self.getUserList() }"
    ),
    (
        "func send(_ transaction: HotlineTransaction) { lastTraffic = .now; "
        "transaction.type != .connectionKeepAlive }"
    ),
    "func handleTransaction() { lastTraffic = .now; handleReply(transaction) }",
    (
        "func handleReply() { pendingTransactions.removeValue(forKey: transaction.id); "
        "Received reply for unknown transaction }"
    ),
    "func disconnect() { keepAliveTask?.cancel() }",
    "enableKeepAlive = true; keepAliveIdleTime = 60",
    "",
])
# Each fact: the file it is read from, a text that it needs, and a text without it.
BREAKS = {
    "opcode": ("protocol", "= 500", "= 501"),
    "post-login": ("state", "startKeepAlive", "stopKeepAlive"),
    "server-info": ("client", "setServerInfo(serverInfo)", "setServerInfo(info)"),
    "version": ("client", "getUInt16()", "getUInt8()"),
    "threshold": ("client", ".seconds(180)", ".seconds(60)"),
    "check": ("client", ".seconds(15)", ".seconds(20)"),
    "quiet": ("client", "lastTraffic >= Self", "lastTraffic > Self"),
    "branch": ("client", "version >= 185", "version >= 190"),
    "traffic": ("client", "transaction.type !=", "transaction.type =="),
    "reply-traffic": (
        "client",
        "; handleReply(transaction)",
        "; handleOther(transaction)",
    ),
    "ack": ("client", "Received reply for unknown", "Received nothing for unknown"),
    "disconnect": ("client", "keepAliveTask?.cancel()", "keepAliveTask?.pause()"),
    "tcp": ("client", "keepAliveIdleTime = 60", "keepAliveIdleTime = 30"),
}


def broken(names: tuple[str, ...]) -> object:
    """Break the named facts in the three files and run the check.

    Returns
    -------
    object
        What ``check_chain`` returned.
    """
    texts = {"protocol": PROTOCOL, "client": CLIENT, "state": STATE}
    for name in names:
        file, needed, replacement = BREAKS[name]
        texts[file] = texts[file].replace(needed, replacement)
    return check_chain(texts["protocol"], texts["client"], texts["state"])


CASES: Cases = {"intact": lambda: broken(())}
CASES |= {name: (lambda n=name: broken((n,))) for name in BREAKS}
CASES |= {
    f"{a}+{b}": (lambda pair=(a, b): broken(pair))
    for a, b in itertools.combinations(BREAKS, 2)
}


class Request500CheckOrderTests:
    """Keep the predicates in the order in which they have run."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each broken source ends with the message recorded earlier."""
        now, recorded = replay(CASES, TABLE, name)
        assert now == recorded, "ending differs"


def table() -> str:
    """Say how every case ends, for the table; run it only on the earlier scripts.

    Returns
    -------
    str
        The table text.
    """
    return record(CASES)
