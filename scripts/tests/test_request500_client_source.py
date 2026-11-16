"""Fault controls for the pinned source-chain predicates."""

import pytest
from verify_request500_client_source import check_chain

PROTOCOL = "case connectionKeepAlive = 500"
STATE = "func completeLogin() { await client.startKeepAlive() }"
CLIENT = (
    "\n"
    "performLogin(login); setServerInfo(serverInfo)\n"
    "reply.getField(type: .versionNumber)?.getUInt16()\n"
    "private static let keepAliveAfter: Duration = .seconds(180)\n"
    "func startKeepAlive() { Task.sleep(for: .seconds(15)) }\n"
    "func keepAliveIfQuiet() { lastTraffic >= Self.keepAliveAfter; "
    "sendKeepAlive() }\n"
    "func sendKeepAlive() { version >= 185; type: .connectionKeepAlive; "
    "self.send(transaction); self.getUserList() }\n"
    "func send(_ transaction: HotlineTransaction) { lastTraffic = .now; "
    "transaction.type != .connectionKeepAlive }\n"
    "func handleTransaction() { lastTraffic = .now; "
    "handleReply(transaction) }\n"
    "func handleReply() { pendingTransactions.removeValue(forKey: "
    "transaction.id); Received reply for unknown transaction }\n"
    "func disconnect() { keepAliveTask?.cancel() }\n"
    "enableKeepAlive = true; keepAliveIdleTime = 60\n"
)


class ChainTests:
    """Reject each broken link of the keep-alive source chain."""

    def test_chain(self) -> None:
        """Accept the chain with every link in place."""
        check_chain(PROTOCOL, CLIENT, STATE)

    def test_wrong_opcode(self) -> None:
        """Refuse a protocol source whose opcode is not 500."""
        with pytest.raises(ValueError, match="opcode 500"):
            check_chain(PROTOCOL.replace("500", "501"), CLIENT, STATE)

    def test_wrong_threshold(self) -> None:
        """Refuse a client whose keep-alive threshold is not 180 seconds."""
        with pytest.raises(ValueError, match="180-second threshold"):
            check_chain(
                PROTOCOL, CLIENT.replace(".seconds(180)", ".seconds(60)"), STATE
            )

    def test_missing_postlogin_start(self) -> None:
        """Refuse a login that never starts the keep-alive."""
        with pytest.raises(ValueError, match="post-login start"):
            check_chain(
                PROTOCOL, CLIENT, STATE.replace("startKeepAlive", "stopKeepAlive")
            )
