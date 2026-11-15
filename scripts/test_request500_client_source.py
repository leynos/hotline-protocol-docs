"""Fault controls for the pinned source-chain predicates."""

import unittest

from verify_request500_client_source import check_chain


class ChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.protocol = "case connectionKeepAlive = 500"
        self.state = "func completeLogin() { await client.startKeepAlive() }"
        self.client = """
performLogin(login); setServerInfo(serverInfo)
reply.getField(type: .versionNumber)?.getUInt16()
private static let keepAliveAfter: Duration = .seconds(180)
func startKeepAlive() { Task.sleep(for: .seconds(15)) }
func keepAliveIfQuiet() { lastTraffic >= Self.keepAliveAfter; sendKeepAlive() }
func sendKeepAlive() { version >= 185; type: .connectionKeepAlive; self.send(transaction); self.getUserList() }
func send(_ transaction: HotlineTransaction) { lastTraffic = .now; transaction.type != .connectionKeepAlive }
func handleTransaction() { lastTraffic = .now; handleReply(transaction) }
func handleReply() { pendingTransactions.removeValue(forKey: transaction.id); Received reply for unknown transaction }
func disconnect() { keepAliveTask?.cancel() }
enableKeepAlive = true; keepAliveIdleTime = 60
"""

    def test_chain(self) -> None:
        check_chain(self.protocol, self.client, self.state)

    def test_wrong_opcode(self) -> None:
        with self.assertRaisesRegex(ValueError, "opcode 500"):
            check_chain(self.protocol.replace("500", "501"), self.client, self.state)

    def test_wrong_threshold(self) -> None:
        with self.assertRaisesRegex(ValueError, "180-second threshold"):
            check_chain(
                self.protocol,
                self.client.replace(".seconds(180)", ".seconds(60)"),
                self.state,
            )

    def test_missing_postlogin_start(self) -> None:
        with self.assertRaisesRegex(ValueError, "post-login start"):
            check_chain(
                self.protocol,
                self.client,
                self.state.replace("startKeepAlive", "stopKeepAlive"),
            )


if __name__ == "__main__":
    unittest.main()
