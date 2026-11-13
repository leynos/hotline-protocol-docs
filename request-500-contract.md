# Request 500: native reply and one modern client's schedule

Hotline Server 1.9 dispatches request **500** only for an online session with
no recorded authentication failure. Before the session is online, its
dispatcher admits only 107 and 121; another numbered request, including 500,
takes the close path. The [dispatcher
map](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c) routes 500 to
[`10018c00`](../mothra/evidence/hotline-server-1.9/queries/D-10018c00.c),
which constructs and queues an empty direct success reply. Captured requests
confirm the empty ACK and matching request ID in the [framing
corpus](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json).
The complete-request dispatch path refreshes the server activity timestamp
before selecting the handler; partial TCP input does not. See [activity
clocks](session-transport-contracts.md#activity-clocks-and-incomplete-input).
These facts establish a server mechanism, not a required client schedule.

A separate [pinned source-only
corpus](../mothra/evidence/gap-remediation/2026-11-13/request500-client-source-01/manifest.json)
identifies one modern Swift client's chosen behaviour at commit
`ace7945525429742874bc4b0bb377d76a836b239`:

| Source anchor | Observed implementation |
| --- | --- |
| `HotlineProtocol.swift:1212` | Names type 500 `connectionKeepAlive`. |
| `HotlineState+Connection.swift:390–422` | Starts the timer after login completes. |
| `HotlineClient.swift:488–510, 774–805` | Reads the server version from the login reply, checks every 15 seconds, and sends a fieldless 500 after at least 180 seconds of inbound and outbound silence when reported version is at least 185. Otherwise it requests user list 300. A 15-second check cadence does not guarantee a send at exactly 180 seconds. |
| `HotlineClient.swift:562–581, 712–720, 778–805` | Incoming replies reset the traffic clock. Type 500 does not update the separate client activity clock; its send path does not register a pending reply waiter. A returned ACK is logged as an unknown reply ID, without immediate retry. Disconnect cancels the timer task. |
| `HotlineClient.swift:373–376` | Separately configures TCP keepalive at 60 seconds; this is distinct from transaction 500. |

The client's own keepalive name and timer explain **that implementation's**
purpose and scheduling. Its comment comparing the behaviour with an original
client is not independent evidence about a historical binary. The client was
not run against native 1.9 here; whether it chooses 500 in that pairing
depends on the actual login-reported version. The identified shx 0.1.48 build
has no located 500 sender, and its finite no-500 capture windows do not
establish a universal absence or interval. No mandatory request-500 period,
ACK-wait rule, or native-author intent follows from these sources. Wider
client support remains profile-specific.

The [offline source
guard](../mothra/scripts/verify_request500_client_source.py) checks the pinned
file hashes and this enum-to-trigger chain against locally retained raw files.
Full third-party files are not redistributed in the corpus because the pinned
licence was not established within the bounded lookup. Supply the three files
at their manifest URLs with `--source-dir` to rerun the guard. This packet
includes no run of the modern client.
