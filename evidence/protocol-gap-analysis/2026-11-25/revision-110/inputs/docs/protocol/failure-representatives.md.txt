# Captured representative native failures

This bounded GAP-003 supplement renders one retained
[native](../glossary.md#native) request and its measured result for each of the
five classes named in the original closure criterion. The
[selection record][selection] pins the source plan/report hashes, action
indexes, decoded headers and exact event bytes. All five source reports are
`native-mac-oracle` captures from the identified Hotline Server 1.9 Mac OS
9.0.4/[SheepShaver](../glossary.md#sheepshaver) run; see the
[source runtime][runtime] and [manifest][core]. These are host TCP streams
through SLiRP. A host socket EOF alone does not establish whether the guest
sent FIN or RST.

Each line below is one complete request or response frame, formed by joining
the report's 20-byte receive header and payload events for that action. The
first word of a request contains the transaction type. In the four numbered
error replies the first word is `00010000` (reply marker 1, type 0), followed
by the copied request ID, status `00000001`, equal total/data sizes and one
field 100 (`0064`). Text bytes are shown exactly; the missing-file message
contains MacRoman quote bytes `d2` and `d3`.

This document belongs to the [Hotline 1.9 wire protocol](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

## Authentication: rejected password

[Plan][auth-plan], [report][auth-report], actions 3 send/4 receive. Request
107, ID 1; reply ID 1, status 1, field 100 length 16, ASCII `Incorrect login.`.
Action 5 is a scripted client close; this report does not measure a
server-initiated close. A separate [guest timing corpus][timing] observed one
failed login with no guest FIN/RST for 65.060281 host seconds and another with
a reset after a fresh connection; neither is a universal deadline.

```text
request  0000006b00000001000000000000003e0000003e00050069000b9996878b8a8d9ad2939088006a000a99968d8c8bd28f9e8c8c00a0000200be0066000f666978747572652d73657373696f6e006800020001
reply    0001000000000001000000010000001600000016000100640010496e636f7272656374206c6f67696e2e
field100 496e636f7272656374206c6f67696e2e
```

## Permission: account enumeration denied

[Plan][permission-plan], [report][permission-report], actions 7/8. Request 348,
ID 10; reply ID 10, status 1, field 100 length 43, ASCII
`You are not allowed to administer accounts.`. The client later sends request
115 and 500, receives their replies, then closes at action 13: this particular
denial did not end the control session.

```text
request  0000015c0000000a0000000000000002000000020000
reply    000100000000000a00000001000000310000003100010064002b596f7520617265206e6f7420616c6c6f77656420746f2061646d696e6973746572206163636f756e74732e
field100 596f7520617265206e6f7420616c6c6f77656420746f2061646d696e6973746572206163636f756e74732e
```

## Missing object: file information lookup

[Plan][missing-plan], [report][missing-report], actions 7/8. Request 206, ID
10, naming an absent file; reply ID 10, status 1, field 100 length 75. The
response text begins `Cannot get info because there is no file/folder named`
and embeds `d2`/`d3` around the requested name. The client closes at action 9;
no server FIN/RST is established by this report.

```text
request  000000ce0000000a000000000000001e0000001e000200c900126d6f746872612d616273656e742d66696c6500ca00020000
reply    000100000000000a00000001000000510000005100010064004b43616e6e6f742067657420696e666f2062656361757365207468657265206973206e6f2066696c652f666f6c646572206e616d656420d26d6f746872612d616273656e742d66696c65d32e
field100 43616e6e6f742067657420696e666f2062656361757365207468657265206973206e6f2066696c652f666f6c646572206e616d656420d26d6f746872612d616273656e742d66696c65d32e
```

## Malformed request: zero-size frame

[Plan][malformed-plan], [report][malformed-report], action 7 sends request
300/ID 10 with both size words zero and no payload. Action 8 records host proxy
EOF 4.421455 ms after the send event (473.937017 ms after capture start), with
**no numbered response frame** in that action or the remaining capture. Action
9 is the client's cleanup close. This is an observed host-stream lifetime, not
proof of a particular guest FIN/RST packet or a general rule for all malformed
frames.

```text
request  0000012c0000000a000000000000000000000000
result   host proxy EOF; no reply bytes
```

## Unsupported operation: unknown online transaction

[Plan][unsupported-plan], [report][unsupported-report], actions 11/12. Request
999, ID 4; reply ID 4, status 1, field 100 length 25, ASCII
`Unknown transaction type!`. The same report then records two further error
replies and a scripted client close at action 17. The earlier
[calculated example][derived] uses request ID 1 and is **derived**, whereas the
bytes here are a captured ID-4 exchange.

```text
request  000003e7000000040000000000000002000000020000
reply    0001000000000004000000010000001f0000001f000100640019556e6b6e6f776e207472616e73616374696f6e207479706521
field100 556e6b6e6f776e207472616e73616374696f6e207479706521
```

These five examples satisfy the _representative-byte_ part of the original
GAP-003 criterion. They do not settle every failure status, exception-to-wire
translation, partial effect or failure in an operation without a normal ACK.
The [broader registry][registry] and [reply/effect map][replies] retain those
boundaries. No universal connection deadline, 111-before-close behaviour or
error taxonomy is inferred from this sample.

[selection]: ../../evidence/gap-remediation/2026-11-13/failure-representatives-01/selected-witnesses.json
[core]: ../../evidence/gap-remediation/2026-11-12/native-core-01/manifest.json
[runtime]: ../../evidence/gap-remediation/2026-11-12/native-core-01/runtime.json
[auth-plan]: ../../evidence/gap-remediation/2026-11-12/native-core-01/old-password-rejected/plan.json
[auth-report]: ../../evidence/gap-remediation/2026-11-12/native-core-01/old-password-rejected/report.json
[permission-plan]: ../../evidence/gap-remediation/2026-11-12/native-core-01/low-privilege-and-missing-room/plan.json
[permission-report]: ../../evidence/gap-remediation/2026-11-12/native-core-01/low-privilege-and-missing-room/report.json
[missing-plan]: ../../evidence/gap-remediation/2026-11-12/native-core-01/missing-file-info/plan.json
[missing-report]: ../../evidence/gap-remediation/2026-11-12/native-core-01/missing-file-info/report.json
[malformed-plan]: ../../evidence/gap-remediation/2026-11-12/native-core-01/malformed-zero-size/plan.json
[malformed-report]: ../../evidence/gap-remediation/2026-11-12/native-core-01/malformed-zero-size/report.json
[unsupported-plan]: ../../evidence/gap-remediation/2026-11-12/native-core-01/early-login-and-errors/plan.json
[unsupported-report]: ../../evidence/gap-remediation/2026-11-12/native-core-01/early-login-and-errors/report.json
[timing]: ../../evidence/gap-remediation/2026-11-12/native-transport-01/timing-observations.json
[derived]: error-outcomes.md#derived-unknown-operation-example
[registry]: error-outcomes.md#wire-status-and-failure-classes
[replies]: operation-contracts.md#per-operation-reply-and-fan-out-map
