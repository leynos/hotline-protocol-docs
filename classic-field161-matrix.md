# Classic client field-161 width and omission matrix

The [portable B52 corpus][corpus] records three one-attempt local sessions on
14 November 2026 through the fixed, isolated [Classic login proxy][proxy]. The
actual native Hotline Server 1.9 sent the same successful Login107 ACK each
time: field 160 `00be`, field 161 `0000`, 34 bytes. The as-run proxy source
SHA-256 was `44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e`.
Only the ACK field-161 shape changed on the downstream path. The archive and
app label say **1.9.2**; embedded `vers` says **1.9.1.0**. The identified
client DATA/RSRC hashes are in the corpus manifest. Neither label proves vendor
authenticity or identifies a universal client release profile.

| Variant         | Forwarded ACK | 161 value  | Client progression | Proxy teardown |
| --------------- | ------------: | ---------- | ------------------ | -------------: |
| `omit-161`      | 28 bytes      | Absent     | 121/300/212; data  | 28.282 s       |
| `one-byte-161`  | 33 bytes      | `00`       | 121/300/212; data  | 28.089 s       |
| `four-byte-161` | 36 bytes      | `00000000` | 121/300/212; data  | 28.248 s       |

Each client sent Login107, saw the exact controlled 242-byte 109 agreement, and
accepted it once. The client then sent 121 with display name `unnamed`, 300 and
212. Native returned the login ACK, 109, a 121 ACK, 354, 122, a 300 roster
record and a 212 ACK. The dynamic 212 reference matched the 16-byte `HTXF` data
request; the 58-byte `GIF89a` response reached the client. UI screenshots show
Connected and roster-transfer progress. The banner still said **Loading banner
image**; rendering completion is unproved.

The verifier selects one complete SYN lifetime, including FIN/RST tails, at
five views: client guest, proxy namespace ingress, proxy namespace upstream,
host loopback, and server guest. All client-to-server control bytes match at
all five views. Raw server bytes match across upstream, host and server guest;
forwarded bytes match across namespace ingress and client guest. Applying the
pinned transformation to the native 34-byte ACK yields the _only_
server-direction difference; all following frames and both data directions
match byte-for-byte. Intended proxy audit bytes are also compared with the
delivered streams. Client and server event threads may interleave in the audit
log; each directional order is verified independently.

The separate managed host and namespace recorders passed ten readiness checks:
after launch, before A7, and before each Connect. Receipts pin the running PID,
start tick, namespace inode, writable PCAP FD and fixed group deadline. Their
retained journals report 0 kernel drops. The group finished before its
12-minute deadline. Exact 29-action A7 preflight and postflight matched: two
accounts, 41 Files entries, 242-byte agreement SHA-256
`5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7`, and full
1,049,073-byte FILP download including identical DATA and MACR forks. The three
proxy units and two recorder units ended with MainPID 0; the original emulators
remained live with unchanged executable hashes.

The proxy intentionally closed each connection about 28 seconds after its ACK,
with relay teardown under 30 seconds. The later **Connection Closed** dialog is
therefore not evidence that the client rejected any 161 variant. These
observations establish tolerance of the three tested zero-valued shapes
**through the listed stages**. They do not establish the meaning of 161,
nonzero values, field 162, banner rendering, or complete interoperability.

An earlier B50 run stopped before any variant because its namespace recorder
had exited despite a valid PCAP header. The operator missed the absent `lsof`
FD. The [B51 readiness gate][gate] checks the actual managed process, FD and
remaining deadline; B52 used it. B50 was a capture failure, not a protocol
result. The complete B52 source PCAPs remain ignored locally; the portable
corpus retains selected complete TCP lifetimes, packet indexes, action records,
A7 reports, screenshots, frozen as-run proxy and parser sources at revision
`79d867d`, and a SHA inventory. The verifier checks the historical source
snapshots, while current transformation code is separately checked against the
retained ACK outputs. Later proxy edits do not change the recorded source
identity.

Replay from this repository in an adjacent two-repository export:

```sh
python3 scripts/verify_classic_field161_matrix.py \
  evidence/gap-remediation/2026-11-14/classic-field161-01
python3 -m unittest discover -s scripts -p 'test_verify_classic_field161_matrix.py'
```

[corpus]: evidence/gap-remediation/2026-11-14/classic-field161-01/
[proxy]: classic-login-proxy.md
[gate]: https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/docs/capture-readiness.md
