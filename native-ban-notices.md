# Native 1.9 temporary ban notice: disposable option-one witness

This is a bounded **GAP-044** observation from one disposable Mac OS 9 Hotline
Server 1.9 lab. The byte-level option-one notice is witnessed; option two and
post-ban Login107 were later measured in a
[separate control-only witness](native-ban-control-witness.md). The
1,800-second expiry and reload persistence remain open. The option-one capture
is `evidence/gap-remediation/2026-11-13/native-ban-one-01/`.

## Identity and baseline

The lab was prepared from the stopped read-only disk with SHA-256
`e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910`. The ROM
SHA-256 was `18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd`.
Read-only preboot HFS extraction identified `/Hotline19/HLserver19` DATA
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b` and RSRC
`fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12`. The lab
emulator PID 3953986 held only its owned working disk at FD 6 and owned guest
capture at FD 16. Its network namespace `net:[4026532475]` differed from the
primary server and isolated client namespaces.

Before the ban, the original A7 29-action readback passed against lab endpoints
`127.0.0.1:15720/15721`. It matched the two-account baseline, exactly 41 Files
entries, fields 201/205/206/207/213, unchanged idle 303, and the complete
1,049,073-byte FILP transfer. The DATA and resource fork hashes matched the
frozen original fixture. The source A7 plan, as-run plan, report, and local
semantic verification are frozen separately.

## One option-one exchange

GET 352 first returned error 1 for absent `m-ban32-only`. Create 350 then
returned success; subsequent GET 352 returned access field 110 as eight zero
bytes. Both administrator and target Login 107 replies had status 0. The
administrator's type 301 disclosed the target's two-byte UID `0005`.

Exactly one administrator request 110, ID 33, carried field 103 `0005` and
field 113 `0001`. The target received unsolicited type 104, ID 3, with one
field 101:

```text
59 6f 75 20 61 72 65 20 74 65 6d 70 6f 72 61 72 69 6c 79 20
62 61 6e 6e 65 64 20 6f 6e 20 74 68 69 73 20 73 65 72 76 65 72 2e
```

These bytes decode as “You are temporarily banned on this server.” The target
socket then reached EOF. The administrator received a numbered type-0 ACK, ID
33, status 0. The namespace and guest TCP streams contain a later unsolicited
type 302, ID 4, field 103 `0005`. The capture runner closed the administrator
socket after reading the ACK; the 302 is a **packet-stream observation**, not a
runner-consumed frame. The ordered stream offsets and both packet views are in
`fixture/ban-stream-views.json`.

One fresh TCP connection sent only the TRTP handshake. The server returned the
normal eight-byte handshake response; the runner then timed out waiting for
EOF. Its report status is **failed** at two completed actions. It did not send
Login 107, so this probe establishes neither post-ban login rejection nor an
enforcement defect. A separate Ghidra read places ban checks at Login 107; its
own independent evidence belongs in
`evidence/gap-remediation/2026-11-13/native-ban-oracle-01/` when published. No
runtime retest was made on that basis.

## Isolation and limits

The existing isolated launcher still made its fixed primary-port 15500 relay
available in the lab namespace. It was unused: the independent host recorder
captured zero packets, and the namespace recorder found zero 15500/15501 SYN
packets. The lab had loopback only and empty main routes. This limits
accidental routing during this run; it is not a full sandbox or a proof that
the relay could never be used. The actual emulator was a child of a
`sudo unshare` chain outside the user service's control group; teardown
verified that exact PID was gone. Primary server and client FD identities
remained unchanged.

The stopped lab's Hotline19 directory listing matched its base listing. No
`Banned` file appeared there, but that directory check does not prove global
absence of writes or persistence. The source disk stayed unchanged; the used
working disk was retained separately. No option-two branch, clock change,
account change on the primary, or second fresh probe occurred.

Offline replay, from the adjacent protocol documentation repository:

```sh
python3 scripts/verify_native_ban_one.py \
  evidence/gap-remediation/2026-11-13/native-ban-one-01
python3 -m unittest discover -s scripts -p 'test_native_ban_one.py'
```

The [second-lab transfer failure](native-transfer-stall.md) preserves the
failed mandatory baseline and offline packet findings. It supplies no
option-two ban result.
