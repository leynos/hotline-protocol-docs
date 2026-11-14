# Identified shx peer field tolerance: controlled matrix

This matrix extends the [identified client source](identified-client-source.md)
record for GAP-080/081. It uses one identified **complete terminal shx 0.1.48
build**, not a second historical client or a SynHX server. The source revision
is `adb1bf8c8cb12f7eb2fa2c01673295a6312f262b`; the executable SHA-256 is
`8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0`.
The matching [profile record][profile] gives the build flags, patch and
dependencies. The retained native 1.9 PEF SHA-256 is
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
Those identities are checked before launching the client. Neither reported
sub-version 2 nor field 160 identifies the peer build.

The [new corpus][corpus] contains five complete client sessions against a
**controlled loopback receiver**, with ports 15600–15604. The fixture starts
from exact retained native handshake/login/privileges/agreement/roster/chat
frames. It changes only the named field or delivery order. Banner 122 is the
exact 71-byte native frame retained in the earlier corpus. The listener and
client syscall records, loopback PCAP, raw terminal bytes, process exits and
private HOME outputs are preserved. This is real client behaviour under a
controlled receiver; it is **not** execution of the Mac server or SynHX daemon.

| Case | Deliberate receiver variant | Observed complete client result |
| --- | --- | --- |
| `control` | Native bootstrap, no banner | Login, automatic roster, explicit roster reload, chat and normal exit. |
| `omit-161` | Remove field 161 from login reply | Same continuation and normal exit. |
| `vary-161` | Change native 161 from `0000` to `0001` | Same continuation and normal exit; no claim about the field's meaning. |
| `unknown-login` | Append field 32767 containing `mothra-unknown-login` | Same continuation and normal exit. |
| `early-122` | Deliver exact native banner 122 after agreement, before automatic roster request | Client reports `unknown header type 0x0000007a`, writes the exact 71 bytes to `hx.dump`, then reloads the roster, chats and exits normally. |

The five sessions used the same compiled profile and reported handshake
`TRTPHOTL 00 01 00 02`. Each sent 166 client socket bytes. Receiver totals
were 496, 490, 496, 520 and 567 bytes respectively. The loopback PCAP has
114 retained packets and zero kernel drops. The verifier reconciles each
direction's TCP stream with peer syscalls and listener events; it checks exact
field bytes, frame ordering, banner dump, terminal continuation, identity,
private-home save and checksum inventory. Four discovery tests include
checksum-refreshed wrong identity, changed 161 value and changed banner order
negative controls.

Prior [native full-peer sessions][prior] already show this same build accepting
native 160=`00be`, 161=`0000`, ASCII/high-byte 162 and native roster output.
Prior controlled receiver sessions show field 115 subject presentation and
122 delivery after the automatic roster. The new trials add omission/value/
unknown-field and earlier 122 ordering checks. They do not establish arbitrary
field tolerance, malformed-TLV tolerance, banner presentation, other compiled
profiles or the behaviour of unidentified clients.

The [exact-build registry](peer-profile-rules.md) now supplies GAP-080's
protocol targets and unknown-peer rule, including the separately identified
Classic candidate. These five conditions remain finite GAP-081 evidence;
untested cells stay explicit and no universal omission/default policy is
chosen. Release-target selection remains separate. GAP-082 remains open:
the earlier ambiguous-byte chat sample is one build's byte-preservation
evidence, and mxd's state/field decoder policy and independent interoperability
tests are separate requirements.

## Reproduce and verify

In a clean adjacent checkout with the retained build, dependencies, `bwrap`,
`strace` and permission for loopback `tcpdump`, run from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/peer_tolerance_run.py \
  --root . --protocol ../hotline-protocol-docs \
  --work state/delegation/peer/run-01 \
  --destination evidence/gap-remediation/2026-11-13/delegated-peer-01
python3 ../hotline-protocol-docs/scripts/verify_peer_tolerance.py \
  evidence/gap-remediation/2026-11-13/delegated-peer-01 \
  --source evidence/gap-remediation/2026-11-13
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p 'test_peer_tolerance.py'
```

The work and destination paths must be fresh. The driver checks identities and
available ports before creating them. It uses the existing capture driver's
read-only system sandbox with a private HOME bound under
`state/delegation/peer/run-01/captures/`. The real `~/.hxvars` before/after
hash, size and timestamp are checked. The old client always writes `.hxvars`
on normal exit, even with `-q`, so direct uncontained execution is unsafe.
The fixture never contacts the shared native control port 15500.

[profile]: ../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/peer-profile.json
[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/delegated-peer-01/manifest.json
[prior]: identified-client-source.md#native-configured-name-and-controlled-receiver-matrix

## Cross-peer acceptance and omission rules

The [profile registry](peer-profile-rules.md) pins the exact shx executable
and Classic DATA/RSRC pair. The following cells consolidate their measured
coverage; a product name or reported version does not extend a cell to
another build.

| Field/output | Identified shx terminal build | Identified Classic candidate |
| --- | --- | --- |
| Native 161=`0000` | Native sessions continue. | Native baseline continues through login, roster and banner data. |
| 161 omission/value/width | Controlled omission and `0001` continue. | Native proxy omission, one zero byte and four zero bytes continue. |
| Nonempty 162 | Native ASCII/high-byte configured names continue through the recorded stages. | One 14-byte ASCII append continues through login, roster and banner data. |
| Banner 122 | Controlled delivery/order tests produce an unknown-header diagnostic and exact dump, then roster/chat continuation; banner presentation is unsupported. | Native advertisement leads to a 16-byte data request and 58-byte banner response; image rendering remains unproved. |
| Native packed roster 300 | Native sessions and controlled reload continue. | The Online Users row is displayed. |
| SynHX-shaped subject 115 addition | Controlled receiver observation includes subject display and continuation. | One 15-byte ASCII append to the first roster reply preserves subsequent Online Users row display; subject rendering remains unproved. |

The additional Classic evidence is the
[native baseline](classic-native-baseline.md),
[161 matrix](classic-field161-matrix.md),
[ASCII server name](classic-server-name-162.md), and
[first-roster subject](classic-roster-subject-115.md). Each proxy corpus
retains both the native and modified streams. The subject test's later
Online Users row supplies a processing observation; a TCP ACK or an earlier
212 request alone would not establish that the roster was processed. Its
screenshot file timestamp is a receipt bound, not a measured capture-start
time. No topic or banner rendering claim follows.

No observed field rejection in these cells requires a family-based omission
rule. The shx 122 diagnostic is an observed unsupported feature with continued
operation, not an inferred session failure. Keep native 1.9's documented
producer rules, including its numeric version/configuration condition for
122, separate from peer identity. Unknown builds and untested values remain
unknown; this is not universal tolerance of malformed or arbitrary TLVs.

This matrix meets GAP-081's original finite evidence criterion before any
omission/default policy is selected. It does not choose an mxd implementation
or release policy. Non-ASCII ambiguity, field meanings, and release sign-off
remain their separate requirements.
