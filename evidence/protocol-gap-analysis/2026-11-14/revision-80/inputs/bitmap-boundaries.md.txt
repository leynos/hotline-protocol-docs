# Native 1.9 privilege bitmap replacement and width observations

This [13-capture corpus][corpus] tests field 110 against the exact Mac PPC
Hotline Server 1.9 DATA SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
It is a bounded GAP-031 investigation with field-110 evidence for GAP-015,
GAP-016 and GAP-019. The [runtime record][runtime] names the continuing
Mac OS 9.0.4 guest, executable, service and original guest capture source.
Only the preflight-absent `m-bit32-owned` account was written. The cleanup
restored the exact two-entry account enumeration.

## All 64 bit positions

The [per-bit evidence table][bits] has one row for each bit `0..63`, its case,
353 request ID, 352 readback ID, submitted eight bytes and returned eight
bytes. Every 353 replacement succeeded, and every immediate 352 readback
equalled the submitted single bit. The eight [walk reports][walk] each contain
eight ordered replacement/readback pairs. The bit formula is byte index
`b >> 3`, mask `0x80 >> (b & 7)`; bit 0 is
`80 00 00 00 00 00 00 00`, bit 7 is
`01 00 00 00 00 00 00 00`, bit 8 is
`00 80 00 00 00 00 00 00`, and bit 63 is
`00 00 00 00 00 00 00 01`. This is measured replacement/readback for all
positions, including currently unlabelled bits. It does not show that each
position grants a distinct permission or is safe to use.

Each 353 request repeated the owned complemented login, fixed display name,
field 111 value `bitmap32` and the one-NUL field-106 password preservation
sentinel. The 352 replies consistently returned that name, complemented login
and nonempty-password placeholder `x`. This prevents a changed name/password
from being mistaken for a field-110 effect. Field 111 is not returned by 352;
the fixture supplies it on every replacement. The [account record rules][record]
show that 353 starts a cleared record, so omitting 111 could clear it. These
captures do not use field-111 absence to infer any bitmap effect or attribute
meaning.

## Field-110 presence and width

All six [width controls][widths] used the same owned account and 353/352 pair.
Every replacement returned status 0. The differing marker bytes expose both
zero fill and the eight-byte copy cap:

| Submitted field 110 | Bytes in TLV | Exact 352 readback |
| --- | ---: | --- |
| Absent | — | `00 00 00 00 00 00 00 00` |
| Present empty | 0 | `00 00 00 00 00 00 00 00` |
| `a5` | 1 | `a5 00 00 00 00 00 00 00` |
| `01 23 45 67 89 ab cd` | 7 | `01 23 45 67 89 ab cd 00` |
| `10 32 54 76 98 ba dc fe` | 8 | `10 32 54 76 98 ba dc fe` |
| `10 32 54 76 98 ba dc fe 55` | 9 | `10 32 54 76 98 ba dc fe` |

The [353 handler][handler] calls the field reader with an eight-byte
destination after clearing the replacement record. These native cases show
accepted omitted/zero/short/exact/nine-byte inputs and returned eight-byte
values for **this operation**. They do not establish a universal TLV-width
rule, a 65,535-byte input outcome or an mxd release policy. An omitted 110
clears the replacement account bitmap; it is not a partial-update instruction.

The [all-ones case][allones] replaced the owned record with `ff` eight times,
read it back in 352, logged in with the original owned password, and received
the same eight bytes in session push 354. Its 109 agreement flag 154 was
`0001`; that is consistent with existing bit-27 handling but is not a
per-bit enforcement test. No operation was attempted by the all-ones subject.

## Enforcement and remaining criteria

The existing [privilege registry][registry] records 37 observed native uses,
its source call sites, and unknown positions 12–13, 18–19 and 41–63. These
new captures establish that single bits in every position survive 353/352;
they do **not** turn unknown positions into reserved, ignored or permission
labels. Separate native fixtures provide specific operation contrasts:

- [Metadata corpus][metadata]: comment-only `0000000c00000000`,
  rename-only `1100000000000000` and zero accounts for 207 effects.
- [Room corpus][rooms]: receive bit 9, send bit 10, create bit 11 and zero
  controls for 105/112 behaviour.
- [Account batch corpus][batch]: create/delete/update bits 14/15/17,
  subset denial and the bit-27 creation exception.
- [Account identity corpus][identity]: bit-23 target protection for kick,
  contrasted with account deletion.

Those fixtures have their own identities and scopes. They do not prove a
meaning for every unlabelled bit. GAP-031's original per-bit meaning and
reserved/ignored distinctions remain open for unknown positions. GAP-015's
all-core-scalar criterion and GAP-016's all-field default table remain open;
this packet contributes field-110 rows only. GAP-019 retains broader fields,
input lengths and aggregate limits. Nothing here chooses mxd's compatibility
or release policy.

## Verification

From the private `mothra` checkout, with adjacent protocol checkout:

```sh
sha256sum -c evidence/gap-remediation/2026-11-13/native-bitmaps-01/SHA256SUMS
python3 ../hotline-protocol-docs/scripts/verify_native_bitmaps.py \
  evidence/gap-remediation/2026-11-13/native-bitmaps-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p test_native_bitmaps.py
```

The verifier checks all 64 sent/readback values, account identity and
password controls, width outcomes, all-ones 354, cleanup, capture hashes,
14 paired host/guest TCP lifetimes and two retained unread notice tails.
Mutation tests reject wrong bits, identity, order and duplicate 354. The host
capture reports 582 packets and zero kernel drops; the guest snapshot is a
copy of the original cumulative Ethernet capture, not a new emulator.

For a fresh run, revalidate the original runtime PID, executable/oracle
hashes, service and handshake, acquire the exclusive native lease, then
generate plans with `native_bitmap_cases.py --runtime-record <runtime.json>
--output <new-plan-directory>`. Capture `preflight` first and refuse an
occupied owned name or changed baseline. Run `seed`, eight walks, `widths`,
`all-ones` and `cleanup` in order with `protocol_capture.py capture`, copying
the original guest pcap only after stopping the host observer. Retain failed
reports and distinct unread tails; a timeout does not authorize a restart.

[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/manifest.json
[runtime]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/runtime.json
[bits]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/per-bit.json
[walk]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/walk-00/report.json
[widths]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/widths/report.json
[allones]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/all-ones/report.json
[handler]: ../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c
[record]: native-wire-details.md#account-record-and-field-schema
[registry]: privilege-contracts.md#bitmap-numbering-and-known-uses
[metadata]: ../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json
[rooms]: ../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json
[batch]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json
[identity]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json
