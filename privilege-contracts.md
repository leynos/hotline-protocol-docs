# Native privilege registry and composition

This supplement refines GAP-031/032/072/073/078 for the hashed 1.9-family
oracle. The [call-site review][calls] reconciles **40 direct calls in 25
functions** to all three privilege accessors against the retained native
decompilations. Inline bitmap tests, including account operations, supply
additional evidence. This is static enforcement evidence, not a native
permission-fixture corpus.

## Bitmap numbering and known uses

Field 110 is eight bytes. Bit `b` uses byte `b >> 3` and mask
`0x80 >> (b & 7)`. The three accessors read exactly that bit from the session;
they do not implement inherited rights or a universal administrator override.
Unknown entries below are **unknown**, not declared reserved, rejected or safe
to clear. The table covers the full 0–63 numbering space. The
[per-bit evidence index](privilege-bits.md) gives all 64 bitmap values and
native readback IDs.

| Bit   | Observed native use                                        | Evidence / condition                                  |
| ----: | ---------------------------------------------------------- | ----------------------------------------------------- |
| 0     | Delete ordinary file                                       | 204, `100140e0`                                       |
| 1     | Upload ordinary file                                       | 203, `100130f0`                                       |
| 2     | Download ordinary file                                     | 202, `100121a0`                                       |
| 3     | Rename ordinary file                                       | 207, `100170c0`                                       |
| 4     | Move ordinary file                                         | 208, `100177d0`                                       |
| 5     | Create folder                                              | 205, `100143f0`                                       |
| 6     | Delete folder                                              | 204, `100140e0`                                       |
| 7     | Rename folder                                              | 207, `100170c0`                                       |
| 8     | Move folder                                                | 208, `100177d0`                                       |
| 9     | Receive chat                                               | 105, `1000fc20`; room-message helper `10004790`       |
| 10    | Send chat                                                  | 105, `1000fc20`                                       |
| 11    | Create private chat                                        | 112, `10017f30`                                       |
| 12–13 | Unknown in this review                                     | No normative open/close-chat interpretation assigned  |
| 14    | Create account                                             | Inline byte-1 mask `0x02` in 350 and batch 349        |
| 15    | Delete account                                             | Inline byte-1 mask `0x01` in 351 and batch 349        |
| 16    | Read/enumerate accounts                                    | Inline byte-2 high-bit test in 352 and 348            |
| 17    | Modify account                                             | Inline byte-2 mask `0x40` in 353 and batch 349        |
| 18–19 | Unknown in this review                                     | Bit 19 is not this build's PM-send gate               |
| 20    | Read old news / article body; old-board update eligibility | 101/103 and 400                                       |
| 21    | Post old news / article                                    | 103 and 410                                           |
| 22    | Disconnect user; also contributes privileged roster status | 110 and status builders                               |
| 23    | Protection from request-110 disconnect                     | Tested on target, not requester                       |
| 24    | Read client diagnostic information                         | 303                                                   |
| 25    | Bypass upload destination-name restriction                 | 203/213; does not replace their upload gate           |
| 26    | Use requested session display name                         | Settings helper; otherwise account name selected      |
| 27    | Bypass agreement content                                   | 109 selects flag 154 = 1                              |
| 28    | Set ordinary-file comment                                  | 207                                                   |
| 29    | Set folder comment                                         | 207                                                   |
| 30    | Bypass inspected drop-box restrictions                     | 200/202/210/207; operation-specific predicates        |
| 31    | Create alias                                               | 209                                                   |
| 32    | Broadcast                                                  | 355                                                   |
| 33    | Delete article                                             | 411                                                   |
| 34    | Create news category                                       | 382                                                   |
| 35    | Delete ordinary-file news item                             | 380, native kind 2                                    |
| 36    | Create news folder/bundle                                  | 381                                                   |
| 37    | Delete news directory/bundle                               | 380, native kind 3                                    |
| 38    | Upload folder                                              | 213; not a combined bit-1/38 check                    |
| 39    | Download folder                                            | 210; not a combined bit-2/39 check                    |
| 40    | Send private message                                       | 108                                                   |
| 41–63 | Unknown in this review                                     | No normative names or reserved-bit rejection inferred |

For example, bit 0 alone serializes as `80 00 00 00 00 00 00 00`, while bit 40
alone is `00 00 00 00 00 80 00 00`. These are calculated bitmap examples, not
captured native frames. A status bitmap in field 112 is a different schema;
privilege names do not define its bit positions.

## Operation-specific composition

The [handler catalogue](operation-contracts.md#request-catalogue) links each
operation to its captured entry. A positive base permission does not erase
other target, session, filesystem or configuration checks.

| Operation group    | Composition established in inspected handlers                                                                                                                                       |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 202 / 210 download | Require bit 2 / 39 respectively. Bit 30 controls an additional drop-box restriction. A folder download does not separately call the bit-2 accessor.                                 |
| 203 / 213 upload   | Require bit 1 / 38 respectively. With bit 25 clear, the destination component must satisfy the handler's upload/drop-box name predicate. Bit 25 alone does not permit uploading.    |
| 204 / 208          | Select the file/folder delete or move gate from target classification, rather than requiring both bits. Resolver and filesystem checks still apply.                                 |
| 207                | Comment and rename have independent file/folder gates. A requested comment change occurs before later rename validation. Bit 30 controls an additional drop-box rename restriction. |
| 110                | Requester must have bit 22; a target with bit 23 is rejected. No blanket override is provided by these accessor calls.                                                              |
| 380                | Kind-specific bits 35/37 and root checks; alias-kind uncertainty remains in the [news structure table](news-contracts.md#structure-operation-effects-and-conflicts).                |
| 113/115/120        | The inspected invite/join/subject handlers do not enforce a guessed bit-12/13 gate or universal room-owner requirement. Other state/routing checks remain documented separately.    |

Bits 25 and 30 select byte-name predicates, not portable filesystem ACLs. For
upload, the handler tests the selected destination component for the `upload`
and `drop box` strings. This does not prove that an ancestor's name, a
symlink-equivalent target or an arbitrary translated name grants permission.
Full byte/case/alias boundary fixtures remain necessary.

## Account creation, update and batch rules

[Create handler 350][create] requires bit 14. Before creation, it checks that
requested field-110 bits are a subset of the requester's session bitmap,
**except bit 27**. In the first big-endian 32-bit word, it masks the requested
value with `0xffffffef` for that comparison; the second word is compared
without that exemption. This is a grant restriction in the create path, not a
general property supplied by the accessors.

[Update handler 353][update] requires bit 17 and writes the replacement account
record. No equivalent subset comparison appears in that handler before the
write. Its missing/empty fields and one-NUL password sentinel follow the
[account record rules](native-wire-details.md#credential-bytes-lookup-and-account-updates).
Do not silently import the create restriction into an observation about update.

Batch 349 admits a requester with any of bits 14, 15 or 17, then checks the
specific operation for each item. Deletion requires 15; rename/update requires
17; creation requires 14 and repeats the create bitmap-subset check with the
bit-27 exemption. A later failure can follow earlier mutations. This is neither
all-or-nothing nor permission to perform every batch action once admitted. The
[captured batch matrix](operation-contracts.md#captured-batch-account-framing-and-partial-effects)
confirms each one-right actor, the bit-27 create exemption, immediate
permission stops and a different rename-failure path that overwrites the
destination and continues before its final error.

[Read 352][read] and [enumeration 348][enumerate] require bit 16. The same gate
does not imply identical reply shape: 348 returns nested repeated account
values, while 352 returns one account's top-level fields.

[Delete helper `10007340`][delete] resolves the account file and invokes the
shared native Trash mover. The inspected helper does not compare the requested
login against the configured head-administrator name. The handler ACKs before
`10005f90` scans matching connected account logins, sends a data-only 104
notice and requests transport disconnection. This ordering is distinct from
live privilege updates, which use 354 and roster propagation. The
[live-account corpus](native-wire-details.md#captured-live-account-changes-and-server-restart)
captures two matching subjects for each path, including guest-first FIN,
retained roster entries and later unread 302 messages after deletion. Normal
server-restart persistence is verified separately. The
[identity contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts)
show that bit 23 rejects kicking while permitting account deletion, including
self-deletion by an account with bit 15. This does not test deletion of the
configured head administrator. Orderly close is not atomic roster removal.

## Remaining acceptance evidence

GAP-032's decision-table deliverable is satisfied for the three accessor
domains: all read the session bitmap directly, and the composition table
separates base, additional, target and grant checks. There is no helper-level
inheritance or administrator override to document as an extra permission
source. GAP-031 retains the semantic meaning of 27 unknown positions; the
[per-bit index](privilege-bits.md) separately records all-64 serialization and
links representative enforcement fixtures. Alias and byte-name predicates,
configuration changes and complete runtime branch coverage remain
GAP-047/054/084. Account grant/update, batch partial effects and live-delete
sequencing require before/after native fixtures under GAP-072/073/078/084. No
mxd release scope or deliberate deviation is chosen by these native
observations.

[calls]: evidence/gap-remediation/2026-11-12/batch-15/privilege-callsite-review.json
[create]: evidence/hotline-server-1.9/queries/D-100146f0.c
[update]: evidence/hotline-server-1.9/queries/D-10014df0.c
[read]: evidence/hotline-server-1.9/queries/D-10014bc0.c
[enumerate]: evidence/hotline-server-1.9/queries/D-10015160.c
[delete]: evidence/gap-remediation/2026-11-12/batch-15/queries/B15-D-10007340.c
