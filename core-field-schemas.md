# Core transaction field schemas

This registry covers session establishment, settings, roster, chat, PM and room
operations for the [native 1.9 baseline](protocol.md). The full dispatch
inventory remains in [operation contracts](operation-contracts.md). It satisfies
GAP-002's core schema inventory; open questions remain explicitly linked rather
than being replaced by guessed universal types or peer requirements.

## Types, occurrence and direction conventions

An occurrence of a TLV has a BE16 ID, BE16 byte length and unpadded value. A
**scalar** row means one logical input/output value: a canonical sender emits
at most one occurrence. This is not a native duplicate-rejection rule. The
native scalar lookup's duplicate choice is not defined as first/last-wins;
see GAP-017 and [parser details](native-wire-details.md#parameter-parsing-and-scalar-access).
A **repeated** row preserves order and allows zero or more records unless its
operation says otherwise.

**N** is the native generic unsigned numeric accessor: effective reads of
1/2/4 bytes, zero for absent/empty/three-byte values, and first four bytes of an
overlong value. Native numeric emission uses BE16 through 65,535, otherwise
BE32. For reliable canonical output use those emitted widths. This tolerance
does not make every numeric field unbounded: assignment can narrow a UID/icon
to 16 bits. Remaining boundary/range outcomes are GAP-015/019.

**B** is an uninterpreted byte string in the outer TLV; there is no embedded
length or terminator unless explicitly shown. **A8** is the exact eight-byte
MSB-first privilege bitmap. **U** is the packed roster record
`BE16 UID | BE16 icon | BE16 status | BE16 name_length | name bytes`.
It has `8 + name_length` value bytes. **ACK** is a server-to-client direct reply,
with is-reply set, type zero and the request ID. Native empty ACK payload is
`00 00`. Notifications are server-to-client messages with their own type/ID.

## Login and settings requests

All request rows are client-to-server. Fields are scalar unless marked repeated.
The count stream can omit fields structurally; the table states the resulting
helper/default behaviour, not a promise of successful authentication.

| Operation | Field | Type / content cap | Absence/default and condition |
| ---: | ---: | --- | --- |
| 107 | 105 | B; complemented login; up to 32 copied content bytes | Absent/empty selects literal `guest`; otherwise complement, byte-table normalization and CR replacement precede lookup (GAP-023). |
| 107 | 106 | B; complemented password; up to 32 copied bytes | Absent/empty means zero-length comparison value; success depends on the selected account's password. |
| 107 | 160 | N, saved as 32-bit reported version | Absent/default zero; numeric value does not establish client identity (GAP-024/080). |
| 107 | 102 | B; up to 32 copied content bytes in login input | Nonempty name together with nonzero narrowed icon selects early completion; otherwise completion is through 121. |
| 107 | 104 | N, narrowed to 16-bit icon | Zero after narrowing disables early completion, regardless of field presence. |
| 121 / 304 | 102 | B; at most 31 requested-name bytes | Absent/empty becomes `***`; account naming privilege determines effective display name. |
| 121 / 304 | 104 | N, narrowed to 16-bit icon | Absent/default zero replaces the previous icon. |
| 121 / 304 | 113 | N; low bits 0/1/2 used | Absent/default zero clears PM refusal, chat refusal and automatic response. |
| 121 / 304 | 215 | B; at most 127 content bytes | Used only with auto response enabled; absent/empty chooses native default text (GAP-030). |

121 ACKs before applying settings; 304 has no normal success ACK. Updates are
session assignments, not generic sparse or durable account edits. Exact
agreement/configuration/runtime fixtures remain GAP-025/027/029.

## Login and presence outputs

| Reply or notification | Fields and occurrence | Conditions/defaults |
| --- | --- | --- |
| 107 ACK | Scalar N 160 = 190, scalar N 161, scalar B 162 | Native success adds these without a client-kind gate; empty byte values can be omitted by the writer. 161 is an unnamed word initialized to zero; 162 is the current server-name string. See [content sources](presence-messaging-contracts.md#fields-160-161-and-162); later-value/lifetime fixtures remain GAP-026. |
| 109 notification | Scalar B 101 **or** scalar N 154 = 1, or empty list | Account bit 27 selects 154. Otherwise configured agreement bytes are used; absent buffer can yield empty list. |
| 122 notification | Scalar four-byte 152, conditional scalar B 153 | After 121, reported version at least 151 and configured type/buffer conditions apply (GAP-028). |
| 354 notification | Scalar A8 110 | Sent on login completion; changed live account privileges also use this form. |
| 300 ACK | Repeated U 300 | Request has no directly required fields. Builder includes active sessions with nonempty effective names; no subject 115 is added. |
| 301 notification | Scalar N 103/104/112, scalar B 102 | Session appearance/status update. Masks and online/ready recipients are in the presence supplement. |
| 302 notification | Scalar N 103 | Departing UID after room-leave calls; delivered/concurrent order remains GAP-036. |
| 303 ACK | Scalar B 102 and B 101 | Request reads scalar N 103; requires privilege 24 and an eligible existing target. Generated diagnostic text is not a fixed client-profile record (GAP-037). |

## Chat, PM and room requests

| Request | Field schemas / occurrence | Absence, conditions and normal result |
| ---: | --- | --- |
| 105 | Scalar B 101, scalar N 114, scalar N 109 | Text copied to 8,192-byte cap before formatting; room zero/absent selects main chat. Option exactly 1 selects action prefix; other values ordinary. Push 106; no normal ACK (GAP-042). |
| 108 | Scalar N 103/113, scalar B 101, conditional scalar B 214 | Target required for delivery, PM privilege 40. Missing option reads zero, not an automatic normal-option 1. Main text cap 4,096; quoted bound remains GAP-019/043. ACK precedes routing. |
| 112 | Repeated N 103 | Each target is read by index and narrowed to UID; zero targets still permit creation. Privilege 11; ACK with room/creator fields after invitation calls. |
| 113 | Scalar N 114, repeated N 103 | Existing room required; targets exclude self/existing members. No normal ACK; no whole-batch atomicity promise (GAP-039). |
| 114 | Scalar N 114 | Reject text routed as room chat 106; no normal ACK. |
| 115 | Scalar N 114 | Existing room required. Adds member only if absent, then ACKs roster/optional subject. |
| 116 | Scalar N 114 | Removes member when present; 118 to remaining members or room deletion. No normal ACK. |
| 120 | Scalar N 114, scalar B 115 up to 255 content bytes | Missing/empty 115 clears subject. Existing room required; 119 notification, no normal ACK. |

The observed join, invite and subject handlers do not implement a universal
room-owner/invitation permission model. Per-handler checks and missing-object
outcomes are in [presence contracts](presence-messaging-contracts.md#rooms-invitations-and-subjects).
Unresolved lifecycle/concurrency cases remain GAP-038–GAP-041.

## Room and message outputs

| Reply or notification | Field schemas / occurrence | Notes |
| --- | --- | --- |
| 106 notification | Scalar B 101; conditional scalar N 114 | Formatted chat or room-system text. No universal separate sender UID. |
| 104 notification | Variant-specific scalar B 101; conditional N 103/113 and B 102/214; denial path can use N 109 | Routed users, feedback, console, bans and denials have distinct field presence (GAP-044). |
| 112 ACK | Scalar N 114/103/104/112, scalar B 102 | Creator identity, not all invited users already joined. |
| 113 notification | Scalar N 114/103, scalar B 102 | Room and inviter identity. |
| 115 ACK | Repeated U 300, optional scalar B 115 | Post-add roster; subject absent when none is stored. |
| 117 notification | Scalar N 114/103/104/112, scalar B 102 | Newly joining identity to existing ready members before insertion. |
| 118 notification | Scalar N 114/103 | Room and departed UID. |
| 119 notification | Scalar N 114, conditional scalar B 115 | Empty subject is omitted by the zero-length writer. |
| 111 notification | Scalar B 101 | Conditional shutdown dialog; not required for ordinary kicks/errors. |
| 355 notification | Scalar N 103, scalar B 102/101 | Client broadcast path; native console message uses data-only 104 instead. |

An operation's success ACK is not proof of downstream receipt, durability or
idempotency. Error status/fields and disconnect outcomes still need GAP-003/021
native fixtures. This registry provides the core field contract without closing
those separate acceptance criteria.
