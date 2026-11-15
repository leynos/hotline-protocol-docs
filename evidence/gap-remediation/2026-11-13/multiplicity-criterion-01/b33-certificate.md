# B33: GAP-017 original-criterion audit

Read-only audit on 2026-11-13. Canonical mothra HEAD:
`175719f50380d7024d47c42663d4c706cebb58ac`. Canonical protocol-docs
HEAD: `3c7b063334f1e1c81e7800748753d0ec80f2c85e`. The protocol worktree
had concurrent uncommitted edits to `core-field-schemas.md`,
`native-pm-preparation.md`, `native-settings-preparation.md`, and
`protocol.md`. This audits the visible text and retained evidence. Recheck
those edits at final adjudication. No status or canonical files were changed.

## Frozen record

The `GAP-017` object in
`evidence/protocol-gap-analysis/2026-11-12/initial-gap-register.json` asks:
“Beyond observed list/invitation cases, are duplicate scalars rejected,
first-wins, last-wins or accumulated, and is order meaningful?” Its exact
close condition is: “Define multiplicity and ordering by transaction/field
and test repeated scalars, interleaved repeated records and reordered
inputs.” It does not demand every permutation of every scalar field.
Current `../hotline-protocol-docs/gap-analysis.md:1144–1188` still marks it
Investigating and not closed. Its progress text predates at least the newly
visible 304/113 table.

## Clause 1: define multiplicity by transaction and field

`../hotline-protocol-docs/core-field-schemas.md:9–16` defines a scalar as one
logical canonical value and a repeated field as ordered records. Lines
36–49 and 116–143 map individual login, settings, chat, PM, and room input
fields. The output tables mark repeated 300 in 300 and 115 ACKs. The scalar
default applies to rows not marked repeated. This is canonical schema
cardinality, **not** native rejection of duplicate scalar TLVs.

`../hotline-protocol-docs/protocol.md:128–140` and
`internal-compatibility-matrix.md:126–140` identify additional repeated
contexts: 112/113 request field 103, modern 370 reply field 323, and
file-list reply field 200. `operation-contracts.md:200–219,240–249`
identifies 348 repeated outer 101, 349 repeated outer account values,
and the nested 349 field meanings. The core table is a core-operation
registry, not an exhaustive duplicate-outcome table for all dispatches.

## Clause 2: define ordering by transaction and field

`native-wire-details.md:9–35` says scalar lookup sorts an ID index, then
uses binary search with a cached match. It makes no universal first- or
last-wins promise. Indexed iteration retains original wire positions.
`presence-messaging-contracts.md:359–373` says 112/113 iterate repeated
103 targets; eligible 112 invitations follow request field order.
`operation-contracts.md:213–245` says 349 processes outer account records
sequentially in wire order; outer ID does not select the operation.
There is no claim of a global cross-socket delivery order.

## Clause 3: test repeated scalars

`evidence/gap-remediation/2026-11-12/native-framing-01/verification.json`
records four paired host/guest 304/104 icon cases:
`duplicate-icon-1-2`, `duplicate-icon-2-1`,
`duplicate-icon-1-2-3`, `duplicate-icon-3-2-1`. Their emitted icons are
2, 1, 3, and 1 respectively. The corpus has 62 cases overall.

`evidence/gap-remediation/2026-11-13/native-settings-01/raw/cases/`
contains `duplicate-refuse-auto/report.json` and
`duplicate-auto-refuse/report.json`. Both complete 33 actions. Action 15
sends duplicate 304/113, action 16 observes 301, and subsequent PM effects
show effective value 1 in both. See `native-settings-witness.md:8–29`.
Neither measured field selection licenses universal last-wins behavior.

## Clause 4: test interleaved repeated records

`native-settings-01/raw/plans/settings/duplicate-auto-refuse.json`
action 15 sends 113=`0004`, then identical 104/102, then 113=`0001`.
The paired report's action 16 and PM effects select 1.

`native-account-batch-01/batch-ordered-outer-ids/plan.json` action 7
sends request 349 with outer IDs **0, 65000, 0**. Its report action 8
returns an empty ACK. `operation-contracts.md:240–245` documents the
position-based result: create A, rename A to B, update B, leaving B.
The corpus's before/after enumerations support that result.

`native-rooms-01/create_invites.plan.json` action 31 sends 112 with five
repeated 103 targets, including a duplicate and missing/zero values.
Action 36 of its completed report includes 113 notifications. The mixed
and repeated target effects are described in
`presence-messaging-contracts.md:479–487`. These cases prove indexed
handling in their handlers; an unknown outer ID in 349 is not a new
semantic field.

## Clause 5: test reordered inputs

The framing icon pairs `[1,2]`/`[2,1]` and `[1,2,3]`/`[3,2,1]` have the
measured outputs above. The 304/113 `[0001,0004]` case and interleaved
`[0004,0001]` case both select 1. The second result rules out inferring
a universal last-wins behavior from the first.

## Answer and closure handoff

The evidence supports **no single global duplicate policy**. Repeated
indexed fields retain wire order and can accumulate as transaction-specific
records. Ordinary scalar lookup uses the sorted-ID/cached-match path;
field/case outcomes above cannot be generalized to first- or last-wins.
Duplicate scalars are not globally rejected. Interleaving and reorder
controls each have direct native witnesses.

**Defensible closure candidate for the frozen representative criterion**:
transaction-specific cardinality and ordering are documented for the
identified core and additional list/batch fields, and all three named test
categories have native fixtures. It does not prove deterministic selection
for every malformed duplicate of every field, nor fixture coverage for all
45 request kinds; neither is explicitly required by the frozen condition.
If the root reads “by transaction/field” as demanding one complete
all-dispatch occurrence table, the smallest outstanding documentation change
is a consolidated table linking the existing 200/300/323, 348/349, and
112/113 contexts to the scalar default. The named test categories need no
new native fixture. Root alone adjudicates closure and any table change.
