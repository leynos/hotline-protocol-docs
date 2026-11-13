# Parameter multiplicity and ordering in Hotline Server 1.9

This is the canonical wire-shape rule for the hashed native 1.9 server. The
[45-handler catalogue](operation-contracts.md#request-catalogue), [core field
schemas](core-field-schemas.md#types-occurrence-and-direction-conventions),
and [parser analysis](native-wire-details.md#parameter-parsing-and-scalar-access)
give field meanings and limits. The [GAP-017 certificate][certificate] records
the representative native tests. The [parent acceptance][acceptance] meets
the unchanged GAP-017 criterion with the limitations stated below.

An outer parameter is a counted sequence of ID/length/value records. Preserve
its order and duplicate IDs through decoding. **Scalar** below means one
logical canonical value, so emit at most one occurrence; it does not mean the
native server rejects duplicates. Its ID lookup sorts an index and uses binary
search with a cached match. No universal first-wins or last-wins rule follows.
**Repeated** means zero or more ordered occurrences unless the transaction
specifies a tighter count. An inner packed list is one outer value, not
repeated outer parameters.

| Direction and transaction | Field(s) | Canonical occurrence and native order |
| --- | --- | --- |
| Requests 107, 121, 304 | 102, 104, 105, 106, 113, 160, 215 where listed for that request | Scalar; [core schema](core-field-schemas.md#login-and-settings-requests). 121/304 delegate settings reads to a helper. |
| Requests 105, 108, 110, 114–116, 120 | Fields in the [catalogue](operation-contracts.md#request-catalogue) | Scalar except the separate 112/113 target rows below; no global duplicate-selection rule. |
| Requests 112 and 113 | 103 target UID | Repeated; handlers iterate original outer positions. Eligible 112 invitations follow request field order, with no global cross-socket arrival promise; [room evidence](presence-messaging-contracts.md#rooms-invitations-and-subjects). |
| Requests 112–120 | Other listed fields, including 113/114/115 | Scalar where read; see [core schema](core-field-schemas.md#chat-pm-and-room-requests). |
| Request 349 | Every outer value, regardless of outer ID | Repeated, sequential, wire-ordered account operations; each value is a nested count-prefixed TLV stream. Nested 101/102/105/106/110/111 are logical scalar record attributes, with no universal duplicate-choice rule; [batch contract](operation-contracts.md#administrative-account-list-and-batch-mutation). |
| Other request handlers | Directly read fields in the [catalogue](operation-contracts.md#request-catalogue) | Canonical scalar for each listed value unless a specific operation defines another shape. Unlisted, delegated or indirect reads are not disproved by the direct-handler inventory. |
| Replies to 200, 300, 115 | 200 file record; 300 packed user record | Repeated outer records in list order; [file list](native-wire-details.md#structured-file-paths-and-file-list-entries) and [roster](core-field-schemas.md#login-and-presence-outputs). |
| Reply to 348 | 101 account record | Repeated outer records; each is a nested count-prefixed TLV stream with logical scalar attributes; [account contract](operation-contracts.md#administrative-account-list-and-batch-mutation). |
| Reply to 370 | 320 legacy or 323 modern category record | Repeated outer records, selected at saved version 15; [news contract](news-contracts.md#category-list-variants). |
| Reply to 371 | 321 | One outer field containing a packed article list, including nested article/flavour records; [article grammar](news-contracts.md#article-list-field-321). |

The [frozen inventory][manifest] hashes a decompilation for each of the 45
catalogued request handlers. Direct request-parameter indexed calls appear in
112 (`10017f30`), 113 (`100188e0`) and 349 (`10015500`). Other handlers use
named scalar helpers, delegate reads, or have no direct field reads identified.
This is a **direct-call survey**: it cannot exclude helper-side, copied,
aliased or indirect iteration. Consequently, duplicate outcomes for fields
outside the measured cases remain unreviewed, not declared unique or rejected.

Native repeated-scalar controls include 304/104 icon pairs `[1,2]`/`[2,1]`
and `[1,2,3]`/`[3,2,1]`, emitting 2/1 and 3/1 respectively. Two 304/113
sequences, including an interleaved 104/102 reversal, both selected 1. The
[framing corpus][framing] and [settings witness](native-settings-witness.md)
retain their paired actions and outcomes. A 349 fixture interleaves outer IDs
`0,65000,0` and performs create, rename, then update in position order; a
112 fixture includes duplicate, missing and zero target IDs. These measure
specific operations. They do not establish arbitrary duplicate semantics or
every malformed-input permutation.

[certificate]: ../mothra/evidence/gap-remediation/2026-11-13/multiplicity-criterion-01/b33-certificate.md
[manifest]: ../mothra/evidence/gap-remediation/2026-11-13/multiplicity-criterion-01/manifest.json
[framing]: ../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/verification.json

[acceptance]: ../mothra/evidence/gap-remediation/2026-11-13/multiplicity-acceptance-01/decision.json
