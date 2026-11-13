# mxd direct reply header correction candidate

Status: private implementation blocked at full PostgreSQL gate at mxd base
`481294915b48f4db06943c8af86cf31b7e47597a`. This note supports
[GAP-085](gap-analysis.md#gap-085); it does not change the baseline native
1.9 contract or close that gap.

The [native baseline](protocol.md#4-reply-semantics) requires a direct reply
to carry marker 1, type 0 and the request ID, including login success and
failure, ordinary nonlogin ACKs and error ACKs. Numbered server
notifications use marker 0 and retain their notification type.

At the pinned mxd base, both `header_util::reply_header` and
`HotlineTransaction::reply_from_params` copied the request type into the
reply. The normal login route therefore transmitted type 107, not merely
used 107 as an internal dispatch label. The shared helper also produced
nonlogin and router-error replies, including the legacy writer path.

The candidate makes both direct-reply constructors emit type 0 while
preserving ID and status. The router still dispatches on incoming type 107.
Its compatibility layer passes that original request kind to the extras
predicate, so a successful login can retain the existing conditional
161/162 behaviour after the reply's wire type becomes 0. A failed login or
nonlogin reply cannot receive those extras through the predicate. Generic
frame serialization still preserves an explicitly supplied header, and
presence notifications still emit types 301/302 with marker 0.

The first full PostgreSQL gate exposed an additional header-aware validator
assumption: repeated roster field 300 was accepted only when the reply header
echoed request type 300. A native type-0 roster reply therefore failed mxd's
own parser and legacy writer. The approved correction permits repeated field
300 for marker-1 direct replies regardless of wire type. Tested marker-0
Login requests and 301 notifications, marker 2, and unrelated duplicate
fields remain rejected. The pre-existing marker-0 request type-300 opaque
payload bypass is unchanged and outside this correction. Four new
parser/writer/Tokio tests failed before it;
all six new positive and negative controls pass after it. The original
multiuser presence BDD scenario now passes in a focused SQLite run.

Four new router-boundary tests failed at the old type 107/200 and passed
after the candidate. Focused wireframe, writer and BDD tests pass. The
[private evidence package][evidence] pins two failed full-gate outcomes and
source hashes. The first failure was the repeated-300 validator dependency,
which the candidate now corrects. The second gate ran 557 PostgreSQL cases:
556 passed, and one failed during embedded database startup (`pg_ctl` could
not start). Later feature profiles and doctests did not run. There is no mxd
source commit or conformance claim yet.

This correction does not validate the existing peer classifier, choose
whether any profile needs omitted extras, set configured server name 162,
or resolve field 161's meaning. The old passing classifier tests remain
implementation-policy tests. GAP-085 still needs source/test reconciliation
at the final mxd revision; GAP-001 and GAP-086 need their independent
scope and acceptance decisions. No new native peer test was run here.

[evidence]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-direct-ack-01/manifest.json
