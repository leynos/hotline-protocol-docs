# Delayed 121 default-text preparation (A35)

This is an offline route and fixture plan, not a live result. The pinned
primary server can enter delayed transaction 121 using client-controlled
login fields alone. No agreement, account, file or server option change is
needed for this branch. The [A33 corpus](native-settings-transition-witness.md)
read back the original 242-byte agreement in a 109/101 notice and the two
existing account records; the original delayed-admin capture in
`../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/captures/restored-delayed-admin/`
shows a successful 121 after admin 107 omitted both 102 and 104.

Frozen `10011960` enters early completion only when both a nonempty 102 and
nonzero 104 are present during 107. `native_auth_cases.states()` already
uses `name=None, icon=None` for delayed-admin. The restored native capture
has 107 ACK, 109/101(242), then 121 empty ACK and 354; a 122 is possible
on this path. Frozen `10011ee0` calls the shared settings helper, sends the
empty ACK, then emits 301, marks the session online and sends 354, with an
optional later 122. This is send-call order; the observer 301 and subject
354 travel on separate TCP flows and have no asserted total receipt order.

`scripts/native_121_default_cases.py` prepares two **sequential** admin
subject sessions and one existing admin observer. Each subject's 107 omits
102 and 104, waits for 109, and remains absent from a pre-121 roster. Its
121 sets a distinct name/icon and bitmap 113=4. The first omits 215; the
second sends a zero-length 215. The observer records the emitted 301 and
current UID, a post-121 roster and an automatic-response 104 after one
uniquely labelled PM. The sender sees the empty 108 ACK; the subject gets
the original PM. A 500 reply absorbs any optional 122 without requiring a
banner configuration. After each subject closes, the observer records 302
and a subject-free roster. The account's naming privilege predicts the
requested name becoming effective; the separate account-name fallback for
other privilege profiles remains untouched.

The expected automatic-response field 101 is the exact ASCII literal
`I'm not able to respond right now. Please try later!` for both absent and
empty 215. The name/icon/UID 301, option-4 104 and 109/121/354 ordering
must be checked against complete report and paired packet streams before
calling either case verified. The prepared capture plan records these
frames; it does not itself provide per-field semantic stop gates. A live
operator must first approve the verifier/gate strategy and stop on an
unexpected login branch or first case failure, without improvising retries.

The generator takes the pinned A7 29-action/full-FILP plan, checks its
SHA-256 and runtime identity, and emits byte-identical `preflight.json` and
`postflight.json` plus one 70-action `observe.json`. Future live work needs
root's separate START, exclusive oracle lease, actual PID/executable/FD and
listener checks, independent host PCAP ready before the first socket, exact
A7 preflight passing before observe, and exact A7 postflight and session
cleanup at the first safe point. Preserve all failed reports and untrimmed
host/guest tails. The two subject sessions are sequential, and no account,
configuration, Files or restart operation is in the plan.

This packet addresses only 121 default-wire fixtures. Re-login, restart,
durability and general non-ASCII encoding remain outside its scope;
GAP-029/030 retain those original requirements.
