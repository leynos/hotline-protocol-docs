# Same-session 304 transition preparation (A32)

This is an offline preparation, not a native result. GAP-029/030 remain open.
The A31 audit identifies missing persistence and 121 evidence. This packet
covers one same-session 304 sequence. It makes no server option, account,
file, agreement or restart change.

The generator `scripts/native_settings_transition_cases.py` takes an explicit
runtime record and the exact A7 29-action/full-FILP baseline plan, SHA-256
`5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e`.
It emits byte-identical preflight and postflight copies and one observation
plan. It rejects a mismatched runtime PID, emulator hash, oracle hash or
guest-PCAP path. Eight labelled PMs target the UID captured from this
connection's subject 301. The observer obtains its UID through 300.

The eight ordered stages are:

1. Explicit: name `A32-Explicit`, icon 7, 113=4, explicit 215
   `a32-explicit`; expect exact explicit option-4 feedback and original PM.
2. Omit 102/104/215 with 113=4; expect name `***`, icon 0 and exact default
   option-4 feedback.
3. Empty 102/104/215 with 113=4; expect the same state and default. A
   difference falsifies the absent/empty equivalence.
4. Unknown-only 113=8, name `A32-Unknown`, icon 9; expect original PM and
   no auto feedback.
5. Mixed-unknown 113=12, name `A32-Mixed`, icon 10; expect default auto
   feedback and original PM.
6. Disable with 113 absent, name `A32-Off-A`, icon 11; expect original PM
   without feedback.
7. Disable with 113=0, name `A32-Off-Z`, icon 12; expect the same.
8. Re-enable with 113=4, 215 absent, name `A32-Reenable`, icon 13; expect
   default feedback and original PM.

Each stage reads 301 on both sockets, requires the labelled 108 empty ACK,
reads expected 104 messages, then uses two 500 ACK/quiet barriers. The
`--run` mode in `verify_native_settings_transition.py` checks the roster and
subject identity before any 304, then both decoded 301 states before each
stage's PM. It checks PM and quiet-barrier results at each stage end and
stops after the first bad observation. It records the failed
report and closes owned sockets. It sends no further settings or PM request
after failure. On success the plan restores the subject's session
name/icon/options, observes both 301s, uses a final barrier and closes both
sockets. Session teardown is the cleanup when a stage fails before restore.

Future operator, only after a separate live START: revalidate the actual
primary emulator PID, executable hash, managed unit, display, listener,
guest-PCAP path, original account/Files state and exclusive server lease.
Use privileged `readlink` for proc FD proof. Acquire the canonical
`mothra/state/delegation/oracle.lock` for the authorised capture. Start and
confirm an independent host tcpdump before the first connection. Preserve
untrimmed host/guest packet tails. Run the pinned preflight with
`protocol_capture.py`, then one `--run` observation with the pinned binary
path and fresh output directory, then the exact pinned postflight. Do not
retry a failed observation. A failed stage has no automatic postfailure
semantic requests; root must approve any subsequent baseline probe. Use
read-only `--verify` on the retained capture and reconcile host/guest
streams separately.

No 121, re-login, restart, durable persistence or non-ASCII encoding
conclusion follows. Test the default literal as exact bytes
`I'm not able to respond right now. Please try later!`, not as a general
codec rule.
