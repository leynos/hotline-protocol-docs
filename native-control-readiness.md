# Readiness for isolated control-operation fixtures

This profile permits a separately authorized control-operation fixture on an
owned disposable native 1.9 server. It supports questions such as ban replies
or session settings. Its reports must identify the profile as `control-only`
and the full-file baseline as `not_exercised`.

The normal full A7 gate remains the gate for transfer, buffering, throughput,
large-message and transfer-failure assertions. C32 and the primary server have
completed its full 1,049,073-byte download. The separate C35/C45/C50 labs
stalled at 98,304 bytes; their failures remain evidence, not passed baselines.
The [comparison](native-transfer-stall.md) records the first two failures. The
[C50 focus-event witness](native-ui-focus-witness.md) additionally records a
verified focus event without resumed output. No historical cause or native size
limit follows.

## Why a separate profile is appropriate

A ban notice and subsequent Login 107 rejection are control-channel outcomes.
The full-file reader's failure does not supply those outcomes. Requiring that
unrelated read to pass before observing them introduces a research dependency
that the protocol gap criteria do not require. This profile removes that
dependency while preserving all original transfer requirements and failures. It
must not be used as evidence that the disposable server passed full A7.

Only an explicit parent task packet may select this profile. An executor cannot
replace a failed required A7 with it during a run. The packet must name the
exact control question, allowed mutations, gates, capture scope and cleanup.

## Required gates

| Gate              | Required evidence                                                                                                                                                                                      |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Oracle identity   | Pinned server DATA `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`, resource fork, ROM, emulator and source-image hashes; actual PID/start time, owned image and packet-capture FDs |
| Isolation         | Owned namespace, loopback-only interfaces, empty routes, explicit lab endpoints; independent evidence that the fixed primary bridge was unused                                                         |
| Capture readiness | Host/namespace recorders ready before contact; complete guest capture, actual recorder PIDs and zero-drop/terminal receipts                                                                            |
| Authentication    | Complete TRTP and successful fixture-admin login; expected agreement bytes and privilege bitmap; no foreign active session                                                                             |
| State             | Current roster, original two accounts and their expected attributes, 41 Files entries, fixture file metadata and idle operational state                                                                |
| Transport         | Correlated control replies, a liveness barrier, and complete host/guest control-stream agreement; no timeout or unexplained tail                                                                       |
| Mutation safety   | Guard the owned account name before creation. Recheck stored zero privileges and the current target name/UID before sending a destructive request.                                                     |

The existing short metadata helper may provide the state checks. Its 18 actions
are a control-readiness plan, **not** the 29-action A7/full-FILP plan. Retain
its exact source, derived plan and semantic verification. No report may infer
the fixture file's transferred content from metadata alone.

## Ban fixture boundary

An authorized ban fixture may create one uniquely guarded, zero-privilege
account and use its successful login as the target. The requester must be the
existing authenticated administrator. Resolve both current UIDs from that
connection's roster/announcements and verify they differ before request 110.
Never use an original account as the target.

After the one specified ban request, record the target notice/close, requester
ACK and departure, then a fresh TRTP **and Login 107** probe. A handshake alone
does not exercise the ban check. Validate the exact error and field-100 text
against the source-derived prediction; preserve a differing outcome as failure.
One packet's observed stream order must not become a universal cross-socket
arrival rule.

Existing admin-session queries may verify the expected original accounts, the
added fixture record and unchanged Files metadata after the ban. Fresh logins
may be intentionally blocked, so a new full A7 is not a postcondition of this
profile. No ban removal, primary-server mutation or restart is implied.

Retire the owned lab and independently prove its actual emulator PID and
listeners are gone. Only then hash/read its stopped image and export any
persisted ban file with source provenance. File presence is distinct from
successful reload after restart. Preserve raw bytes when the format is unknown.

## Acceptance and escalation

Accept only the particular control outcomes supported by the captures and
oracle trace. Keep transfer health, whole-server conformance, persistence after
restart and untested options explicitly separate. The protocol gap criteria
remain unchanged.

An identity, isolation, control-readiness, target, capture or cleanup mismatch
stops the experiment. No retry, substitute account, extra option or weaker
control gate is allowed without a new bounded parent packet. ROMs, disk images
and live-memory snapshots remain outside Git.
