# mxd validation findings and deferred work

Status: **on hold at the user's instruction, 13 November 2026**. The primary
task is documenting native Hotline Server 1.9. Further mxd validation, fixes
and client trials are deferred. This record preserves findings already made; it
is not a release sign-off or a claim of full native compatibility.

## Recorded checkout and corrections

Canonical mxd remains at `cb907885cc2a61df2d708f38a3cf42da85c2a016`. The trial
binary was built offline from that revision and has SHA-256:

```text
3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375
```

Three corrections were accepted before this hold:

| Area                                     | Recorded result and evidence                                                                                                                                                                                                           |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Physical frames and logical transactions | Separate frame and reassembly limits, with overflow and boundary controls. See [limit contracts](mxd-limit-contracts.md) and the [accepted correction](../mothra/evidence/gap-remediation/2026-11-13/mxd-correction-01/manifest.json). |
| Direct replies                           | Type 0 with reply marker 1 and copied request ID; repeated roster records remain accepted. Notifications retain their own type and marker. See [direct replies](mxd-direct-ack-correction.md).                                         |
| Successful-login extras                  | Two opaque zero bytes in 161; configured nonempty ASCII 162, at most 31 bytes. Inferred client-family gates were removed. See [login extras](mxd-login-extras-correction.md).                                                          |

The last correction's controlled full gates passed seven nextest profiles and
both doctest groups. PostgreSQL had 565 passing tests, SQLite 569, and
wireframe-only 551. The verification profile retained one skip; mxd doctests
retained four ignores. [Frozen logs and source snapshots][correction] record
the exact commands, environment and results. Kani was **not run**. These
results establish the tested implementation scope, not historical-client
startup or protocol-wide parity.

## Two actual Classic-client trials

The identified client archive is labelled 1.9.2, while its embedded version
resource says 1.9.1.0. Its fork hashes and [isolated native session][native]
identify the tested candidate; vendor authenticity and a universal version
profile are not established. Both mxd trials used a separate loopback-only
namespace, an owned SQLite fixture, and one manually selected connection.

| Trial                                        | Wire and UI result                                                                                                                                                                                                  | Interpretation                                                                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| 48-character ASCII fixture password          | Handshake succeeded. Login 107 carried only the complemented first 31 password bytes. mxd returned type 0/status 1 with no payload; the client reported Connection Closed.                                          | The full password was not transmitted. This trial did not reach login extras or the roster. See [failed trial](mxd-classic-login.md). |
| Separate 24-character ASCII fixture password | All 24 password bytes were transmitted. Login 107 succeeded with 161=`0000` and 162=`mxd`. UI displayed Connected to: mxd, then remained at Loading Agreement with zero users. No 121, 300 or 212 request followed. | Successful authentication and a partial startup witness; not a completed client session. See [redacted evidence][short].              |

The second observation lasted **93 seconds**, exceeding its authorized
30-second settle window. The overrun is retained as a process deviation; it
cannot support a claim of a compliant timed trial. Future timed observations
need an independent cutoff. Both clients were quit, both trial daemons were
stopped, and their recorded PIDs and port-15650 listeners were absent.

Credential-bearing raw PCAPs and seed files remain in ignored private state.
The public witnesses contain redacted decoded metadata, screenshots and raw
file hashes. They are not complete portable packet proofs. Private replay
checked the password-prefix/full-password comparisons and host/guest stream
parity without publishing the credential bytes. The 31-byte observation does
not distinguish a UI limit from an encoder limit, or establish a universal
wire-password limit.

## Startup hand-off missing from the current implementation

At the recorded mxd revision:

- `src/login.rs:53–56` grants successful users `NO_AGREEMENT`.
- `src/commands/handlers.rs:101–115` sends the login ACK and updates presence
  for other peers. It sends no agreement notification 109 to the new client.
- `src/commands/parsing.rs:48–76` has no implemented 121 command branch;
  the registered route falls through to the unknown-command result.
- `src/commands/handlers.rs:119–137` builds a roster on explicit request 300.
  The Classic trial sent no 300, so it did not test that writer.

Native 1.9 still sends 109 with field 154=`0001` for the agreement-bypass path.
Its
[login-state contract](presence-messaging-contracts.md#captured-configured-login-states-and-visibility)
distinguishes that notification from becoming online. The source trace is
consistent with the observed Classic wait; a corrective replay has not been
performed. The [frozen source review][review] records the exact anchors.

Current mxd user/developer guides overstate agreement completion. Private
corrections to those guides and one source comment were interrupted and
preserved when this hold was requested; they have not changed canonical mxd.
The roadmap already lists agreement handling as pending. No new agreement
implementation or release scope has been approved by this record.

## Handoff locations

Start with this document when resuming. The
[original assertion review]( mxd-reconciliation.md) maps the earlier 55 focused
tests; later correction records above supersede its stale classifier, reply and
login-extra findings.

| Location relative to mothra                    | State at the hold                                                                                                                                                                                                                          |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `../mxd`                                       | Canonical accepted source at `cb907885`; no newer mxd changes imported.                                                                                                                                                                    |
| `state/delegation/workspaces/batch-02-mxd/mxd` | Same source base, with interrupted uncommitted changes to `docs/users-guide.md`, `docs/developers-guide.md` and the doc comment in `src/commands/support.rs`. Preserve and review these changes; they do not implement agreement handling. |
| `state/native-sessions/mxd-peer-c14`           | First build, failed/corrected seed, supervision anomaly, accepted C19 daemon and terminal receipts. Private credential/config/SQLite inputs remain here.                                                                                   |
| `state/native-sessions/mxd-peer-a22`           | First failed Classic trial and private raw captures.                                                                                                                                                                                       |
| `state/native-sessions/mxd-peer-short-01`      | Separate short-password fixture, C21 readiness and terminal receipts.                                                                                                                                                                      |
| `state/native-sessions/mxd-peer-a24`           | Successful authentication followed by stalled startup, raw captures and recorded timing deviation.                                                                                                                                         |
| `state/delegation/workspaces/batch-02-native`  | A25 partial-login publication work: private Mothra commit `5168b93`, uncommitted protocol notes. Its validators were not imported after the hold.                                                                                          |

These ignored local paths are recovery pointers, not portable evidence links.
The linked committed redacted witnesses and frozen source/test bundles are the
portable handoff. Raw packet replay additionally requires the private
credential-bearing inputs. No live mxd trial daemon remains running.

## Repeatability and deferred validation

The [fixture workflow](mxd-peer-capture-workflow.md) retains the offline build,
owned config/database setup and namespace supervision. The initial seed failed
because the subcommand loader searched `HOME/.mxd.toml` separately from
top-level `MXD_CONFIG_PATH`. The corrected owned file supplied it. A
user-service sudo launch also put the daemon outside its control group; the
accepted direct system service used UID/GID 1000 and `NetworkNamespacePath`,
with actual PID/group checks and a tested timeout.

Resume mxd work only when requested, starting with these recorded items:

1. Reconcile guide claims and design/test the 109/121 startup sequence,
   including notification IDs, recipient selection and ordering.
2. Complete one identified Classic startup before claiming roster, banner or
   general interoperability; keep authentication-only results separate.
3. Complete the requirement-to-test map and remaining stale-assertion review
   under GAP-085. Passing focused tests are not proof of all operation paths.
4. Resolve native byte-encoding versus mxd's ASCII server-name policy,
   remaining omission/fallback choices, and other explicit compatibility gaps.
5. Obtain the separate release subset, sign-off owner and proof obligations
   for GAP-001/086. Do not infer them from the native 1.9 documentation target.

[correction]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-login-extras-01/manifest.json
[native]: mac-peer-isolated-session.md
[short]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-classic-short-login-01/redacted-witness.json
[review]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-validation-hold-01/source-reconciliation.as-reviewed.txt
