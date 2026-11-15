# C4 H1 falsification result: mechanism witnessed

Date: 2026-11-13. Private workspace: `batch-02-mxd`. Pinned mxd HEAD:
`2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131`. No native/oracle lease was acquired.

## Prior condition

Resolved `futures-util` 0.3.34 `Select::poll` polls its first future (work)
before its second future (timer), returning immediately if work is ready.
`Cargo.toml` supplies Tokio with `full` features. Exact source excerpts and
feature line are in `resolved-select-poll.txt` and `dependency-features.txt`.
The original watchdog test file was saved byte-for-byte before the temporary
addition; `before.sha256` records it and both existing codec candidate hashes.

## One controlled run

Temporary addition: one 111-line current-thread Tokio test in
`src/db/migrations_tests.rs`, saved as `temporary-migrations-tests.rs.txt`
and `temporary-test.patch`. It calls the actual production
`run_with_migration_timeout` helper. The shellchecked `run-named-test.sh`
selected only `diagnostic_delayed_watchdog_poll_order`, with offline/locked
Cargo, the existing PostgreSQL/test-support/legacy-networking features,
standard linker flags, one build job, and the existing private external
Cargo target. The script ran as managed user unit
`mxd-watchdog-h1-20261113-1602.service`, invocation
`439db79c68714c3da5974c4d4b520602`, with `RuntimeMaxSec=1200`.
No broad suite, source commit, production edit, dependency change, or cache
cleanup was performed.

The diagnostic first established pending on the actual helper and separate
1 ms and 50 ms Tokio timer probes. At 94 µs after its monotonic start it
printed the pending observation, then paused its current-thread runtime for
100 ms. After driving the timer runtime with a bounded short sleep, both
independent probes reported ready at 103,957 µs. The helper's work future
recorded its ready transition at 104,041 µs; the helper returned
`Ok(Ok(()))` at 104,061 µs. The selected work completed before the helper
reported a timeout. The immediate-completion control succeeded. A separate
work future waiting only for a cloned cancellation token received a wrapped
1 ms timeout under the same delayed-poll setup, and the token was cancelled.

`test.log` reports one named test passed, zero failed, 397 filtered out;
compilation took 2m08s. The service was observed inactive with a success
result and no main PID after the test. Its transient unit was later unloaded,
so `final-unit-props.txt` is **not** durable proof of the original
`RuntimeMaxSec` or invocation ID; those were recorded at launch. The test
output, launch log, script, and journal are retained locally.

## Interpretation and boundary

**Mechanism witnessed:** a delayed poll can leave both independently armed
timer probes ready, yet the actual helper returns completed work because
`Select` polls work first. The probes and monotonic times support a sufficient
mechanism; the helper's timer readiness was inferred from its first pending
poll and timer-driver advance, not instrumented directly. This experiment
does not establish that host scheduling caused the earlier managed-gate
failure, estimate its frequency, or decide the intended tie policy.

**Separate contract question:** when work and the watchdog deadline are both
ready at the next poll, should completed work or timeout win? The existing
developer guide says expiry cancels in-progress work but does not explicitly
settle this tie. No test assertion or production behaviour was changed to
answer it.

After the service stopped, only the watchdog test file was restored from its
saved exact bytes. `sha256sum -c before.sha256` passed for that file and both
codec candidates. Private HEAD is unchanged; `after-status.txt` lists only
`src/wireframe/codec/mod.rs` and `src/wireframe/codec/framed_tests.rs` as
modified and unstaged. The C2 full gate remains unpassed.
