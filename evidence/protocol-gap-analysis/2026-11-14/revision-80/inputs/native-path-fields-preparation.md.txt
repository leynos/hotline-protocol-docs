# Native path-field matrix preparation

The subsequent [native path witness](native-path-fields.md) records the
completed twelve-case run and its limits. This page describes preparation.

This is an **offline fixture**, not a native result. It implements M1 of
Mothra's `docs/execplans/structured-path-fields.md`. The prospective endpoint
is `127.0.0.1:15900` inside the owned emulator namespace. The guest server is
`10.0.2.15:5500`; `10.0.2.2` is the guest view of the relay client. The guest,
service, capture recorders and oracle lock need separate supervisor approval.
A fresh runtime receipt is required before invoking the coordinator.

## Inputs and commands

The producer takes a JSON runtime identity with `fixture_profile` set to
`control-only`, plus actual emulator PID, start time, executable SHA-256,
network namespace inode, owned working-image path and inode. Host inode values
are not restricted to 16 or 32 bits. The supervisor checks the full approved
Python source closure, original DATA and ROM hashes, image ownership, managed
capture FDs and deadline before creating the plan or opening a socket.

```sh
python scripts/native_path_fields_cases.py \
  --runtime RUNTIME.json --output NEW-PLAN-DIR --port 15900
python scripts/native_path_fields_control.py \
  --plan-dir NEW-PLAN-DIR --capture-receipt ROOT-OWNED-RECEIPT.json \
  --binary ORIGINAL-DATA --output NEW-RESULT-DIR
```

Both output leaves must be absent. The producer writes an exact plan and
`source-hashes.json` for the plan and both owned Python sources. The runner
checks those hashes and regenerates the exact plan before socket use. The
capture receipt and source-closure pins remain separate operator gates. The
runner requires the actual network namespace, runtime identity and oracle DATA
hash, and runs the existing `runtime_gate` before each connection and after
the case. A closed, unchanged 18-action control readiness preflight is a
separate operator step. It is not silently included in the case connection.

## Fixed case

One retained admin connection sends 82 deterministic numbered requests,
including login. The case begins with account, roster, Files-root and
News-root reads. It then makes nine owned Files creates and two News creates.
Six Files moves use field 212, each with a before 206, the move, three
candidate-parent 200 views, an after 206 and a 500 barrier. Six News reads
use field 325, each followed by 500. The exact twelve byte values and their
lengths are in the plan and ExecPlan: nested high-byte, declared empty or
truncated components, opaque word `ffff`, and the 2048/2049-byte boundaries.
The generator never infers that these values must succeed or fail.

The only permitted cleanup is 380 owned category, 380 owned News folder,
then 204 owned Files wrapper, after positive ownership and location checks.
Final health reads accounts, same dynamic roster UID, Files root, News root
and 500 on that same retained case connection. At most 17 extra read-only
requests may supplement the 82, with only a conditional Files-root stop probe
implemented. The maximum is 99 requests, 20 mutation requests, one case
connection, 210 seconds for the runner, 240 seconds for the managed process
and 720 seconds for the complete future epoch. Case start requires at least
390 seconds of that epoch remaining; managed 900-second recorders do not
extend the epoch.

The runner records all raw send/receive events, parsed frames, action times,
terminal tails, selected-parent views and a partial progress prefix even on
failure. Its offline verifier binds report streams to events, direct reply IDs
and parsed fields, request counts, each selected marker's before/after views,
and type/creator bytes for every owned-parent entry. A successful move with
no measured location change stops as ambiguous. Final account/UID controls
are also checked. The report does not establish stopped HFS
catalogue IDs, both forks, actual peer acceptance, or equivalence of fields
202, 212 and 325. Those require the later native and publication milestones.

An incomplete reply, foreign marker location, missing ownership proof,
runtime drift or deadline failure stops the case. No automatic retry, blind
cleanup, original Files or News deletion, account change or clock change is
part of this fixture. A stopped disposable image may need quarantine after a
partial mutation. The supervisor must retain paired PCAPs, capture-drop
journals, managed unit and mutex receipts, and stopped five-fork proof for M2.

## Offline checks

Run `python -m unittest -q test_native_path_fields` with canonical protocol
dependencies on `PYTHONPATH`; run Ruff format/check, `ty check`, Markdownlint
and Nixie on a fresh committed export. The model tests exercise the exact
matrix and semantic faults, while a real socketpair test covers split replies
and a retained partial frame with owned FD closure. None contacts Hotline.
