# Restore the owned ban-expiry accounts after the final probe

Cleanup is a separate stage **after** the intended post-expiry Login107
succeeds and its paired packet evidence is accepted. No cleanup login, guard or
mutation may precede that first lookup. The generator opens no sockets. It
emits plans only for `m-expiry-zero` and `m-expiry-protected`; it cannot accept
substitute account names or select the original accounts for deletion.

This document belongs to the [native evidence](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

## Guard, then delete

Use the same verified emulator PID/start/executable, namespace and image inode
as the recorded ban, with a fresh managed capture epoch and actual-namespace
runner context. `POST_RESULTS` must contain the accepted `summary.json` and
`post-probe/{plan,report}.json`. Runtime metadata must match that post plan.
Create each output leaf once; preserve failures and do not retry automatically.

```sh
python3 scripts/native_ban_expiry_cleanup.py --stage guard \
  --post POST_RESULTS --runtime RUNTIME_JSON --output GUARD_PLAN_DIR
```

Capture the generated guard plan under the supervisor's live grant. It logs in
as admin, reads both owned accounts with 352 and closes. Before authorizing any
deletion, verify the generic capture checksums/events and exact names,
complemented keys, `x` password placeholders and ACLs zero/bit 23. A missing,
changed or ambiguous record stops the sequence. The staged generator checks
these conditions again when producing deletion:

```sh
python3 scripts/native_ban_expiry_cleanup.py --stage delete \
  --post POST_RESULTS --runtime RUNTIME_JSON --guard GUARD_CAPTURE \
  --output DELETE_PLAN_DIR
```

Capture deletion separately after review. It sends two 351 requests, checks
both ACKs, checks both 352 missing-account replies and compares 348 enumeration
with the original two-account digest. Partial deletion is a failed outcome;
never broaden the target set or delete an original account to force a match.

Run the generic `protocol_capture.py verify` on each capture. From Python,
`native_ban_expiry_cleanup.semantic(report, "guard")` or `"delete"` provides
the corresponding semantic check. The generator additionally binds the guard to
the post-probe/runtime before it emits any delete plan.

## Postflight and evidence limits

After successful deletion, run the original 18-action control-only baseline as
a **separate** capture. It must again find two original accounts, 41 Files
entries, the expected agreement/metadata, roster and idle diagnostic. This
checks control health; it does not exercise the full A7 file transfer.

Retain complete namespace/guest TCP streams, unread tails, capture receipts,
zero-drop and zero-primary observations, and the original preflight records.
The current custom B68 post report lacks the generic capture checksum manifest;
its event/stream semantics are checked separately, and the supervisor must
accept its independent packet pairing before cleanup. Generation and offline
tests alone are not that packet proof.

Finally retire only owned runtime/units and prove the actual emulator is gone
and no process holds its working image before reading any stopped forks.
Compare the original account and Prefs bytes with preflight. Never read, copy
or hash the working disk while the emulator remains live.

Offline tests cover wrong owned identity/access, bad status/readback,
substituted original-account enumeration and fail-closed delete generation:

```sh
python3 -m unittest discover -s scripts -p test_native_ban_expiry_cleanup.py
```
