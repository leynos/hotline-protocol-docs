# Identified shx source profile and bounded callback results

A local converted Git repository for the historical client is now retained as
[a hashed source snapshot][manifest], separate from the original server-only
comparison. Its revision is:

```text
adb1bf8c8cb12f7eb2fa2c01673295a6312f262b
```

The commit is dated 3 September 2001. README identifies **Synapse Hotline X
(shx)**, and `version.c` declares **0.1.48**. This identifies source content;
it does not identify a configured executable, a particular distributed binary
or every client called SynHX. Compile-time HOPE, cipher, compression, IPv6 and
UI features create additional profiles. GAP-080/083 retain those boundaries.

## Basic login and unknown fields

The non-HOPE path in `hx_connect` writes the normal shared TRTP/HOTL handshake,
then sends login 107 with name, icon and complemented login/password bytes.
It does not add reported-version field 160 in that basic request path. A
64-byte client credential input cap is not proof that the native server accepts
64 bytes; the native destination limits remain separately documented.

Normal `rcv_task_login` checks the low bit of the header status word. On a
successful low-bit test it calls connection/UI hooks, then iterates TLVs with
`dh_start` and handles **only UID field 103** in its switch. Other well-formed
fields have no matching case. Thus source inspection does not support a rule
that this callback must reject native version/unnamed-value/name extras 160/161/162.

The generic TLV iterator advances by each record's declared length within its
buffer boundary checks. It is not a universal strict field-schema validator.
This observation does not establish tolerance of arbitrary malformed lengths,
fragmentation or every optional field in other callbacks.

## Executed host callback matrix

The [reproducible driver][driver] extracts the **unchanged** historical
`rcv_task_login` function and `dh_start`/`dh_getint` macros from the frozen files.
It compiles them with the original `hotline.h`, generated valid reply buffers
and host stubs for UI/address-formatting hooks. HOPE/cipher/compression are not
enabled. The [recorded result][result] retains source-fragment hashes, compiler
identity/arguments and these seven outcomes:

| Generated reply input | Observed callback result |
| --- | --- |
| Empty success reply | Calls connection hook; leaves previous UID unchanged. |
| Success with 160/161/162 | Calls connection hook; extras ignored. |
| Success with UID 103 and those extras | Calls connection hook; reads UID 42. |
| Success with unrelated field 32767 | Calls connection hook; unknown value ignored. |
| Status 1 with extras | Does not call success hook or update UID. |
| Status 2 with extras | Calls success hook because the low bit is clear. |
| Two UID fields, 42 followed by 43 | Callback finishes with UID 43. |

These are executed **host fragment tests**, not native Hotline/shx sessions,
packet captures, full-client acceptance tests or tests of the compiled HOPE
branch. They show that selected parsing decisions are in the preserved code,
without substituting a newly written model of that callback. UI stubs and valid
buffers do not prove authentication, transport or presentation compatibility.

Run from mothra, with a host C compiler available:

```sh
python3 scripts/verify-shx-login-fragment.py
```

Generated code, executable and current result stay under
`mothra/state/shx-login-fragment/`. The evidence keeps the exact driver/harness
snapshots used for the recorded run. This check is also part of `make check`.

## Other receiver observations and negative scope

The selected source defines task replies as `0x00010000` in its combined first
header word, matching the native reply marker with transaction type zero.
Task lookup correlates by transaction ID. This corroborates the distinction
between a native direct reply and an operation-type-107 augmentation hook.

It names notification 111 **POLITEQUIT** and dispatches it to its ordinary
message receiver after printing a notice. That is independent client-source
corroboration of the native shutdown producer, not a requirement for every kick.

Its `hx_rcv_magic` callback advances to header reading without inspecting the
handshake response bytes. A canonical implementation should validate response
magic/status; the earlier blanket assertion that every client does so is not
established by this source. This callback was inspected, not executed in the
login-fragment harness above.

Chat/message receivers copy data bytes and perform presentation transforms
such as CR-to-LF conversion and ANSI stripping. This selected basic path does
not supply evidence of a universal plaintext-invalid-UTF-8 negotiation signal
or a connection-wide credential-complement mode for chat/news text. Optional
cipher/compression negotiation is a different mechanism.

No request-500 definition or send site was located in the inspected snapshot
search. This is a bounded negative result at this source revision; it does not
prove that later clients never use 500 or settle its native purpose (GAP-079).
Likewise the client account constants/selected account paths do not establish a
human meaning for native account field 111. That value stays opaque (GAP-071).

[manifest]: ../mothra/evidence/gap-remediation/2026-11-12/batch-12/manifest.json
[driver]: ../mothra/scripts/verify-shx-login-fragment.py
[result]: ../mothra/evidence/gap-remediation/2026-11-12/batch-12/host-fragment-result.json
