# Classic client account request constructors

This bounded read-only trace uses the identified Classic PowerPC client DATA
fork, SHA-256 `7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315`,
and resource fork, SHA-256
`f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b`.
The archive labels it “Hotline Client 1.9.2 Classic”, while its `vers`
resources say 1.9.1.0; see the [candidate identity][candidate]. Neither
label proves vendor authenticity. The [portable query corpus][corpus] contains
input/tool hashes, the PEF section map, exact tool arguments and replies,
source scripts, stderr, a query plan, a manifest and SHA inventory. It omits
the client forks and Ghidra project database.

## What the executable trace establishes

Ghidra 12.2 imported this client into a new independent ignored project as a
PowerPC BE32 PEF. The Code block begins at `10000000`; raw section-0 offset
`0xb2294` maps to `100b2294` and reads `38 80 00 6f`. Program identity was
unchanged before and after each bounded query run. B37 made 12 content calls,
B38 eight and B39 three, each under its approved cap. The [offline verifier]
[verifier] checks the retained decompilations and these identities.

| Client path | Positive construction evidence |
| --- | --- |
| `FUN_1000c210`, request 350 | Appends 105 login, 106 password, 102 display name and 110 eight-byte privileges; dispatches type `0x15e`. |
| `FUN_1000c800`, request 353 | Appends the same four IDs; dispatches type `0x161`. |
| `FUN_1000bfa0`, request 349 | Accepts an already-built account parameter object, passes its serialised buffer into the request and dispatches type `0x15d`. |
| `FUN_1005b5b0`, 349 object source | Iterates account records and constructs nested fields 101 old login (conditionally), 105 login, 106 password, 102 display name and 110 privileges; emits each nonempty nested stream as outer field 101. |
| `FUN_1005ce30`, preceding 349 list | Constructs inner field **101** (`0x65`) only, then outer field 101. The native [349 handler][batch] uses a nonempty old login with empty new display/login for its deletion branch. The client field shape and native branch together support the deletion interpretation. |

The client's `FUN_100b05d0` writes a counted BE16 ID/length/value TLV and
skips zero-length values. `FUN_1005b5b0` reads old login at record offsets
`0x576/0x578`, login at `0x298/0x29a`, password at `0x2bc/0x2be`, name at
`0x210/0x212`, and eight privilege bytes at `+4`. These are **client object**
offsets. The separate [server record trace][server] places opaque field 111
at `0x254/0x256` in its 734-byte record; matching some other offsets does
not identify the client's omitted attribute.

The four first-pass `li r4,111` candidates in the client decompile instead
pass `0x6f` to `FUN_1007d7e0` on error paths. They are not demonstrated
account-field accesses. The inspected 350/353 constructors and 349
serializer do not append 111. This is a bounded statement about those
functions, not a whole-client absence, unused-field or semantic claim.
The 349 wrapper has two visible direct callers; indirect callers and other
client parsers/builders remain outside this survey. **GAP-071's human meaning
remains open.** A positive meaning needs a field-111 producer or consumer
traced to a specific UI control, resource or other operation.

## Repeat or check without a live server

From a fresh `mothra` plus adjacent protocol-docs export, check the portable
bundle without the client or Ghidra:

```sh
sha256sum --quiet -c evidence/gap-remediation/2026-11-13/client-account-constructors-01/SHA256SUMS
python3 scripts/verify_classic_account_constructors.py
python3 -m unittest scripts.test_verify_classic_account_constructors
```

To repeat the import, first obtain the exact DATA/RSRC forks and compare both
hashes above. Use Ghidra 12.2, the recorded JAR SHA-256 and a **new ignored
project** separate from any server or GUI project. The retained
`b37-probe.py.txt` shows the environment, command and `oracle.lock` use; it
refuses an existing destination. Copy it to ignored state, review its pinned
paths, set a fresh project/output base and run once under the same lock. Use
`--no-analyze --discard` for follow-up queries, with the recorded addresses
and before/after identity checks. The B38 script was extended between runs;
its final copy is not the exact source of the first two invocations. The raw
report arguments/results and logs are the authority for those runs. No native
server, client app or existing Ghidra project is needed for offline checking.

[candidate]: ../mothra/docs/delegation/mac-peer-candidate.md
[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/client-account-constructors-01/manifest.json
[verifier]: ../mothra/scripts/verify_classic_account_constructors.py
[batch]: operation-contracts.md#administrative-account-list-and-batch-mutation
[server]: account-attribute-trace.md
