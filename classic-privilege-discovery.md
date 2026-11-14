# Classic privilege editor string discovery

This [bounded corpus](../mothra/evidence/gap-remediation/2026-11-14/classic-privilege-discovery-01/manifest.json)
preserves one fresh independent Ghidra 12.2 import of the identified Classic
client and three read-only defined-string queries. The archive calls the app
“Hotline Client 1.9.2 Classic”; its embedded `vers` resources say **1.9.1.0**.
Those names do not establish a vendor-wide client version or behaviour.

The imported DATA fork has SHA-256
`7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315`;
the separately checked resource fork has SHA-256
`f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b`.
The pinned GhidraMCP JAR has SHA-256
`201d18ffde71a83a678eae607de265861f37e5a00b989d91958c1197664d2b43`.
Only a new ignored `classic-privilege-01` project was created. Before and
after the queries, Ghidra reported the same PEF SHA, PowerPC BE32 language,
and 3,564 functions. Neither the GUI nor server project was opened.

## What the queries found

`list_strings` with filter `MyAdminEditUserWin` returned exactly one related
defined string: **`CMyAdminEditUserWin` at loaded address `1014fef8`**. It
did not return an exact unprefixed match. Filters `Can Send Messages` and
the known-control label `Can Disconnect Users` each returned **zero defined
strings**. The planned eight-call discovery therefore stopped after three
calls. No memory read, xref lookup or decompilation was made. The original
reports and raw responses remain unchanged in the corpus.

This result does not say those privilege labels are absent from the client.
Earlier exact DATA-byte inspection found `Can Send Messages` at raw file
offsets `0x14d33c` and `0x14f9b4`, among two Pascal-string runs. The class
name occurs in the raw file near `0x14faf4`. That part of the PEF is
**compressed PackedData**: its file offsets cannot be converted to loaded
addresses by adding a base. The imported initialized PackedData span is
`10135810..10159ef8`. The one positive loaded class address is not a
general offset-mapping rule.

The earlier [constructor trace](classic-account-constructors.md) proves that
this client serializes eight privilege bytes from an account object into
field 110 for account requests. The discovery here does **not** connect a
named UI control to any bit of that object. In particular, it supplies no
meaning for unknown bits 18/19 or 41–63. A client label, if later bound to
a bit, would describe this candidate client's intended UI; server 1.9
enforcement still requires its own evidence. The old bit-19 private-message
label is contradicted by the server's measured bit-40 gate and is not reused.

A further, separately authorised client query could follow the positively
loaded `CMyAdminEditUserWin` reference or use a reviewed PEF decompression
method to locate the Pascal labels. A label-to-bit claim needs the concrete
control/index-to-mask write and the already traced object-to-wire path.
No such follow-up occurred in this packet. GAP-031 remains open on unknown
meanings; account field 111 is separate.

From `mothra`, check the portable source inventory without Ghidra or the
client binary:

```sh
sha256sum --quiet -c \
  evidence/gap-remediation/2026-11-14/classic-privilege-discovery-01/SHA256SUMS
```
