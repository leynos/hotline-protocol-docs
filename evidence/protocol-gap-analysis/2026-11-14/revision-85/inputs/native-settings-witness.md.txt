# Native 1.9 settings field 113 witness

This is one bounded live matrix for transaction 304, field 113, against the
exact Hotline Server 1.9 binary SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
The retained [corpus](../mothra/evidence/gap-remediation/2026-11-13/native-settings-01/manifest.json)
contains ten source/as-run plans, reports, host/guest PCAPs, packet tails,
execution receipts and exact A7 preflight/postflight readbacks. The frozen
capture was made on the original Mac guest; this document can be checked
offline without starting that guest.

| 304 field 113 input | Measured effective flags | PM observation |
| --- | ---: | --- |
| Absent | 0 | Delivered; no feedback |
| Present, zero length | 0 | Delivered; no feedback |
| Two-byte `0000` | 0 | Delivered; no feedback |
| One-byte `01` | 1 | Suppressed; refusal option 2 |
| Two-byte `0004` | 4 | Delivered; auto response option 4 |
| Three-byte `000001` | 0 | Delivered; no feedback |
| Four-byte `00000005` | 5 | Suppressed; auto response option 4 |
| Five-byte `00000001ff` | 1 | Suppressed; refusal option 2 |
| Duplicate `0001`, then `0004` | 1 | Suppressed; refusal option 2 |
| Duplicate `0004`, then `0001`, interleaved identical 104/102 | 1 | Suppressed; refusal option 2 |

The three-byte value defaults to zero and the five-byte value uses its first
four bytes in these **304/113 cases**. Both duplicate orders selected one in
these two cases. This does not establish a universal first/last-wins rule:
the native index sorts scalar IDs before binary-search lookup
(`native-wire-details.md#parameter-parsing-and-scalar-access`), while indexed
iteration preserves original order. Static generic reader `10056b90` and
settings helper `10004d50` predicted the width/default results; the PM and
301 captures provide the actual operation witness.

Each case used an existing admin observer and subject, saved the subject UID
from 301, sent one uniquely labelled option-1 PM, then observed the receiver
delivery and sender feedback through numbered 500 barriers. Transaction 304
has no normal ACK. Each case reset 102/104/113, observed 301 and closed both
sockets. Host and guest streams reconcile for all 20 case sockets. Nine cases
retained identical 28-byte unread 302 disconnect tails after subject close;
one had no unread tail. These tails are not failed PM controls.

The exact immutable A7 baseline was run before and after the matrix: both
29-action reports match two accounts, 41 Files entries, field-206 metadata,
idle 303 before/after and the 1,049,073-byte FILP download with expected DATA
and MACR hashes. Both A7 connections pair with host and guest captures in
each phase. The direct system recorder captured 3,754 packets, with zero
kernel drops and a successful terminal exit. No account, file or server
option was changed for this matrix.

Two preparation defects remain visible in the evidence. The first generator
invocation used a canonical path without the new private script and failed
before any settings plan or native socket. The preflight as-run plan's
`a7_phase` **label** says `postflight` because its preparation reused a
dictionary; its exact A7 steps, source hash and separate preflight result are
retained and verified. Neither defect is erased or treated as a native result.

Offline replay from the adjacent repositories:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_settings_corpus.py \
  evidence/gap-remediation/2026-11-13/native-settings-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts \
  -p test_native_settings_corpus.py
```

This packet adds field-113 rows to GAP-015/016/017. The combined
[scalar registry](native-wire-details.md#core-scalar-width-registry) now covers
the core width contract; GAP-016 presence/default criteria remain open.
Subsequent combined review accepted GAP-017; see
[parameter multiplicity](parameter-multiplicity.md) for the
transaction-specific rules and the scope of that acceptance.
