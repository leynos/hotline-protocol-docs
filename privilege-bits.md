# Native 1.9 access bitmap: per-bit evidence index

This index expands the
[source-use registry](privilege-contracts.md#bitmap-numbering-and-known-uses)
and the retained [64 native single-bit controls][native] into individual rows.
Field 110 is eight bytes in MSB-first wire order: bit `b` uses byte `b >> 3`
and mask `0x80 >> (b & 7)`. Each `353→352` pair below replaced and read back
**one owned account**; IDs are transaction IDs within the named walk. `S` means
a source-observed use in the linked registry. The [call-site review][calls]
covers direct accessors; the registry also cites inline checks. `N` means
native submitted/readback bytes in the linked per-bit record. No row asserts
that its bit alone passes every enclosing handler check.

<!-- markdownlint-disable MD013 -->

| Bit | One-bit field 110 hex | Native case: 353→352 ID | Source-observed use, or unknown                            | Key |
| --: | --------------------- | ----------------------- | ---------------------------------------------------------- | --- |
| 0   | `8000000000000000`    | `walk-00`: 20→21        | Delete ordinary file                                       | S+N |
| 1   | `4000000000000000`    | `walk-00`: 22→23        | Upload ordinary file                                       | S+N |
| 2   | `2000000000000000`    | `walk-00`: 24→25        | Download ordinary file                                     | S+N |
| 3   | `1000000000000000`    | `walk-00`: 26→27        | Rename ordinary file                                       | S+N |
| 4   | `0800000000000000`    | `walk-00`: 28→29        | Move ordinary file                                         | S+N |
| 5   | `0400000000000000`    | `walk-00`: 30→31        | Create folder                                              | S+N |
| 6   | `0200000000000000`    | `walk-00`: 32→33        | Delete folder                                              | S+N |
| 7   | `0100000000000000`    | `walk-00`: 34→35        | Rename folder                                              | S+N |
| 8   | `0080000000000000`    | `walk-01`: 20→21        | Move folder                                                | S+N |
| 9   | `0040000000000000`    | `walk-01`: 22→23        | Receive chat                                               | S+N |
| 10  | `0020000000000000`    | `walk-01`: 24→25        | Send chat                                                  | S+N |
| 11  | `0010000000000000`    | `walk-01`: 26→27        | Create private chat                                        | S+N |
| 12  | `0008000000000000`    | `walk-01`: 28→29        | Unknown                                                    | N   |
| 13  | `0004000000000000`    | `walk-01`: 30→31        | Unknown                                                    | N   |
| 14  | `0002000000000000`    | `walk-01`: 32→33        | Create account                                             | S+N |
| 15  | `0001000000000000`    | `walk-01`: 34→35        | Delete account                                             | S+N |
| 16  | `0000800000000000`    | `walk-02`: 20→21        | Read/enumerate accounts                                    | S+N |
| 17  | `0000400000000000`    | `walk-02`: 22→23        | Modify account                                             | S+N |
| 18  | `0000200000000000`    | `walk-02`: 24→25        | Unknown                                                    | N   |
| 19  | `0000100000000000`    | `walk-02`: 26→27        | Unknown                                                    | N   |
| 20  | `0000080000000000`    | `walk-02`: 28→29        | Read old news / article body; old-board update eligibility | S+N |
| 21  | `0000040000000000`    | `walk-02`: 30→31        | Post old news / article                                    | S+N |
| 22  | `0000020000000000`    | `walk-02`: 32→33        | Disconnect user; also contributes privileged roster status | S+N |
| 23  | `0000010000000000`    | `walk-02`: 34→35        | Protection from request-110 disconnect                     | S+N |
| 24  | `0000008000000000`    | `walk-03`: 20→21        | Read client diagnostic information                         | S+N |
| 25  | `0000004000000000`    | `walk-03`: 22→23        | Bypass upload destination-name restriction                 | S+N |
| 26  | `0000002000000000`    | `walk-03`: 24→25        | Use requested session display name                         | S+N |
| 27  | `0000001000000000`    | `walk-03`: 26→27        | Bypass agreement content                                   | S+N |
| 28  | `0000000800000000`    | `walk-03`: 28→29        | Set ordinary-file comment                                  | S+N |
| 29  | `0000000400000000`    | `walk-03`: 30→31        | Set folder comment                                         | S+N |
| 30  | `0000000200000000`    | `walk-03`: 32→33        | Bypass inspected drop-box restrictions                     | S+N |
| 31  | `0000000100000000`    | `walk-03`: 34→35        | Create alias                                               | S+N |
| 32  | `0000000080000000`    | `walk-04`: 20→21        | Broadcast                                                  | S+N |
| 33  | `0000000040000000`    | `walk-04`: 22→23        | Delete article                                             | S+N |
| 34  | `0000000020000000`    | `walk-04`: 24→25        | Create news category                                       | S+N |
| 35  | `0000000010000000`    | `walk-04`: 26→27        | Delete ordinary-file news item                             | S+N |
| 36  | `0000000008000000`    | `walk-04`: 28→29        | Create news folder/bundle                                  | S+N |
| 37  | `0000000004000000`    | `walk-04`: 30→31        | Delete news directory/bundle                               | S+N |
| 38  | `0000000002000000`    | `walk-04`: 32→33        | Upload folder                                              | S+N |
| 39  | `0000000001000000`    | `walk-04`: 34→35        | Download folder                                            | S+N |
| 40  | `0000000000800000`    | `walk-05`: 20→21        | Send private message                                       | S+N |
| 41  | `0000000000400000`    | `walk-05`: 22→23        | Unknown                                                    | N   |
| 42  | `0000000000200000`    | `walk-05`: 24→25        | Unknown                                                    | N   |
| 43  | `0000000000100000`    | `walk-05`: 26→27        | Unknown                                                    | N   |
| 44  | `0000000000080000`    | `walk-05`: 28→29        | Unknown                                                    | N   |
| 45  | `0000000000040000`    | `walk-05`: 30→31        | Unknown                                                    | N   |
| 46  | `0000000000020000`    | `walk-05`: 32→33        | Unknown                                                    | N   |
| 47  | `0000000000010000`    | `walk-05`: 34→35        | Unknown                                                    | N   |
| 48  | `0000000000008000`    | `walk-06`: 20→21        | Unknown                                                    | N   |
| 49  | `0000000000004000`    | `walk-06`: 22→23        | Unknown                                                    | N   |
| 50  | `0000000000002000`    | `walk-06`: 24→25        | Unknown                                                    | N   |
| 51  | `0000000000001000`    | `walk-06`: 26→27        | Unknown                                                    | N   |
| 52  | `0000000000000800`    | `walk-06`: 28→29        | Unknown                                                    | N   |
| 53  | `0000000000000400`    | `walk-06`: 30→31        | Unknown                                                    | N   |
| 54  | `0000000000000200`    | `walk-06`: 32→33        | Unknown                                                    | N   |
| 55  | `0000000000000100`    | `walk-06`: 34→35        | Unknown                                                    | N   |
| 56  | `0000000000000080`    | `walk-07`: 20→21        | Unknown                                                    | N   |
| 57  | `0000000000000040`    | `walk-07`: 22→23        | Unknown                                                    | N   |
| 58  | `0000000000000020`    | `walk-07`: 24→25        | Unknown                                                    | N   |
| 59  | `0000000000000010`    | `walk-07`: 26→27        | Unknown                                                    | N   |
| 60  | `0000000000000008`    | `walk-07`: 28→29        | Unknown                                                    | N   |
| 61  | `0000000000000004`    | `walk-07`: 30→31        | Unknown                                                    | N   |
| 62  | `0000000000000002`    | `walk-07`: 32→33        | Unknown                                                    | N   |
| 63  | `0000000000000001`    | `walk-07`: 34→35        | Unknown                                                    | N   |

<!-- markdownlint-enable MD013 -->

All 64 submitted single-bit values matched native 352 readback after 353. This
demonstrates **preservation in that measured account-record path**; it does not
establish a permission meaning, an ignored-bit rule, or a safe grant policy.
Positions 12–13, 18–19 and 41–63 remain **unknown**. No bit is positively
classified reserved or ignored. Bit 19 is not this build’s private-message send
gate; source-observed bit 40 serves that operation.

The separate
[six width controls](bitmap-boundaries.md#field-110-presence-and-width) show
missing/empty/short/eight/nine-byte replacement results. The
[all-ones control][all-ones] shows eight-byte readback and a 354 session push.
These serialize the bitmap; they do not exercise every bit as a separate right.
Representative [native metadata][metadata], [room][rooms],
[account batch][batch] and [target-protection][identity] fixtures contrast
selected granted and denied operations. Their evidence does not extend
enforcement claims to unknown rows.

[native]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/per-bit.json
[calls]: ../mothra/evidence/gap-remediation/2026-11-12/batch-15/privilege-callsite-review.json
[all-ones]: ../mothra/evidence/gap-remediation/2026-11-13/native-bitmaps-01/all-ones/report.json
[metadata]: ../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json
[rooms]: ../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json
[batch]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json
[identity]: ../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json
