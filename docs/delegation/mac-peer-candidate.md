# Mac Hotline client candidate: static identity

The [portable metadata][corpus] records an acquired candidate ZIP and its
static inspection. The original ZIP, applications, resource forks, AppleDouble
sidecars, ROMs and disk images remain only in ignored local state. No client
was launched, installed or connected to a server.

The archive was retrieved on 2026-11-13 at 16:16:05–16:16:07 UTC from the
[Higher Intellect archive link][source]. The requested and final URL matched.
The downloader enforced a 5 MiB streaming cap; it wrote 1,807,023 bytes with
SHA-256 `21bd2df35eb06b9e9310f1fffd7deb2d23efd62a638e09c7bc394778b8a0b679`.
HTTP reported ZIP content, a weak ETag and a 2017 last-modified date, without a
content length. The ZIP central directory declared 4,379,181 expanded bytes; no
traversal path or symlink was found. The retained inventory gives every
member's size, mode and CRC. `unar -k hidden -nr -D` preserved the resource
forks in AppleDouble sidecars beside the data forks.

| Application name in archive    | Data fork SHA-256                                                  | Resource fork SHA-256                                              |
| ------------------------------ | ------------------------------------------------------------------ | ------------------------------------------------------------------ |
| `Hotline Client 1.9.2 Classic` | `7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315` | `f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b` |
| `Hotline Client 1.9.2 OS X`    | `492baea53ff8afee9839f1c90eccdd9099c1ce5c989cf997db766129d4bae4aa` | `2f10e56bec80a81bd194e2371b8cddfcc3f2e5fe304f9d338528d4382f4a50c2` |

Both data forks have PowerPC PEF headers; AppleDouble Finder metadata says
`APPL`/`HTLC`. The two resource forks each have `vers` IDs 1 and 2 with short
strings **`1.9.1.0`** and first four bytes `01 91 80 00`. ID 1 identifies
“Hotline Connect Client 1.9.1.0” with a Hotsprings Inc copyright notice. The
[identity JSON][identity] preserves the raw small `vers` payload hex, complete
fork and sidecar hashes, sizes and Finder codes. The companion
[Finder/version hashes][hashes] record SHA-256 for AppleDouble entry 9, its
first 32 Finder bytes, and each small `vers` payload. The Classic app entry 9
is 179 bytes: 32 Finder bytes followed by `ATTR` metadata containing a
quarantine attribute. The OS X app entry 9 is 32 bytes. The server staging
script requires a 32-byte entry 9, so it cannot be reused unchanged for the
Classic client. The **1.9.2** archive/folder/ application labels conflict with
this embedded **1.9.1.0** version. Neither label is silently adopted as a
behavioural release identity.

The package includes `EULA.rtf`, SHA-256
`ac3b1e5af8db1485a5fc92622489725ee7c98626bb3cd40340a71954e627145d`. Its body is
not retained in this evidence; no legal conclusion is drawn. A vendor-origin
chain, the relationship between the two builds, actual OS 9 launch
compatibility and protocol behaviour remain unproved. The next action requires
a separately reviewed disposable guest and capture plan.

## Verification

From this private `mothra` checkout:

```sh
sha256sum -c evidence/gap-remediation/2026-11-13/mac-peer-candidate-01/SHA256SUMS
markdownlint-cli2 docs/delegation/mac-peer-candidate.md
nixie docs/delegation/mac-peer-candidate.md
```

[source]: https://preterhuman.net/download/Hotline_Client_1.9.2_for_OSX_and_OS9.zip
[corpus]: ../../evidence/gap-remediation/2026-11-13/mac-peer-candidate-01/
[identity]: ../../evidence/gap-remediation/2026-11-13/mac-peer-candidate-01/mac-identity.json
[hashes]: ../../evidence/gap-remediation/2026-11-13/mac-peer-candidate-01/finder-vers-hashes.json
