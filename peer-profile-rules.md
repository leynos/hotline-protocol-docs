# Identified peer profiles and the unknown-peer rule

The protocol documentation uses the two exact builds below as its current
interoperability evidence targets for native Server 1.9. A target is a
particular executable and configuration with measured coverage. It is not
every release carrying the same product name. The matrix records tested and
untested cells; it does not certify a complete implementation or select an
mxd release subset. Further mxd validation remains on hold.

## Evaluated build identities

**shx 0.1.48, configured modern Linux terminal build.** The source revision is
`adb1bf8c8cb12f7eb2fa2c01673295a6312f262b`; the executable SHA-256 is
`8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0`.
The [build record](identified-client-source.md) identifies flags, patches and
dependencies. Other compile-time UI, HOPE, encryption, compression or IPv6
profiles do not inherit these results.

**Classic PPC candidate.** Its executable DATA SHA-256 is
`7f286e3f8941c2261fc9c32b2d1d03acef32bdea567362a1c64abd5d64fe5315`;
its resource-fork SHA-256 is
`f762cfdedcc39758f841f720a4586dbbb88a7b74ec9e83db1793791b7c3f318b`.
The archive/application label says 1.9.2, while embedded `vers` says 1.9.1.0.
Both observations are retained. Vendor authenticity and a universal mapping
from these labels to other binaries are unproved. The
[Classic corpus](classic-field161-matrix.md) pins both forks and its runtime.

| Evidence cell | Exact shx build | Exact Classic candidate |
| --- | --- | --- |
| Native login and roster | Captured full-process sessions | Captured baseline and proxy sessions |
| Native zero-valued 161 | Accepted in native sessions | Accepted in native baseline |
| 161 omission/variation | Controlled receiver: absent and `0001` continue | Native proxy: absent, one zero byte and four zero bytes continue |
| Nonempty 162 | Native ASCII/high-byte configured names accepted through recorded stages | One proxy-appended ASCII value accepted through login/roster/banner-data stages |
| Unknown login TLV | Controlled field 32767 continues | Untested |
| Roster subject 115 | Controlled receiver observation | Untested |
| Banner 122 | Controlled ordering cases continue; early frame produces diagnostic/dump | Native 212 request and 58-byte data transfer; rendering unproved |

The [shx evidence](peer-tolerance-matrix.md),
[Classic baseline](classic-native-baseline.md),
[Classic 161 matrix](classic-field161-matrix.md), and
[ASCII 162 case](classic-server-name-162.md) define each cell's actual
transport, transformations and observed stopping point. A controlled receiver
is not native server execution. A native proxy tests the named rewrite;
unchanged upstream/downstream views and complete TCP tails bound that claim.
An intentional observation cutoff is not a peer rejection.

## Profile assignment and unknown-peer fallback

Assign one of these evaluated profiles only when operator/build provenance
matches its opaque executable identity and configuration. For the Classic
candidate, retain both fork hashes. A handshake, self-reported version, app
name or similar-looking exchange alone is insufficient. Without matching
provenance, the peer remains **unknown**. Shared handshake sub-version 2 and
numeric field 160 do not turn an unknown peer into SynHX or Hotline 1.8.5.

For an unknown peer, the documentation's wire baseline remains native 1.9's
[login producer](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh).
There is no family classifier or extra omission branch in that producer:
successful Login107 adds version 160=190 and the current unnamed numeric
value 161, whose constructor/default and captured value are `0000`. Nonempty
configured server name 162 is included; an empty name is omitted. This does
not prove 161 can never change. Banner 122 is separate and conditional on
banner configuration and saved client version at least 151.

These rules describe what native 1.9 sends to an unidentified peer; they do
not guarantee that every unidentified client accepts it. Keep unsupported or
unmeasured cells unknown. The finite evidence supplies no family-wide reason
to omit 161/162. An mxd omission or fallback policy would be a separately
identified implementation/release decision and is not selected here.

GAP-080's hashed corpus, exact-build targets and evidence-based unknown-peer
rule are covered by this registry. Per-field acceptance remains GAP-081;
161's meaning, general text decoding and release sign-off remain separate.
