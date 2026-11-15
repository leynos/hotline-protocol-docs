# Internal compatibility matrix (observed Hotline peers)

This matrix records the implemented wireframe login behaviour. A handshake
sub-version or a self-reported login version is an observed value, not proof of
peer identity. In the native 1.9 baseline, the Mac client, identified shx
client, and historical SynHX source all use sub-version 2. The wider release
subset and owner remain undecided; see the protocol documentation's GAP-085.

| Observed peer or input                         | Login facts retained                                    | mxd successful Login107 direct ACK                                                                                      | Remaining limits                                                                                                           |
| ---------------------------------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Mac Hotline 1.9                                | Handshake sub-version 2 and optional reported field 160 | Type 0, correlated ID, server version 190 in 160, opaque two-byte `0000` in 161, configured nonempty server name in 162 | Configured name currently accepts ASCII of at most 31 bytes; native raw high bytes and setter clipping are not reproduced. |
| Identified shx 0.1.48                          | Handshake sub-version 2; reported version varies        | Same successful-login fields; no identity gate                                                                          | Other native client parity remains subject to separate evidence.                                                           |
| Historical SynHX source                        | Source uses handshake sub-version 2                     | Same successful-login fields; no identity gate                                                                          | This source observation does not establish a tested release profile.                                                       |
| Absent, zero, 150, 151 or 190 reported version | Raw request value retained when present                 | Same successful-login fields; no version gate                                                                           | Reported version is not an identity or release-profile signal.                                                             |
| Failed Login107                                | Raw request value retained when present                 | No success-only 161 or 162                                                                                              | Error contract is separate from successful-login augmentation.                                                             |

The `ClientCompatibility` adapter preserves handshake and login-version facts.
The router uses one `DefaultAuthStrategy` for all peers. Field 162 is emitted
as exact configured ASCII bytes when nonempty and omitted when empty.
Configured names containing non-ASCII characters or more than 31 bytes fail
validation before the wireframe listener starts. The default remains `mxd`, an
mxd product default rather than an observed native default. XOR-enabled
connections apply the existing bytewise XOR transform to field 162 after
augmentation; field 161 is unchanged.

This matrix describes an implemented subset, not full native 1.9 parity or a
release decision. Native field 162's raw `9a` witness and 32-byte typing
attempt clipped to 31 bytes require a separately approved encoding and
configuration policy. Field 161's meaning is unresolved. Kani source harnesses
are not proof unless run. The native observations and remaining decisions are
tracked in the adjacent protocol documentation and its gap analysis.
