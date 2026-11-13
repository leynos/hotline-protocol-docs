# Identified shx source profile and bounded callback results

A local converted Git repository for the historical client is now retained as
[a hashed source snapshot][manifest], separate from the original server-only
comparison. Its revision is:

```text
adb1bf8c8cb12f7eb2fa2c01673295a6312f262b
```

The commit is dated 3 September 2001. README identifies **Synapse Hotline X
(shx)**, and `version.c` declares **0.1.48**. This identifies source content;
the source snapshot alone does not identify a configured executable, a
particular distributed binary or every client called SynHX. The complete build
and native sessions below now identify one configured modern executable.
Compile-time HOPE, cipher, compression, IPv6 and UI features create additional
profiles. GAP-080/083 retain those boundaries.

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

## Identified complete terminal build

The [frozen full build][full-build] uses the same source commit, with terminal
UI, IPv4, HFS/CAP forks and fork-based transfers enabled. GTK, HOPE, cipher,
compression and IPv6 are disabled. Four obsolete cast-as-lvalue expressions
in cached file-list traversal/rendering were replaced with explicit pointer
advances. Modern GNU host-detection helpers replace their ancient counterparts.
The build keeps the historical login/transport/serialization code and the
legacy configure result for bundled `snprintf`. Both CFLAGS and CPPFLAGS point
to the recorded local Readline/ncurses headers.

The tested executable has SHA-256:

```text
8fbbe56cef439d4c1732e8d9fbe2c676b9d45fbd273a42b22f8034e3b3914fa0
```

This identifies a modern Linux build of historical source. It does not identify
an original distributed executable. Build inputs, patch, configuration, compiler
flags, dependency identities and logs are retained. An earlier exploratory
manual build omitted CPPFLAGS and has a separate profile; its one basic session
is retained under `initial/`, outside the accepted matrix.

## Full native peer acceptance matrix

The [full-process corpus][full-corpus] runs the complete terminal client against
the continuing native Mac OS 9.0.4 server. Five sessions completed. Raw terminal
output, command events, hexadecimal strace records and both host-loopback and
guest-Ethernet PCAPs are retained. Six peer socket lifetimes and one controlled
witness lifetime reconcile byte-for-byte at both packet boundaries. The host
recorder reports 170 packets and zero kernel drops.

| Session | Native exchange and independently checked result |
| --- | --- |
| Basic login/chat | Ordinary TRTP/HOTL version 1/sub-version 2; nonempty complemented password; login ACK includes 160=`00be`, 161=`0000`; privileges, agreement, automatic roster and chat echo complete. |
| Root listing | Same bootstrap; request 200 and repeated field-200 native file records are consumed and displayed. The fork fixture is `TEXT`/`MOTH`, aggregate size 330. |
| Fork download | Request 202 gets a nonzero reference; the child attaches to data port 5501 through host 15501 and consumes 510 FILP bytes. Saved DATA is 13 bytes and MACR is 317 bytes, each exactly equal to the known fixture and captured stream. |
| Ambiguous-byte receive | A controlled script logs in as `native-byte-witness` and sends ordinary chat 105. Native 106 and the real peer's raw terminal output preserve the complete test bytes below. |
| Wrong password | Native status 1 with field 100=`Incorrect login.`; the real client prints the task error and `login failed?`, then exits normally without sending the roster request. |

The basic client omits version field 160 from its request. Native nevertheless
returns 160/161. The server name is empty, so 162 is omitted. No 122 banner is
emitted in these sessions. The successful profile therefore supplies full-peer
tolerance evidence for these 160/161 values and native roster/file records;
it does not yet test configured 162, 122, the SynHX subject addition or other
client builds/profiles (GAP-080/081).

The client automatically requests roster 300 after its login callback.
Subsequent `/who` commands display the local roster and generate no additional
300 requests in this corpus. The login reply contains no UID field 103, and the
client's basic login callback handles only that field. Successful chat/listing
is not proof that every self-identity-dependent feature has valid state.
No delayed 121 acceptance occurs in these sessions.

## Ambiguous text at the real peer boundary

The controlled witness sends these field-101 bytes:

```text
mothra-peer-byte-80-9a-c3b6-ff-END
```

Here `80`, `9a`, `c3b6` and `ff` denote raw hexadecimal bytes between literal
ASCII hyphens. The exact hex is
`6d6f746872612d706565722d627974652d802d9a2dc3b62dff2d454e44`.
Native prefixes the chat with CR, `native-byte-w:`, and two spaces. That truncated
name is the captured server formatting, while the roster retains the full
`native-byte-witness` name. The whole test suffix occurs unchanged in native
106 and `stdout.bin`. It contains both invalid UTF-8 bytes and the valid UTF-8
sequence `c3b6`, without triggering a credential-complement transformation.

The capture records the locale variables for this session and forces
`TERM=dumb`. The PTY applies ordinary terminal line-ending handling; this is
byte-preservation evidence for the test suffix, not a glyph/font rendering test
or a negotiated character-set declaration. `stdout.txt` is an escaped UTF-8
convenience view; the verifier uses `stdout.bin` and packet bytes. The witness
is a controlled script, not a second identified historical client. mxd decoding
policy and unknown-peer fallback remain separate unresolved decisions.

## Reproducing and checking full peer sessions

Follow the repository-local [build and containment guide][peer-guide] and the
native capture workflow. Use the retained plans with a new output directory,
matching build profile and verified native oracle input. The driver maps a
private repository-backed home over HOME, shares loopback networking and keeps
the system root read-only. It records normal process exit and checks that the
real `~/.hxvars` state is unchanged. The legacy client saves that file even
with `-q`; direct execution can overwrite an existing file. The initial
uncontained probe did so; no verified previous contents were recovered.

Run the offline acceptance verifier from mothra:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_shx.py \
  evidence/gap-remediation/2026-11-13/native-shx-01
```

This check is part of `make check`. Nine regression cases reject missing
sessions, omitted native extras, altered high bytes, a false successful login,
changed guest packets and incorrect saved resource bytes; they also exercise
truncated syscall text and partial writes. The recorder's
`native_conformance: false` remains literal: the capture tool checks local
hashes and records operator-supplied guest provenance. Independent packet and
semantic checks establish the bounded results above, without certifying every
operation or treating supplied runtime metadata as process attestation.

[full-build]: ../mothra/evidence/gap-remediation/2026-11-13/shx-build-01/inputs.json
[full-corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json
[peer-guide]: ../mothra/shx-peer.md
