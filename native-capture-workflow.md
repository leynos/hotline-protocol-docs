# Reproducing native protocol captures

The remaining native-fixture requirements need the recorded Mac PPC application
running under a documented Mac OS environment. The generic emulator harness is
in sibling `mothra`; protocol-specific preparation and capture scripts are in
this repository. ROMs, OS disks, compiled emulators and mutable runtime state
are local inputs under `mothra/state` or `mothra/tools`, never Git artefacts.

## Prepare the emulator and application

Install the host prerequisites listed in the generic
[SheepShaver harness guide](../mothra/sheepshaver.md). From `mothra`, build the
pinned interpreter:

```sh
scripts/build-sheepshaver
python3 scripts/mac_runtime.py prepare state/mac-runtime/hotline19 \
  --rom /path/to/supplied/ROM --disk /path/to/OS9.dsk.zip
```

Preparation hashes the supplied ROM and extracted base disk, creates a writable
working copy and refuses an existing runtime directory. A multi-file archive
needs `--member`; nested archives must be unpacked explicitly. Keep the original
base disk for future resets. The observed blank 1 GiB `.hfv` from the Windows
archive was an installation target, not an installed OS. Do not identify a disk
as bootable merely because it is named after an operating system.

Prepare the exact application and resource metadata from the extracted server
archive, using this repository's script:

```sh
python3 ../hotline-protocol-docs/scripts/prepare_hotline_server.py \
  ../hotline-bench/extracted/HotlineConnectServer-Mac \
  state/mac-runtime/hotline19/shared/Hotline19
```

The script verifies the oracle data-fork hash and bounded AppleDouble entries.
It copies Finder information and resources to `.finf` and `.rsrc` for the shared
filesystem, with an exact source manifest. `HLserver19.Classic` has a different
data fork and is not substituted for this oracle.

Launch on an available X display:

```sh
python3 scripts/mac_runtime.py sheep state/mac-runtime/hotline19 \
  --display :0 --port 15500
```

For an isolated display, start `Xvfb :97 -screen 0 1024x768x24 -nolisten tcp -ac`
and use `--display :97`. The Linux real-addressing build needs low-address
mapping: the launcher uses passwordless `sudo` only to start the emulator as
the invoking UID/GID with process-scoped `CAP_SYS_RAWIO`. It does not change the
host's `vm.mmap_min_addr`. Its patched TCP forwards bind to loopback: host
15500–15503 forward to guest 5500–5503. Confirm the guest TCP/IP settings before
using those ports; a listening proxy is not proof that Hotline is running.

Copy the prepared application folder from the guest's Unix/shared volume onto
its native Mac disk using Finder before testing file/fork/Trash/alias effects.
Run the copy there, accept its application licence and configure a dedicated
fixture account. Record guest OS/CarbonLib versions, volume type, account
privileges, agreement/banner settings and exact launch/configuration steps.
Only disposable fixture data should be used for mutation cases.

The initial emulator attempts are not native protocol evidence. The installed
Linux build's JIT asserted during startup; direct-addressing trials encountered
mapping/crash problems. QEMU 10.1.5 with `mac99`, G3/G4 and supplied media reached
OpenBIOS/Mac-ROM loading but did not establish a working server. The source-built
real-addressing interpreter reached a usable desktop. Launching the exact
`HLserver19` from `System9:Hotline19` created the dedicated `admin` fixture
account with password `mothra19`. These credentials are disposable test data.
The first retained native handshake returned `5452545000000000`; this confirms
one control exchange, not the remaining corpus requirements. See the
[session record][native-handshake] for hashes, preferences and limitations.
The supplied base disk SHA-256 is
`c36b7bc9c513b2b576d5e7bdd2d51c54a4d0af01a863e5154ce71274272a3ffe`.
The initial session predates the generic launcher: its exact launch command and
preferences are retained separately, rather than claimed as a launcher test.
That guest subsequently exited with SIGSEGV/double-free diagnostics during GUI
interaction. Its running executable hash and exact guest component versions were
not retained before exit. The initial transcript is therefore an observation
with these limitations, not a complete reproducible conformance fixture.

## Capture an exchange

The capture runner accepts a JSON plan containing schema version 1, an evidence
profile, operator, oracle SHA-256, gap IDs, named endpoints and ordered steps.
Profiles are `native-mac-oracle` and `synthetic-tool-test`; the former requires
the exact recorded oracle hash. Keep the environment description and guest
configuration in the plan as additional provenance. The local binary hash is
verified, while remote process identity remains operator-reported.

Example plan for an established test server:

```json
{
  "schema_version": 1,
  "profile": "native-mac-oracle",
  "operator": "fixture operator",
  "oracle_sha256": "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
  "gap_ids": ["GAP-008", "GAP-084"],
  "environment": "Record emulator, guest OS, volume and server launch here",
  "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
  "steps": [
    {"op": "connect", "connection": "main", "endpoint": "control"},
    {"op": "send", "connection": "main", "hex": "54525450484f544c00010002"},
    {"op": "read", "connection": "main", "size": 8,
      "expect_hex": "5452545000000000"},
    {"op": "close", "connection": "main"}
  ]
}
```

Run from `mothra`, retaining output in a new directory:

```sh
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/native-mac/handshake-plan.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/native-sessions/handshake-001
python3 ../hotline-protocol-docs/scripts/protocol_capture.py verify \
  state/native-sessions/handshake-001
```

Each plan supports `connect`, `send`, fixed-size `read`, `read_frame`,
`read_eof`, `pause` and `close`. Connections have unique lifetime labels.
`read_frame` reads the 20-byte header and declared physical payload; it does not
silently reassemble logical fragments. A receive action can save a bounded byte
slice as `{"save":{"name":"reference","offset":26,"size":4}}`; a later
send can include `{reference}` in its hex string. Select offsets against the
actual decoded response rather than assuming every reply has the same layout.

Timeouts are total monotonic deadlines per action. The 8 MiB session/read limit
is a capture-tool bound, not a native protocol acceptance limit. The transcript
retains successful send/receive chunks, direction, elapsed time, EOF, partial
input, decoded physical frames and concatenated per-connection streams. Failed
expectations/timeouts remain failed and retain the bytes already observed.

Output includes the exact plan, report and directory-relative `checksums.sha256`.
Verification checks identities, stream reconstruction and decoded-frame
consistency. It never turns a synthetic test or matching checksum into native
conformance. These are application TCP-stream transcripts; they do not contain
IP/TCP headers or prove platform-level packet timing. Add a separately hashed
packet capture when a requirement needs those properties.

## Acceptance and corpus coverage

A completed plan establishes its recorded exchange and expectations, not every
gap listed in its provenance. Review the decoded/events result against the
unchanged closure criterion before changing a gap's status. Preserve setup,
before/after filesystem or account state, failures and explicit deviations.

| Fixture family | Required scenarios / related gaps |
| --- | --- |
| Transport and framing | Positive/negative/truncated/pipelined handshakes; both HTXF entry paths; envelope limits and flags; repeated/interleaved/oversized/abandoned fragments; scalar/TLV boundaries. GAP-003–018/084. |
| Authentication and presence | Known nonempty credential success/failure and updates; name normalization/guest cases; agreement/configuration variants; visibility/roster/settings/status transitions and teardown. GAP-019–036/073/084. |
| Messaging and board | Member/nonmember rooms, invitations/partial targets, topics, action/multiline/non-ASCII chat, all PM options/refusal/auto-response states, spam boundaries and board ordering. GAP-037–046/076/084. |
| Files and transfers | Root/nested/alias/invalid paths; listing/info/mutations and partial failure; HTXF refs; forks/resume/folder states; queue concurrency; cancellation; banner changes; interrupted persistence. GAP-047–064/084. |
| News | Both category layouts at threshold 15; empty/branching/cached article lists; navigation/flavours/dates; create/delete graph rewrites, hierarchy and failure cases. GAP-065–070/084. |
| Accounts and administration | Opaque 111 absent/empty/value; create/update/password sentinel/identity conflicts; live changes; bans/expiry/restart; 348/349 mixed outcomes. GAP-071–078/084. |
| Identified peers and release | Hashed compiled historical clients, field-tolerance and ambiguous-text corpus; request-500 scheduling; test-policy reconciliation; chosen release subset/owner and scoped proof results. GAP-001/079–086. |

The retained [synthetic transcript][tool-test] and 14 loopback tests validate the
capture runner. They do not discharge the native scenario families above.
Run the tool tests from this repository with
`python3 -m unittest discover -s scripts -p test_protocol_capture.py`.

[tool-test]: ../mothra/evidence/gap-remediation/2026-11-12/capture-tooling-01/transcript/report.json

[native-handshake]: ../mothra/evidence/gap-remediation/2026-11-12/native-handshake-01/manifest.json
