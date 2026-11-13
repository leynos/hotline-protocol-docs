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
Use `--guest-pcap state/native-sessions/SESSION/guest.pcap` with a new path to
record the emulated Ethernet boundary as well as a separate host-loopback
capture. The observer refuses existing files and records host wall-clock
timestamps; its location before packet injection does not prove guest receipt.

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
`read_eof`, `pause`, `shutdown_write`, `expect_quiet` and `close`. Connections
have unique lifetime labels, and connect events retain local/peer socket
addresses for packet correlation. `shutdown_write` sends a write-half-close
while preserving reads; later sends on that lifetime are rejected before I/O.
`expect_quiet` succeeds only when its bounded receive window expires without
bytes or EOF. An unexpected byte or EOF is retained as a failed observation.
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

## Recorded native core fixtures

The [native core corpus][native-core] contains 16 identified native transcripts:
14 completed plans and two retained failed close-observation attempts. Its
runtime record identifies the running emulator executable, pinned source/patch,
ROM/base disk hashes, OS 9.0.4 environment and native application data/resource
fork hashes. No ROM or OS disk is included. The generic harness now patches
SLiRP's 32-bit queue allocations on Linux x86-64; the original host crash,
ordinary-malloc negative control and threaded allocation checks remain in
mothra's separate evidence batch.

Run the semantic checks from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_core.py \
  evidence/gap-remediation/2026-11-12/native-core-01
python3 -m unittest discover -s ../hotline-protocol-docs/scripts -p 'test_*.py'
```

The checks cover nonempty credential creation/change, accepted new and rejected
old/plaintext passwords, both observed login paths, representative failures,
plain-input 352 lookup, nested 348 enumeration/permission denial and account-111
storage variants. Their tests also reject a structurally consistent wrong reply
ID and a changed stored password. These are additional to the capture runner's
current loopback tests.

For another native run, prepare the same supplied base disk and exact application
as above, create only the dedicated `admin` / `mothra19` fixture, and keep banner
and server-name options at their initial values. Start a host-loopback packet
capture before replaying TCP plans. Follow `capture_order` in the retained
manifest: account creation, initial login, password change and later rejection
cases depend on that order. Begin with no `fixture-low` account. Replaying the
create case against an existing fixture is not an equivalent run.

Copy each retained `plan.json` to a new state directory, replace its `environment`
with the new run's complete runtime record and identify its operator before
using the capture command. Preserve expected timeout observations as failed;
do not change them to success. Record the native `UserData` after password
update and after each 111 variant. The original records are 734-byte data forks
at `Hotline19/Users/fixture-low/UserData`; 111 has its length at `0x254`, content
at `0x256`, and password length/content at `0x2bc`/`0x2be`.

The initial run used repository-local Sleuth Kit 4.15.0 for read-only HFS+
inspection. On the recorded Fedora 43 host, prepare it without installing into
system directories:

```sh
mkdir -p tools/sleuthkit-rpms tools/sleuthkit
dnf download --resolve --destdir tools/sleuthkit-rpms sleuthkit
(
  cd tools/sleuthkit
  for task_package in ../sleuthkit-rpms/*.rpm; do
    rpm2cpio "$task_package" | cpio -idm --quiet
  done
)
```

The native batch records the downloaded package filenames and SHA-256 values.
These identify the tested binaries; availability of the same packages from a
future Fedora repository is not guaranteed. With its executables/libraries
under `mothra/tools/sleuthkit`, locate
the current catalog record rather than assuming its original number:

```sh
export LD_LIBRARY_PATH="$PWD/tools/sleuthkit/usr/lib64"
tools/sleuthkit/usr/bin/ifind -f hfs \
  -n /Hotline19/Users/fixture-low/UserData \
  state/mac-runtime/hotline19/working.dsk
```

Use `icat -f hfs IMAGE CATALOG_ID-4352-0` for that data fork. Save the password
update record as `fixture-account-after-update.bin` and the three 111 records
as `CASE/UserData.bin` beside their transcripts before running the semantic
verifier. Read after the corresponding operation has finished; a mutable-disk
observation does not prove crash durability. Shut down cleanly before archiving
or resetting a guest disk. Do not commit the full disk or system components.

## Recorded native transport fixtures

The [transport batch][native-transport] retains a final catalogue of 14 addressed
handshake cases, initial explorations and superseded short quiet windows.
The final split-input cases use three-second quiet windows at five byte offsets.
Thirteen final plans completed; the alternate-control plain-TRTP attempt timed
out and remains failed. Root checksums cover both packet views, all retained
transcripts, emulator/source identities and the semantic checks. The 8 GiB
prelaunch disk is retained only under ignored state; its hash and clean-unmount
filesystem report are committed, not the image.

Run the packet/stream and close-order checks from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_handshakes.py \
  evidence/gap-remediation/2026-11-12/native-transport-01
```

To repeat, launch the same native server with a new guest-capture path and start
a separate host-loopback capture before the socket plans. Prepare new plan
copies with the new runtime identity as described for the core corpus. Preserve
local/peer addresses in connect events. The packet verifier matches these to
both TCP views; do not infer tuple identity from a filename or merge reused
socket lifetimes. Stop the host recorder and take a complete guest-capture
snapshot after the planned connections have closed. Keep the original live
capture separately if the emulator continues running.

The analyser accepts complete classic microsecond PCAP Ethernet/IPv4 TCP input,
checks sequence gaps and conflicting retransmissions, and keeps TCP reset
payloads in packet records rather than appending them to Hotline stream bytes.
IP-fragmented TCP requires separate reassembly and is rejected by this analyser.
The recorded wrong-magic reset demonstrates why transport diagnostics must not
be decoded as protocol frames. Preserve guest FIN/RST distinctions even when
SLiRP exposes only EOF to the host socket.

The separate failed-login timing trials retain a 65-second no-close baseline
and an isolated 35-second quiet/new-connection case. Do not run other scripted
guest connections or GUI actions during that quiet window. An earlier overlapping
trial remains explicitly labelled and is not used to establish the isolated
result. These measurements refine observed outcomes, not a general deadline or
proof of a unique scheduling cause. Complete timer and alternate-wrapper
requirements remain open.

## Recorded native framing fixtures

The [framing batch](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json)
contains 62 reviewed sessions and one separately retained disproven icon-width
hypothesis. It includes both packet views, runtime identity and exact capture
driver versions. Run its independent checks from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_framing.py \
  evidence/gap-remediation/2026-11-12/native-framing-01
```

Prepare repeat plans into a new directory with the current runtime identity:

```sh
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py framing \
  --runtime-record state/native-sessions/runtime-05/runtime.json \
  --output state/native-sessions/framing-repeat-plans
```

The generator refuses to overwrite that directory. Its `runtime-05` example is
an existing local record; replace it with the new session's verified runtime
record when relaunching. Run plans with `protocol_capture.py capture` using the
same binary argument and a fresh output directory per case, as in the core
workflow. These cases require the disposable `admin` / `mothra19` fixture account
and naming privilege bit 26. Start both packet observers before recording.
Stop the host recorder after connections close and snapshot complete guest
records, preserving the live guest capture if it remains in use.

Connect UTC time plus monotonic event duration identifies a unique client SYN
within two seconds. Verification rejects ambiguity and scopes each tuple until
its next distinct SYN. A real reused source port in this corpus requires this
lifetime separation. It does not justify merging independently reused tuples.
Retain original failed expectations rather than editing historical reports.

## Recorded native ordinary-file fixtures

The [fork corpus](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/manifest.json)
includes nonempty DATA/MACR and empty-file uploads, raw/control-handover
downloads, preview, noncanonical selector 7 and wrong-collection selectors.
Verify it from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_forks.py \
  evidence/gap-remediation/2026-11-12/native-forks-01
```

Use `prepare_native_cases.py transfers` and then `downloads`, each with the
current `--runtime-record` and a distinct fresh `--output`, to reproduce the
plans. Start packet recording first. Use a disposable native Files root with
neither fixture filename present; repeating uploads onto existing files can
exercise a conflict/resume path instead. Complete both uploads before starting
the download suite. Preserve the uploaded names, INFO embedded name, comments,
type/creator and fixture account configuration as generated.

Using the read-only SleuthKit setup above, locate each result and retain both
forks and catalogue reports. For example, from `mothra`:

```sh
export LD_LIBRARY_PATH="$PWD/tools/sleuthkit/usr/lib64"
tools/sleuthkit/usr/bin/ifind -f hfs \
  -n /Hotline19/Files/mothra-fork-fixture \
  state/mac-runtime/hotline19/working.dsk
tools/sleuthkit/usr/bin/istat -f hfs \
  state/mac-runtime/hotline19/working.dsk 11210
tools/sleuthkit/usr/bin/icat -f hfs \
  state/mac-runtime/hotline19/working.dsk 11210-4352-0
tools/sleuthkit/usr/bin/icat -f hfs \
  state/mac-runtime/hotline19/working.dsk 11210-4353-1
```

Replace catalogue 11210 with the new `ifind` result and save each output to a
separate file. Repeat for `mothra-empty-fixture`. Retain command status and
stderr: an absent zero-length resource attribute is not a successful `icat`
result. The existing fixture retains that distinction alongside catalogue and
native-wire observations. Live-image read-only inspection establishes observed
state, not restart durability; keep disks outside Git.

Read downloads by saved field 108's advertised byte count, then perform the
bounded quiet/cleanup steps. Do not use EOF as the sole successful download
boundary. Uploads do close from the server after consumption. The initial
30-second EOF timeouts remain labelled and retained; corrected plans do not
rewrite them. The verifier also accounts explicitly for the one unread control
301 observed in both packet views.

## Recorded native resume fixtures

The [resume corpus](../mothra/evidence/gap-remediation/2026-11-12/native-resume-01/manifest.json)
retains 23 reviewed cases and seven initial attempts. Run its packet, fork,
offset and failure checks from `mothra`:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_resume.py \
  evidence/gap-remediation/2026-11-12/native-resume-01
```

Begin with the ordinary-file corpus's nonempty `mothra-fork-fixture` and known
fixture account. Prepare `resume-downloads`, `resume-upload-probes` and
`resume-upload-continuations` with `prepare_native_cases.py`, the new verified
runtime record and separate fresh output directories. Start both packet views
before running plans. Download cases only read the existing fixture.

Run upload plans in this order: `resume-upload-seed`, then the partial, missing
and completed probes, followed by `resume-upload-complete`,
`resume-upload-inconsistent-seed` and `resume-upload-inconsistent-complete`.
The two seed filenames must be absent before starting. Save the first seed's
HFS+ DATA/MACR/catalogue outputs **before** the completion plan, then save both
completed files after the final plan. The same `ifind`/`istat`/`icat` commands
above apply, with the new filenames and catalogue IDs. Preserve incomplete
types and raw partial resource bytes rather than attempting to repair them.

`read_frame` supports `match_frame` with `is_reply`, `type` and/or `id` equality.
It retains every intervening frame while waiting for the selected response;
the original action deadline and capture byte cap still apply, with an added
256-frame bound. Saved fields come from the final matched frame. This avoids
treating asynchronous 301/302 notifications as ACKs. Verification independently
redecodes all recorded frames and checks completed matches. Earlier attempts
that expected the next frame to be the ACK remain unchanged.

Malformed RFLT cases use a measured three-second pause followed by request 500
and a matched ACK; they do not assume an invalid input returns a numbered error.
All-ones offsets explicitly expect native EOF without advertised bytes, while
ordinary bounded offsets use advertised count and a three-second quiet window.
Retain the initial timeout/EOF failures and any unread control suffixes with
their complete paired packet evidence.

## Recorded native queue fixtures

Verify the [retained queue corpus](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/manifest.json)
from `mothra` without running its nine-minute native capture again:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_queues.py \
  evidence/gap-remediation/2026-11-12/native-queue-01
```

The queue suite requires the ordinary-file corpus's nonempty and empty files
and its known admin fixture account. In the native server's General Options,
record the existing maximum simultaneous downloads and per-client values,
change them to **2 globally / 1 per client**, save, reopen the dialog and verify
the saved values. Close the dialog before recording. The captured setup used
limits 100/10 beforehand and retained the IP connection limit of 5. Neither
the prior values nor the test values are advertised as protocol defaults.

Prepare `queues` and `queue-timer` with `prepare_native_cases.py`, separate new
plan directories and the current verified runtime record. Include
`queue_test_configuration` with numeric `global_max_downloads` 2 and
`per_client_max_downloads` 1 in that record. Start fresh host packet recording
and retain the continuous guest observer. Run the mode matrix, cancellation
position case and two-owner ordering case sequentially, then the timer case.
Each case cancels its remaining references and closes its control sessions.

The timer plan takes at least nine host minutes: twelve measured 45-second
pauses with a request-500 ACK after each. Those requests exercise a known ACK
path and keep the observed control connection usable; they do not identify a
historical client's purpose or scheduling for request 500. Do not run other
native connections, edit settings or operate the guest UI during this timer
case. Poll the existing recorder process/handle while it runs; an observation
timeout does not authorize restarting the guest or replacing that attempt.

After the cases close, stop the host recorder, snapshot complete guest packet
records and preserve exact unread control suffixes separately from socket
reports. Restore the server's prior General Options limits and retain proof
that the restored values were saved. Keep ROMs, working disks and full runtime
state outside Git. The standalone queue verifier checks packet/stream bytes,
mode/fork outcomes, initial and updated positions, reference ownership and
measured timer windows; screenshots supply operator-visible configuration
provenance rather than replacing the runtime checks.

## Recorded native cleanup fixtures

The [cleanup corpus](../mothra/evidence/gap-remediation/2026-11-12/native-cleanup-01/manifest.json)
contains ten completed captures and independent native fork extractions.
Verify it from `mothra` without the emulator:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_cleanup.py \
  evidence/gap-remediation/2026-11-12/native-cleanup-01
```

Prepare `cleanup-seed`, `cleanup-downloads` and `cleanup-upload` with
`prepare_native_cases.py`, separate new output directories and a current
verified runtime record. This run used the restored 100-global/10-per-client
limits, not the queue fixture's 2/1 limits. Start host and guest recording first.
The files `mothra-race-fixture` and `mothra-214-upload` must be absent before
their seed/upload plans; use a disposable native Files root.

Run the seed, then the full baseline before the other download variants. Keep
all three immediate and all three partial-read attempts even when their byte
counts differ. The nonowner case uses two control sessions; raw transfer and
stale-reference probes use separate data connections. Each case cleans up its
reference and closes its sockets. Run the pending-upload case separately.

Afterwards use the read-only HFS+ commands above to retain DATA, MACR and
catalogue records for both files. The seed's DATA pattern is bytes 0–255 repeated
4,096 times and its resource fork is the existing valid 317-byte fixture.
Stop host recording and snapshot complete guest records after all sockets close.
Keep any unread control suffix separate from the original application report.

Cancellation `read_eof` steps deliberately retain any returned prefix. Do not
require zero bytes or a complete FILP stream after a racing cleanup. Compare
against the complete baseline instead. Keep application receive timing separate
from the guest packet timestamps for incoming 214, outgoing ACK and data/close;
neither timestamp instruments the handler's internal execution instant.

## Recorded native folder fixtures

The [folder corpus](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json)
contains 17 final cases, three initial probes and one auxiliary finalization.
Verify it from `mothra` without rerunning the emulator or timing waits:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_folders.py \
  evidence/gap-remediation/2026-11-12/native-folder-01
```

Use a disposable Files root where the `mothra-folder-*` fixture roots are absent.
Prepare the named suites with `prepare_native_cases.py`, a verified current
runtime record and separate fresh plan/output directories. Record both packet
views. The core sequence is:

1. `folder-upload-fresh` creates the nested source tree.
2. `folder-skip-all` records descriptor traversal without file bodies.
3. `folder-empty-uploads` creates zero-item and final-directory examples.
4. `folder-partial-seed` retains a complete first file and partial second file.
5. Save positive catalogue/fork observations **before** resuming that file.
6. Run the core `folder-downloads` cases, omitting delayed-choice until the
   timed phase. Run `folder-resumed-uploads` in resume, completed-skip and
   directory-conflict order. Retain a before-login failure as an admission
   failure; it is not a folder-worker result. Retry into a new directory.
7. Save after-state, then capture `folder-timed-uploads` and the delayed-choice
   download. This corpus runs the two upload timing plans concurrently on
   distinct roots, followed by the download timing plan. Preserve that overlap
   or document a changed experiment. Keep the core and timed host PCAPs separate.

The auxiliary `folder-flush` suite finalizes a file outside the tested roots.
It was used while investigating failed path enumeration and did not make that
lookup succeed. Its capture is retained separately. One initial unknown-control
capture was paused during extraction recovery and is superseded by a fresh
three-second-window repeat; it is not used as isolated timing evidence.

When path-based HFS enumeration fails, retain command status/stderr and use
positive direct catalogue observations without inventing absent paths. The
bounded snapshot script verifies each returned path before extracting forks:

```sh
python3 ../hotline-protocol-docs/scripts/snapshot_native_hfs.py \
  --image state/mac-runtime/hotline19/working.dsk \
  --tsk-bin tools/sleuthkit/usr/bin --catalog-range 11220 11240 \
  --root /Hotline19/Files/mothra-folder-source \
  --root /Hotline19/Files/mothra-folder-partial \
  --output state/native-sessions/folder-positive-snapshot
```

Catalogue IDs belong to the specific image: adjust the bounded range for another
run, using working `ifind`/`istat` results or positive matches from bounded
catalogue probes. A range with no match is not proof of path absence. The script
caps a scan at 4,096 IDs, refuses existing output directories and retains every
probe/fork exit code. Before/after partial-file bytes matter; an empty output
from a failed resource-fork read is not a successful empty-fork extraction.

The independent decoder treats download control 3 as next-item or file-skip
according to state, and upload control 3 as readiness or a non-file outcome.
It checks per-file BE32 lengths and RFLT values, preserves interrupted bodies
without counting them complete, and distinguishes final-file EOF from the
extra control 3 preceding final directory/skip EOF. Keep images and ROMs local.

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

The retained [synthetic transcript][tool-test] and the current loopback tests
validate the capture runner. They do not discharge the native scenario
families above.
Run the tool tests from this repository with
`python3 -m unittest discover -s scripts -p test_protocol_capture.py`.

[tool-test]: ../mothra/evidence/gap-remediation/2026-11-12/capture-tooling-01/transcript/report.json

[native-handshake]: ../mothra/evidence/gap-remediation/2026-11-12/native-handshake-01/manifest.json

[native-core]: ../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json

[native-transport]: ../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json

## Recorded native banner fixtures

The [banner corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-01/manifest.json)
retains24 final cases and42 exploratory cases, plans, socket reports, paired
packet views, GUI configuration screenshots
and positive native catalogue/fork observations. Reverify it without an emulator:

```sh
python3 scripts/verify_native_banners.py \
  ../mothra/evidence/gap-remediation/2026-11-12/native-banner-01
```

Use `prepare_native_cases.py` with `banner-seed`, `banner-none`, `banner-url`,
`banner-image`, `banner-missing`, `banner-changed`, `banner-absent-restored` or
`banner-expired`, the current `--runtime-record`, and a fresh `--output` directory.
Run each generated plan through `protocol_capture.py capture` with the identified
oracle binary. Record both packet boundaries throughout, as for the folder
fixtures. Plan expectations are hypotheses; a completed capture still needs
semantic and packet verification.

Seed uploads create `mothra-banner-a.gif` and `mothra-banner-b.gif` in Files with
Finder type `GIFf` and creator `MOTH`. Move them beside the native application in
Finder, preserving their data forks, then verify their catalogue paths and bytes
with `snapshot_native_hfs.py`. This run used catalogue IDs11240/11241; discover
and verify the IDs afresh on another image. Do not assume path enumeration works
or claim that these live reads establish restart durability.

In Options > Banner, select Local and enter the **bare filename**, not a full
Mac path. The traced filename helper replaces colons with hyphens; failed full
and relative paths remain in the exploratory evidence. For remote controls,
select Remote before editing URL, since its field is disabled under Local.
Wake the screensaver, foreground the native application, and inspect the dialog
before editing. Verify the saved configuration with subsequent metadata/bytes;
a Save click and a screenshot of an unpainted window do not prove a change.
An early input helper also omitted Shift for colon and typed semicolons; its
original URL bytes and unsuccessful local lookup are preserved.

For `banner-changed`, begin with A loaded and switch to B during the45-second
pause after the212 reply. Preserve UTC phase markers and screenshots. The
`banner-absent-restored` plan begins with B, pauses45 seconds for a nonexistent
filename, attaches and checks three seconds of silence, then pauses45 seconds
for restoration. It sends500 before attempting the restored payload; retain
failures rather than replacing their reports. That earlier recovery plan remains
exploratory; use the phase-confirmed `banner-recovery` workflow below for the
successful retained recovery. The expiry plan maintains owner
traffic across twelve45-second pauses before attempting the old reference.
Any overlapping configuration phases must be disclosed when interpreting it.

The final24 cases pass semantic checks and exact reconciliation in both packet
views. Of42 exploratory reports,33 complete and nine fail; completed explorers
can still have the wrong configuration for their original hypotheses. One failed
quiet check reads only the first byte of a58-byte banner; the remaining57 bytes
are pinned in both packet views. Another probe leaves86 bytes of301/302 control
notifications unread. Both suffixes remain separate from the original reports.
The two host recording phases captured1,558 and103 packets, respectively, with
zero kernel drops. This is not a claim of exhaustive capture outside these
retained boundaries.

Neither ROMs nor OS/working images are part of this corpus. The generic harness
remains in mothra; the protocol-specific plans and verifier remain here.

## Reproducing banner format and recovery fixtures

The [format/recovery corpus][format-corpus] retains 17 final cases, five
original exploratory reports and additional setup observations itemized in its
manifest. The eight new semantic tests check TEXT conversion, zero-type
eligibility, present-empty metadata, recovery phase/timing evidence and
independently observed Finder types. Reverify without the guest:

```sh
python3 scripts/verify_native_banner_formats.py \
  ../mothra/evidence/gap-remediation/2026-11-12/native-banner-02
```

The committed `fixtures/banner` assets contain one-pixel JPEG, BMP, PICT and
PNG files, plus generation/decoder provenance and hashes. No image-generation
libraries are needed to consume the fixed fixtures. `banner-format-seed`
uploads an owned folder of controls, including an extensionless TEXT file and
an empty GIF. Use a fresh working image/checkpoint or fresh fixture names when
reseeding. In Finder, open only that owned folder, select its contents and
move them beside the native application. Confirm each exact catalogue path,
data fork and Finder type with `snapshot_native_hfs.py`; catalogue IDs are
specific to this run. An initial root-filter mistake selected no records and
is retained as an operator filtering error, not evidence of absent files.

Set Local plus the bare filename, then run `banner-jpeg`, `banner-bmp`,
`banner-pict`, `banner-fallback`, `banner-zero-type`,
`banner-suffix-before-finder`, `banner-text-conversion` or `banner-empty`
through `prepare_native_cases.py` and the capture runner. Preserve
screenshots, but use metadata and payload verification as configuration
authority. The empty case has a separate observer session and expects native
service-reset closes. Run it with the other fixtures completed; its resets
affect all observed sessions. The exploratory open-stream and follow-up-ACK
hypotheses remain unchanged.

For `banner-recovery`, first confirm the 58-byte GIF fixture is loaded. Its
owner completes delayed login and receives 122 before requesting the
reference. The separate `banner-recovery-early` variant retains the
early-completion control. During the first six 30-second owner-activity
intervals, select Remote with an empty URL while retaining a valid local
filename. This removes the loaded image buffer. For the early-completion
control, the retained absence instead follows a failed filename load. The plan
uses a separate authenticated 121/500 session to delimit absence before
attaching the old reference. During the next six intervals, restore the valid
local GIF. Another121/500 session confirms the restored metadata before
reading the waiting connection. Preserve both packet boundaries throughout.
Planned pauses and a late application read must not be described as native
delivery latency.

In the retained cleanup, three Save/Return attempts left the old banner active
despite the displayed Remote selection. Those completed recordings remain
exploratory, with their original failed configuration expectations. After an
explicit pointer move and another Save action, the dialog closed and a new121
session confirmed no 122. An additional B-configuration attempt timed out
before its212 ACK; a subsequent baseline positively confirmed122 and size58
before the delayed recovery trial. The captured helper versions and actions
document this run; they do not establish a general GUI timing rule. Verify
each phase through the protocol before calling it configured.

The host recording phases retain712,67 and490 packets, each with zero kernel
drops. All final streams reconcile exactly in both views. One exploratory
post-reset host write contains a 22-byte500 request that never reaches the
guest; the literal suffix is retained separately in
`boundary-differences.json`. It is not a native request-consumption or
error-response fixture. Two unsuccessful delayed setup trials retain57 unread
banner bytes each; literal301/302 control suffixes are also pinned. Accepted
final cases have no unread output. Positive live fork reads do not establish
restart durability, and no ROM or OS/working image is committed.

[format-corpus]: ../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json

## Reproducing HTXF header and reference fixtures

The [HTXF corpus][htxf-corpus] retains 17 observations plus the banner preflight,
both packet boundaries, runtime provenance, three positive native upload-fork
observations and the exact preparation/packaging helpers as run. Reverify the
retained corpus without the guest:

```sh
python3 scripts/verify_native_htxf.py \
  ../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01
```

For another live run, use the committed mothra harness and a new working copy
of your prepared guest. It needs the ordinary-file and folder source fixtures,
admin/mothra19 and fixture-low/next-pass accounts, Local
`mothra-banner-b.gif` with positively confirmed 58-byte delivery, and General
100/10/5 limits. The generator creates `m-htxf-u0`, `m-htxf-u2` and
`m-htxf-u65535`; begin before those uploads exist or adapt owned fixture names
and retain the changed plan. Reusing a completed upload destination is not the
same experiment. Do not use the empty banner fixture for these cases.

From mothra, with a current runtime record and both packet recorders running:

```sh
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py htxf \
  --runtime-record state/native-sessions/NEW/runtime.json \
  --output state/native-sessions/NEW/htxf-plans
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/native-sessions/NEW/htxf-plans/banner-split-15-plus-1.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/native-sessions/NEW/captures/banner-split-15-plus-1
```

Run each generated plan sequentially into a distinct fresh capture directory.
Retain failed hypotheses unchanged. Record and verify the running executable
hash; the recorder's local oracle-file hash alone does not identify the guest.
Stop the host recorder cleanly, retain its packet/drop counts and select the
complete shared time window from the continuous guest PCAP. Reconcile all
streams independently in both views, preserving any unread native suffixes
separately. The retained run captured654 host packets with zero kernel drops
and has no unread output.

Use `snapshot_native_hfs.py` to retain positive exact paths and forks for the
three upload names. Catalogue IDs11280–11282 belong to this run and must be
rediscovered in another guest. Preserve failed resource-attribute reads as
failures, alongside the native resource-size-zero observation. No ROM or
OS/working disk is committed. Quiet windows and owner-pump delays are bounded
observations; data connections carry no authenticated control-session identity.

[htxf-corpus]: ../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json

## Reproducing ID, envelope and partial-input fixtures

The [ID/envelope corpus][ids-corpus] retains24 sessions,25 read-only oracle
queries, two host packet phases and one continuous guest packet window. Each
stream reconciles exactly in both views, with no unread output. Reverify it
without the guest:

```sh
python3 scripts/verify_native_correlation.py \
  ../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01
```

Use the same committed native harness and record the current executable,
application identity, guest environment and server limits. The plans use the
owned admin/mothra19 account and require its early login completion. They need
no file creation, GUI reconfiguration, ROM modification or guest-memory writes.
Prepare fresh plans from mothra:

```sh
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py correlation \
  --runtime-record state/native-sessions/NEW/runtime.json \
  --output state/native-sessions/NEW/correlation-plans
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/native-sessions/NEW/correlation-plans/pipelined-duplicate-id.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/native-sessions/NEW/captures/pipelined-duplicate-id
```

Run each generated plan sequentially into a distinct fresh directory with both
packet recorders active. The same-ID pipeline deliberately puts both physical
frames in one send; the separate-dispatch control pauses three seconds between
sends without first reading the ACK. Scheduling can change a reproduced
interleaving: retain its actual outcome instead of changing the report to match
the expected collision. The mixed-type case checks both the final type and the
first payload prefix through the emitted301 name/icon fields.

The EOF cases first observe three seconds of silence, then half-close the
client write side. Their native FINs follow client FINs. They must not be
represented as server-initiated timeout closes. Late-reply cases instead keep
the connection open and prove liveness with a subsequent complete request.
No mandatory keepalive schedule is inferred from using request500 as a probe.

The retained host phases report416 and68 packets, each with zero kernel drops.
The complete plans preserve initial19, extended20 and final24-case preparation;
source snapshots and the packaging helper are retained. The oracle captures
include the rejected interior-address query and corrected function boundaries.
ID wrap follows the retained PowerPC increment/zero-skip instructions; no live
four-billion-request trial or guest state mutation is claimed. Repeat the
read-only queries using `scripts/capture-ghidra-evidence.py` in mothra with its
repository-local MCP Python and the retained `oracle-*.json` plans. The capture
helper rejects a changed program hash before collecting evidence.

[ids-corpus]: ../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json

## Reproducing native authentication and visibility fixtures

The [authentication corpus][auth-corpus] retains33 accepted reports, two
exploratory reports, both packet boundaries, five positive account UserData
snapshots, the native agreement fork and14 identity-checked Ghidra queries.
Reverify without the guest:

```sh
python3 scripts/verify_native_auth.py \
  ../mothra/evidence/gap-remediation/2026-11-13/native-auth-01
```

Use the committed mothra harness and a fresh working copy of your prepared
guest. Record its current identity and configuration. This run uses the owned
admin/mothra19 account, configured TEXT agreement, Local58-byte GIF and
General100/10/5 limits. Verify guest absence with admin352 before creating a
temporary guest; never overwrite an existing user's guest/account policy.
The `m-auth-*` account names must also be unused. Sequence the suites below
through `prepare_native_cases.py` with the current `--runtime-record` and
separate new output directories, then run each generated plan through
`protocol_capture.py capture` with the identified oracle binary:

1. `auth-seed`: creates owned CR/high-byte/31-byte/bypass controls. The32-byte
   creation/readback failures are intentional recorded outcomes, not a seeded
   valid32-byte account. Keep the original guest352 failure.
2. `auth-missing-guest`: capture absent/empty/explicit guest failures.
3. `auth-guest-create`: create the temporary empty-password, zero-privilege
   guest and verify352 readback.
4. `auth-lookup`: capture case/CR/high-byte/NUL/length and configured-guest
   outcomes. Preserve failed hypotheses rather than changing old reports.
5. `auth-states`: run observer/subject cases sequentially with no other
   scripted peer overlapping. Snapshot the five owned account records and
   native Agreement.txt using `snapshot_native_hfs.py` before cleanup.
6. `auth-cleanup`: remove only the five owned accounts and verify352 failures.
7. `auth-reauthentication`: run the final isolated admin-only controls after
   cleanup; these do not depend on the temporary accounts.

The generator uses `auth-pass` for owned non-guest accounts and no password
for its temporary guest. Account bitmaps and native record fields are checked
separately from login ACKs. Native catalogue IDs11283–11292 and11184 are run
specific; rediscover exact paths in another guest. Failed resource-attribute
reads remain recorded as failures. Native agreement245 bytes become242 loaded
bytes through TEXT CRLF normalization. No ROM or OS/working disk is committed.

Keep host and guest packet recording active for all phases. This run retained
1,151 host packets with zero kernel drops. One28-byte302 tail follows the final
repeated-login roster snapshot and stays separate from the application report.
The original30-second recovery timeout and a completed cleanup-overlap trial
remain exploratory. Neither timeout nor completion alone certifies its original
hypothesis. The final isolated retry observes three seconds of silence; it does
not establish a universal session-recovery policy or cleanup deadline.

[auth-corpus]: ../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json

## Reproducing agreement configuration and partial-failure fixtures

Use the running native server and independently identified oracle described
above. Capture both host and guest boundaries throughout. The retained
[agreement manifest](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json)
separates accepted cases, setup controls and exploratory hypotheses. Preserve
each report and plan in a new output directory; never overwrite a failed trial.

Prepare `agreement-preflight` before `agreement-seed`. Check the 352 failure
before creating the owned `m-auth-bypass` account. Seed uploads the original
seven controls through 203; `agreement-stages` additionally prepares separate
folders with exact-name children, including a directory child. For example,
from the mothra checkout:

```bash
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py \
  agreement-stages \
  --runtime-record state/native-sessions/runtime-15/runtime.json \
  --output state/agreement-stages-new
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/agreement-stages-new/stage-agreement-text.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/agreement-upload-new
```

Run each selected upload plan once. The folder transfer creates
`Files/m-agr-<phase>/Agreement.txt`; move that child into the application folder
through Finder. Back up the original first. Between configurations remove only
the owned replacement; preserve the original backup and existing server files.
Reload once from the active native server window, acknowledge an oversized-file
warning where applicable, and retain the screenshot/log diagnostic. Verify the
exact positive native path, type and fork bytes with `snapshot_native_hfs.py`
before accepting a phase. A completed GUI script or protocol upload is
insufficient. Finder retyped the BINA control as TEXT in one trial; the accepted
non-TEXT controls use BMP and verify that installed type.

Prepare `agreement-<phase>` using fresh directories for original, absent, text,
empty, directory, text-limit, text-over-limit, nontext, nontext-over-limit,
nontext-field-over-limit and restored. Most produce four state cases; the
oversized-field phase produces two distinct partial-failure probes using a
bypass observer. Its delayed case observes three seconds of silence, sends 500,
then reads EOF. Its early case observes silence then checks 500 ACK, online
replay errors and visibility. Do not substitute an immediate-EOF assertion.

Use the retained original agreement to prepare restoration, with a hash guard:

```bash
agreement_evidence=evidence/gap-remediation/2026-11-13/native-agreement-01
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py \
  agreement-restore-stage \
  --original-agreement "$agreement_evidence/original-agreement.data" \
  --runtime-record state/native-sessions/runtime-15/runtime.json \
  --output state/agreement-restore-new
```

Upload that stage, move the child into place and reload. Verify 245 stored TEXT
bytes and 242 bytes in 109; run all four restored cases before
`agreement-cleanup`. Check 351 success and the following 352 error. The owned
fixture files may remain in the Files area or Trash; their presence is not an
account-cleanup or restart-durability result.

For offline verification from adjacent clean exports:

```bash
python3 ../hotline-protocol-docs/scripts/verify_native_agreements.py \
  evidence/gap-remediation/2026-11-13/native-agreement-01
```

The verifier checks planned transitions, exact notices, native types/forks,
observer visibility, literal unread tails, account cleanup and paired TCP
streams. The corpus retains the preparation scripts as run and the original
runtime record. Its host timer recovery is recorded separately; no guest
memory or register changes were used, and no ROM or working disk is required
for offline verification.

## Reproducing login-extra configuration and refresh fixtures

Use [native-login-extras-01][login-extras] with the same identity checks and
paired boundaries as the earlier corpora. Its final source plans are generated
by `native_login_extras_cases.py`; all UI, input, flush and packaging scripts
are retained as run. Preserve every failed report in a new directory.

Prepare `login-extras-name-a`, `login-extras-name-b`, `login-extras-name31`,
`login-extras-name32`, `login-extras-macroman`, `login-extras-url`,
`login-extras-none` and `login-extras-restored` for their corresponding recorded
GUI phases. Name A and restored phases exercise both readiness paths at absent,
zero,150,151 and 190 client versions; the other phases exercise 190. The explicit
three-second pauses pace independent sessions and retain 500 liveness replies.

```bash
python3 ../hotline-protocol-docs/scripts/prepare_native_cases.py \
  login-extras-name-a \
  --runtime-record state/native-sessions/runtime-16/runtime.json \
  --output state/login-extra-plans-new
python3 ../hotline-protocol-docs/scripts/protocol_capture.py capture \
  state/login-extra-plans-new/name-a-absent-delayed.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/login-extra-case-new
```

In native Options, Info's Name field supplies 162. The controls use
`mothra-name-a`, `mothra-name-b`,30 `N` bytes followed by `A`, then a 32-byte
attempt of 30 `N` bytes followed by `BZ`. Only the tested 31-byte prefix is stored.
The high-byte fixture types `mothra-`, then Mac Option-U followed by `o`, yielding
native byte `9a` in this guest. Verify the actual stored and wire bytes; do not
assume a host Unicode key or clipboard injection produces the same input.

The lifetime suite starts under name A, holds an online and a waiting session,
then pauses 20 seconds. Save name B within that interval using the retained fast
input helper; afterward a fresh login must see B and waiting 121 must complete.
The initial 90-second hypothesis is a separate failed trial with late 121 after
native close. Do not substitute its host send for proof of guest consumption,
or require its waiting session to survive without new evidence.

Remote URL uses `https://example.invalid/extras-url`; no banner uses an empty
Remote URL. Local restoration selects `mothra-banner-b.gif`, preserves its link
and clears both Info Name and Remote URL. The banner-reference suite
`login-extras-downloads` runs with name B and the original Local GIF. It reads
exactly the advertised 58 bytes, observes three seconds of silence and closes
the data channel; an immediate-EOF assertion was disproved and retained.

Before accepting configuration evidence, run the retained
`flush-preferences.py` acquisition helper: it finalizes an independently named
empty 203 upload in Files, exercising the known native FlushVol path. Then
snapshot catalogue 11202 at `/Hotline19/Prefs` with `snapshot_native_hfs.py`.
The configuration decoder checks version 5, the fixed 76-byte prefix and ten
bounded Pascal strings. The fourth is the server name; the banner fields and
General limits are checked too. An unflushed snapshot with stale fork length
is retained and explicitly rejected, not repaired or promoted to a positive
configuration record. These catalogue numbers belong to this guest and must
be independently discovered for another installation.

The final snapshot must match the first retained 175-byte empty-name Prefs;
verify original agreement 242 loaded bytes and the valid 58-byte Local GIF.
This proves the recorded configuration restoration, not restart durability or
an independently captured prelaunch preference file.

```bash
python3 ../hotline-protocol-docs/scripts/verify_native_login_extras.py \
  evidence/gap-remediation/2026-11-13/native-login-extras-01
```

The verifier checks 34 accepted cases plus 11 setup and five exploratory reports.
It verifies equal paired streams for 49 reports and explicitly checks the
90-second trial's late input and guest-only cleanup boundaries. Seven new tests
reject missing/UTF-8-reencoded 162, wrong version gating, invented refresh,
truncated preferences and reduced configuration inventories. The retained
byte-store discovery remains candidate evidence; it cannot establish field 161's
meaning or exclude aliases. That requirement remains GAP-026.

[login-extras]: ../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json

## Reproducing full historical shx sessions

The [full peer guide](identified-client-source.md#reproducing-and-checking-full-peer-sessions)
links the frozen build, five accepted plans and exact executable identity.
Build through `mothra/scripts/build-shx.py` using repository-local dependencies.
Launch through `scripts/capture_shx_session.py`, with a new capture directory,
the matching peer profile and the native oracle file. Keep host and guest
packet recorders active across the session, including the data port for forks.

The legacy `/quit` path always saves `~/.hxvars`, even with `-q`. The contained
driver supplies a private repository-backed home, records the real file's
before/after identity and fails if that identity changes. Its raw terminal,
strace output and process exit must remain together. The initial uncontained
probe truncated an existing real file; earlier contents remain unverified.
No guessed restoration is part of this workflow.

For ambiguous-byte receive, run the retained controlled witness plan alongside
the historical peer plan. The witness pauses before sending, allowing the peer
to complete login. Verify the sender's 105, native 106 and receiver's raw
`stdout.bin`; an output regex or escaped `stdout.txt` alone is insufficient.
For download completion, compare the actual files under the private `work/`
directory with both FILP forks and the known fixture. Do not replace that check
with a terminal progress message. Record untested fields and optional build
features explicitly before changing any compatibility policy.

## Reproducing banner and roster-subject receiver fixtures

Use `scripts/serve_shx_fixture.py` with an explicit mode: `control`, `banner`,
`subject` or `banner-subject`. Supply the retained evidence directory and a new
output directory. Its readiness file identifies localhost15510; verify that the
specific listener process is still live before starting the contained peer.
Use the matching retained receiver plan, including explicit `/who -r` and chat
after fixture delivery. The as-run coordinator is retained in the
[second peer corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/sources/run-receivers.py.as-run.txt).

Record host-loopback packets for15510 and retain listener events alongside peer
syscalls/terminal output. The listener replays retained native bootstrap/banner
frames and optionally adds the selected SynHX field115shape to roster replies.
Its profile is `controlled-receiver-fixture`, never native-oracle execution.
Require exact banner `hx.dump`, expected subject output and subsequent chat,
not merely a process that stayed open. These cases have no guest connection.
Run native configured162sessions separately with positive Prefs/ACK controls,
then restore and compare the full baseline Prefs bytes. The independent offline
verifier checks both groups without conflating their provenance.

## Reproducing directory creation and path fixtures

Use the `mkdir-seed`, `mkdir-create`, `mkdir-final`, `mkdir-cleanup` and
`mkdir-root-empty` suites in `scripts/prepare_native_cases.py`. Supply a current
runtime record and new plan/output directories; execute through
`protocol_capture.py` with the verified oracle input. The
[retained corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json)
includes exact plans, as-run generators, ten read-only identity-checked Ghidra
queries and independent packet/catalogue controls.

Preflight requires no owned `mothra-fs19` root or `m-fs19-` markers in the Files
listing. Seed creates the private directory tree and one ordinary-file conflict
target. Run creation cases in generator order: later literal dot, colon,
high-byte and NUL-component traversals depend on earlier directory creation.
Each case records listings before and after creation, the 205 reply, a 500
liveness reply and one measured second of silence. Preserve bytes rather than display-decoded
filenames; one NUL byte is a tested nonempty name.

Finalization uploads an independent empty file to invoke the known native
volume-flush path, then retains the final directory and 206 views. Take bounded
read-only HFS catalogue observations before cleanup. Native 204 cleanup moves
only the owned root, marker directories and flush file to Trash; it does not
recursively erase them. Retain positive post-move catalogue IDs and child bytes,
and compare the complete Files listing with pre-seed. Capture the six root/name
absence/empty combinations separately after cleanup. Existing Trash names can
trigger native collision naming in a later run; retain that outcome and new
catalogue IDs rather than reusing the frozen run's paths or treating a missing
positive probe as absence.

The frozen semantic verifier checks 47 creation/path cases plus six supplemental
root inputs, all 51 reports/53 sockets, native setup/cleanup and byte preservation.
Run from mothra:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_mkdir.py \
  evidence/gap-remediation/2026-11-13/native-mkdir-01
```

The two literal host recordings are retained with their statistics and exact
chronological concatenation. Keep guest Ethernet capture active throughout both
phases. These 205/202 fixtures do not settle field 212/325 equivalence, aliases,
protected-object deletion or platform variants.

## Reproducing alias and metadata fixtures

The `alias-seed`, `alias-create`, `alias-info`, `alias-download`, `alias-damage`,
`alias-supplementary` and `alias-cleanup` suites prepare the
[retained alias observations](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json).
Use new output directories, a current runtime record and both packet recorders.
Preflight the complete Files listing: `mothra-alias20` and the three
`m-al20-absent`/`m-al20-empty`/`m-al20-zero` marker names must be absent. These
fixed names identify an owned tree; do not run against somebody else's entries.
The permission controls require the previously verified zero-privilege
`fixture-low` account with its recorded password; this suite does not create or
change accounts.

Execute seed, creation cases in generator order, info, downloads, damage and
supplementary cases in that order. Preserve exact plans and raw report statuses.
Creation cases depend on earlier A/B aliases. The damage suite tests a repeated
alias destination and an additional chain; its name does not establish damage
or a deleted target. Supplementary cases cover collision download, unattached
rejection, directory comments and a final independent empty upload to exercise
the known volume-flush path.

Take positive catalogue/fork observations before cleanup. Run owned cleanup,
retain its ACKs and compare the complete Files wire listing with baseline.
Bound disk claims to actual positive probes: this run's immediate post-move view
had only three positive Trash objects. Do not label missing catalogue probes
as absence or claim full disk persistence from successful ACKs.

The initial file download timed out after receiving its complete advertised
FILP body while waiting for EOF. Retain that failed report separately. Current
ordinary-download plans read the exact advertised size, measure three quiet
seconds, cancel through 214, then require EOF and control liveness. These plans
test resolved bytes and bounded close behaviour, not universal completion.

This run required a new guest. Verify the old process and forwarding ports are
actually absent before preparing a copy of its stopped disk. Preserve the old
image, hash the new base, and record that a stopped image may be unclean. Native
Disk First Aid reported completion on the new copy; the record does not identify
the old exit's cause or specific filesystem repairs. Record the actual running
emulator hash: this run uses the timer patch, unlike the earlier directory run.
Never export ROMs or working disks as evidence.

Run the independent offline verifier from mothra:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_aliases.py \
  evidence/gap-remediation/2026-11-13/native-alias-01
```

It reconciles 45 reports/66 sockets, checks exact generated plans for the 44
completed reports, retains the failed EOF observation, and checks the native
metadata/listing/creation/transfer effects against positive physical forks.

## Reproducing rename and comment fixtures

Use `metadata-preflight`, `metadata-seed`, `metadata-mutations`, `metadata-final`,
`metadata-boundaries` and `metadata-cleanup` through the existing plan preparer
and native capture driver. Supply a current runtime record and unused output
paths. The [frozen metadata corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json)
records the complete plans and paired packet evidence.

Before seeding, require the Files listing to lack `mothra-meta21` and verify
that 352 reports no account for `m-meta21-comment`, `m-meta21-rename` and
`m-meta21-neither`. Abort if any owned name already exists. The seed creates
only those accounts and the private tree. Verify all creation ACKs and account
privilege readbacks before running the 36 mutation cases in generator order.

The final suite reads all resulting objects through an administrator session
and performs an independent upload to invoke the known native flush path.
Boundary cases then write 0/1/198/199/200/201/254/255/256/300/65,535-byte comments
to two owned objects. Retain readback sizes separately from any claim about
native storage or restart durability. A one-second quiet window is measured
for mutation cases; it does not prove all possible notification timing.

Cleanup moves the owned tree to Trash, deletes the three owned accounts with
complemented 351 login bytes, and checks raw 352 lookups for absence. Verify the
complete Files listing matches preflight. The frozen run's first cleanup
mistakenly used raw 351 bytes, leaving explicit errors and positive account
readbacks. It is preserved unchanged, followed by successful corrected
`metadata-account-cleanup` recovery. The current regular cleanup is corrected;
recovery is only needed when owned accounts actually remain.

The `metadata-combined-empty` suite adds six independent administrator cases
for empty-name/new-comment, both-empty and new-name/empty-comment combinations,
for files and directories. Preflight all `m-m21-` names from the generated plans
before execution. Each plan creates one owned entry, observes the mutation,
moves it to Trash, and requires exact Files listing restoration. Do not reuse
another operator's existing entries or treat ACK status as sufficient cleanup.

Run from mothra without a live guest:

```sh
python3 ../hotline-protocol-docs/scripts/verify_native_metadata.py \
  evidence/gap-remediation/2026-11-13/native-metadata-01
```

The verifier checks all 49 reports/72 socket lifetimes, exact as-run plans,
partial effects and independent administrator views. Literal recorder files
retain the original account-cleanup mistake and subsequent recovery, rather
than presenting an edited successful transcript. No historical client is run.
