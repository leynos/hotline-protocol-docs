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
failures rather than replacing their reports. The expiry plan maintains owner
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
