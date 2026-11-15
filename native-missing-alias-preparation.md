# Missing-target alias: positive rehearsal preparation

This packet prepares **M2 only** of Mothra's
`docs/execplans/missing-target-alias.md`. It does not remove a target, run a
native server, or establish the missing-target result. The source files are
`scripts/native_missing_alias_cases.py` and
`scripts/native_missing_alias_control.py`; the latter waits for a separately
reviewed Finder receipt and never sends GUI input or executes receipt text.

## Exact boundary

The third control-only profile used `state/mac-runtime/native-alias-live-03`,
display `:124`, owned session `state/native-sessions/native-alias-live-03`, and
namespace-local `127.0.0.1:15980`. Check identifier availability before
preparation. Before live START, root must validate the prepared ownership and
pin all source, base, ROM, executable and target bytes. The guest sees server
address `10.0.2.15:5500`. Do not contact the original primary server or read a
live working image.

That runtime is now retired. Its target was not selected by the preparation
checkpoint, and no protocol request ran. A mistaken menu selection opened an
empty Broadcast dialog. It was cancelled without Send, but continuing
preparation breached the stop-and-escalate rule. Do not reuse the image or its
pins.
[Retained abort evidence](../mothra/evidence/gap-remediation/2026-11-14/native-alias-prestage-abort-01/manifest.json)
records this deviation and the early retirement. Any further attempt needs a
separately reviewed preparation budget and fresh profile. The earlier
+270-second checkpoint belonged to that retired short-window attempt. A later
packet must name its own reviewed operator checkpoint; the 30-minute R04 packet
used a +600 aim and +1200 hard parent-receipt cutoff. Preserve the hard
>=390-second case-start reserve. Retire a late lab without changing its
deadline or re-pinning Finder metadata.

## Optional alias UI capture window

The source gate accepts one explicit `capture_window_profile` value,
`native-missing-alias-ui-30m-v1`, only with
`capture_window_purpose=native-missing-alias-positive`. Put both fields in the
approved runtime before plan generation. Pass the exact profile through the
root-owned readiness and receipt CLIs as
`--capture-window-profile native-missing-alias-ui-30m-v1`; the controller
selects it from the validated plan. The fixed epoch is at most 1800 seconds.
Each managed recorder and lease must have an actual 2100-second runtime cap;
the lease command must use `sleep 2100`. The live gate re-reads their unit
properties, process and FD identities, and monotonic coverage through the fixed
deadline plus five seconds.

With both fields and CLI options absent, the old 720-second epoch and
900-second units and lease sleep remain in force. Unknown or mismatched
profiles and purposes stop before a protocol socket. This source change does
not start a new lab or alter the 390-second reserve, case duration, request
counts or Finder receipt review. A fresh runtime, operator checkpoint and
managed-unit rehearsal require separate root approval.

The independent, closed control readiness has 18 actions: one TRTP handshake,
one Login107 and five numbered control requests (348, 200, 206, 300, 303). The
additional case has one TRTP handshake, one Login107, then 205, 200, 200, 206
with IDs 10–13. That is two TCP connections, two handshakes, eleven numbered
requests total, one mutation and **zero 500** barriers. The case creates one
`Files/m-alias54-only` directory. No target unlink, transfer, retry or cleanup
request is in M2.

Before boot, root stages only the owned `shared/m-alias54-target` DATA bytes
`alias54-live-target\n` (20 bytes), UID 1000, mode 0600, regular and nlink1. Its
`.finf/m-alias54-target` is exactly 32 bytes: `U54TM54X` plus 24 zero bytes,
with the same ownership/mode/link constraints. Pin parent device/inode and the
complete staged hashes. Before planning/readiness, positively show the Unix
target in Finder without making an alias, then record the **actual** 32-byte
sidecar SHA as runtime `initial_finf_sha256` (lower-case 64-hex). Finder
selection may change flags/position; never reset them for a match. The
coordinator checks that pinned full hash before the first case socket, then
checks target identity and first eight bytes after the Finder receipt. Finder
flags or position may change; file identity and type/creator must remain
stable. Both full hashes remain in the report. Both file `mtime_ns` values are
retained before/after UI and at postflight. Finder may quantize them to whole
seconds; stability is not required, and no date-field assertion is made.

## Reviewed Finder receipt

After the 205 ACK and first 200 readback, the coordinator waits at most 120
seconds for `--operator-receipt`. Begin Finder input only after the managed
unit's flushed JSON READY line shows `awaiting-reviewed-Finder-receipt`, the
exact plan SHA, emulator PID, namespace inode and three numbered case requests.
Bind this line to the active unit and confirm no terminal report; the CLI later
prints a separate terminal JSON line. No READY line means no Finder mutation is
authorized. The operator must use the retained named controls: Finder File >
Make Alias once on the uniquely identified owned Unix target, then Finder Edit
> Copy and Paste once for only the separate alias into the owned HFS Files
directory. No old coordinates or guessed shortcut is authorized. Stop on a
disabled item, unknown prompt, overwrite, ambiguous name or destination. The
receipt has schema version 1, target name/size/SHA, dynamic copied alias
basename hex, destination basename hex, six exact gate booleans, false
unexpected/overwrite prompts, `action_count: 1` for the one Make Alias
invocation, and six screenshot SHA-256 values. The PNGs must be in a sibling
`screens/` directory named `target`, `make-alias-menu`, `alias-result`,
`copy-menu`, `paste-menu`, `destination`. The coordinator checks those bytes;
an example schema generator in the cases module is **illustrative only** and is
never an as-run receipt.

The copied alias basename is learned from that reviewed receipt, not a
predicted Finder default. The second 200 must list exactly that one owned
entry. Positive 206 must be direct status zero, name 201 equal to that entry,
field 205 `U54T (alias)`, 206 `M54X`, and 213 `U54T`, each exactly once. Field
207 is recorded as observed resolved-target aggregate size. It is not asserted
to be 20 or treated as a DATA download. An ordinary copied file, unattached
alias, duplicate field or different metadata fails this gate. The imported 200
decoder itself rejects duplicate same-name rows before the coordinator can send
206; an offline raw-frame test exercises this. M2 acceptance additionally
requires post-retirement HFS Finder alias flag and `alis` ID 0 tying the same
object to the Unix leaf; this live-wire coordinator does not assert that
stopped-image fact.

The supervisor may additionally inspect the copied alias's read-only Get Info
Original field, as bounded in the ExecPlan, to identify the Unix volume and
owned leaf. Save that image and binding receipt separately from the exact six
controller screenshot keys. A resource ID alone or a string search does not
prove the target binding. This adds no Hotline request or unlink authority.

## Commands and limits

After root has approved the runtime and source closure, write a fresh plan:

```sh
python3 scripts/native_missing_alias_cases.py --runtime RUNTIME.json --output NEW-PLAN-DIR
```

The root-owned capture and mutex procedure must produce a current exact
`capture-ready.json` before the case. Run only inside the actual emulator
network namespace as root; `--binary` is the pinned server DATA file:

```sh
python3 scripts/native_missing_alias_control.py \
  --plan-dir NEW-PLAN-DIR \
  --capture-receipt capture-ready.json \
  --operator-receipt OPERATOR/receipt.json \
  --binary PINNED-PEF --output NEW-OUTPUT-DIR
```

The coordinator requires the fixed epoch to have at least 390 seconds left,
caps the case at 210 seconds, and retains all observed frames, events, unparsed
bytes, terminal tails and partial stage on failure. A failure or unknown Finder
state ends this one case; it does not authorize another request or a new image.
The unchanged 18-action control preflight and stopped-image alias extraction
remain separate root-owned steps. Neither this guide nor a green offline test
is permission to start M2 or M3.

The optional [recorded-target decoder](alias-record-v2.md) checks the reviewed
v2 subset after extraction. Its recorded path is one binding witness; positive
native resolution and stopped Finder/resource-map proofs remain mandatory.

## Observed Finder preparation and case refusal

[Retained evidence](../mothra/evidence/gap-remediation/2026-11-14/native-alias-prestage-01/manifest.json)
records this run, its frozen sources and paired captures.

The retained `native-alias-live-02` run reached the pre-stage gate. Those
runtime paths are now quarantined; do not rerun these commands against its
working image. A further attempt requires a new reviewed runtime profile.

After normal server startup, activate an identified Finder window, close only
the identified System 9 window, and use the observed application menu **Hide
Others** to expose the desktop Unix volume. Open the owned HFS Files parent and
Unix volume. Move the identified Unix window by its title bar so both window
titles remain visible, then select `m-alias54-target`. Review fresh screenshots
before each operation; retained coordinates describe one layout and are not a
general automation recipe. No alias, Copy or Paste is needed during this
preparation.

Finder preparation changed the full sidecar SHA from the staged zero-suffix
value `1d0021b6…` to `8f0333df…`, while the target DATA and type/creator guards
passed. This observed change supports pinning actual metadata after selection
rather than resetting Finder bytes. Three screenshot files retain the same
reviewed view; their hashes and the root receipt precede runtime construction
and protocol readiness.

All 18 readiness actions completed, including six numbered requests and their
ordinary baseline 206. Only 367.6 seconds remained, below the required
390-second case reserve. The case was refused: no case marker, 205, alias,
Copy/Paste or alias-target 206 occurred. The native server Quit was observed;
the VM was then stopped before its deadline without an orderly OS shutdown.
This is preparation evidence, not a positive or missing-target alias result.

## R04: selection completed, parent checkpoint missed

The
[R04 preparation](../mothra/evidence/gap-remediation/2026-11-14/native-alias-preparation-04/manifest.json)
used required reflinks for both disks after reviewed cache cleanup. The
isolated 1.9 server started, and actual disk/capture identity gates passed.
Finder displayed the sole Unix target selected with the Files parent visible.
The operator completed that selection before epoch+1200, but the parent's
protected receipt writer ran after the hard checkpoint and refused to write.

The
[retired run](../mothra/evidence/gap-remediation/2026-11-14/native-alias-prestage-abort-02/manifest.json)
sent no readiness or case request: both captures contain zero TCP packets. No
205, alias, Copy/Paste or live-alias 206 occurred. The owned VM was stopped
before its fixed deadline; neither application Quit nor OS shutdown was
observed. Stopped checks retain the two users, five pinned forks and empty
board. Target DATA stayed unchanged; Finder metadata changed at offsets8/13.

This is a preparation abort, not a failed native alias response. A subsequent
packet should consolidate routine, already identified startup/Finder actions
and pre-author the parent's receipt command before boot. Preserve every hard
checkpoint, the case reserve and the separate readiness/case grants.
