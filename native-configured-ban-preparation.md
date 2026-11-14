# Configured-address ban application: control-only preparation

This packet prepares a future single Options > Ban > Save observation for
Hotline Server 1.9. It does not boot the lab or exercise native traffic. The
fixture tests the connected-client notice producer at `10006590`, separately
from request 110 and the stored-ban login predicate.

## Owned image and identity

- Canonical `scripts/mac_runtime.py prepare` copied the immutable
  `hotline22-recovery/base.dsk` (`e5cbbaaf2848…`) and ROM (`18da89e42c7c…`)
  into ignored `mothra/state/mac-runtime/native-configured-apply-01`. The new
  base and working image both hash to `e5cbbaaf2848…` before boot.
- Read-only HFS preflight is in that directory's `preflight.json`: two original
  `UserData` records, 175-byte `Prefs`, no `Banned`, no `Banned.bak`, and no
  `m-ban-apply-only`. The application forks are DATA `ad7040db4eb6…` and RSRC
  `fe83a2cfaacd…`. The prepared image is a new copy, not the C56 banned working
  image.
- Candidate display is `:114`, and frontend ports are `15770–15773`. They were
  free at preparation and require a fresh availability check before any boot.
  The original server's `15500/15501` bridges must remain unused; the isolated
  lab recorder must prove zero primary SYNs.

## Planned traffic and gates

The `native_configured_ban_cases.py` source emits four plans against
`127.0.0.1:15770` inside the owned lab namespace. The existing 18-action C52
readiness gate checks original accounts, 41 Files descriptors, file metadata,
roster and idle barrier without 202/HTXF. Guard `352` must show the new key
absent. Seed creates only `m-ban-apply-only` with eight zero access bytes and
reads it back. A single `held-apply` plan then logs in admin and target, checks
target `354` zero access, current `301` target UID/name, and a two-person
roster with distinct admin UID. All four plans contain no request 110.

The held plan has **23 source actions**: 17 before Options, then `104` and EOF
on each of the two sockets, then both closes. The controller retains one report
whose `completed_actions` must equal the original 23-step source plan. It
retains any bytes after the matched notices through each EOF for later parsing.
publishes `held-ready.json` only after the semantic identity gates pass. Any
readable socket before reviewed Save, including a notice or EOF triggered by
**Add**, aborts the observation. A separate operator may create a
`reviewed-save\n` trigger only after the new checked row and unchanged sockets
have been reviewed; the controller then records the tail. This trigger is an
operator handoff, not proof that Save happened. The later capture must retain
UI input/screenshot timestamps showing the single Save after that handoff. The
expected `104` field 101 is the exact 42-byte permanent-ban text on **both**
sockets because both guest peers use 10.0.2.2. The controller makes no
cross-socket ordering claim, and an admin postflight connection is not assumed
possible.

The reviewed UI sequence is one Options > Ban entry with IP `10.0.2.2`, Info
empty, one Add, inspect checked row, and one Save. The earlier C61 read-only
screenshot establishes the tab, fields, row, Add and Save positions at
1024×768. A24's XTest input helper has exercised `type-public` for ASCII digits
and `period`, with pointer motion flushed for 150 ms; C61's Ban click helper
flushes motion for 100 ms. For this **new** image, input focus and the entered
IP must be confirmed in a fresh screenshot before Add. The Add-before-Save
mutation timing is unknown, so any early notices or EOF end the case without
another Apply. Unknown dialog or text editing behaviour requires escalation
rather than blind coordinates.

## Later live handoff and retirement

Boot, GUI input, and the held TCP controller require a separate live grant. The
controller requires root in the owned namespace to inspect the non-dumpable
emulator `/proc` identity; the emulator remains UID 1000. The future recorder
gate requires live host, namespace and guest captures, actual emulator
PID/start/exe/FD6/netns, empty namespace routes, zero primary SYNs and capture
deadlines covering the whole finite case. Freeze the actual runtime PID in
generated plans. Use the existing managed service profile and global capture
deadline from the parent packet; preserve failed reports without retry.

After the one case, retire only owned units and prove actual emulator PID gone,
owned ports absent, zero primary SYNs and packet drops. Read `Banned`, original
and owned `UserData`, and `Prefs` only from the stopped FD-free image. No
ban-file schema, reload behaviour, expiry, full-file health, or mxd parity
follows from this preparation. The prior C35/C45/C50 full-file failures remain
separate; `fixture_profile=control-only` and `full_file_baseline=not_exercised`
are mandatory.
