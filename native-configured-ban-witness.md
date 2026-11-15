# Hotline Server 1.9 configured-address ban application

This control-only fixture observes the connected-client notice path when an
administrator adds `10.0.2.2` in Options > Ban and saves once. The
[portable corpus](../mothra/evidence/gap-remediation/2026-11-14/native-configured-ban-01/manifest.json)
contains the original plans, as-run captures, paired TCP streams, screenshots,
process and capture receipts, and stopped-image readbacks. Replay it offline:

```sh
python scripts/verify_native_configured_ban.py ../mothra/evidence/gap-remediation/2026-11-14/native-configured-ban-01
python -m unittest discover -s scripts -p test_native_configured_ban_witness.py
```

## Boundary and setup

The first C65 display call used the existing runtime directory as its display
output. It raised `FileExistsError`; no VM, guest PCAP, or frontend contact
followed, and the image remained unchanged. C66 used a separate new display
directory. The lab then booted from the immutable `e5cbbaaf…` base and
`18da89e4…` ROM, with the `ad7040db…` DATA and `fe83a2cf…` RSRC application
forks. The actual emulator was PID 600782, starttime 5595993, in its own
loopback-only namespace; FD6 was the owned image and FD16 the guest PCAP. The
host primary-port recorder began before boot. Its PCAP remained a 24-byte
header: no SYN to original ports 15500/15501. Its packet drops and the lab
namespace recorder's drops were zero. A finite managed oracle lockholder had
the expected busy flock, and the capture gates covered the fixed case deadline
plus five seconds.

The fixture profile was `control-only`; `full_file_baseline=not_exercised`.
Readiness used the original 18-action short metadata/auth/roster/idle check,
not the 29-action A7 full-file test. Guard 10 actions found the owned key
absent. Seed 12 actions created only `m-ban-apply-only` with zero access and
read it back. The held 23-action plan authenticated admin and target, checked
current `301` UID/name, zero `354` access, and two distinct roster UIDs. Both
connections remained quiet before Save. No request 110 was sent.

## One Add and Save

The C66 UI rehearsal showed an empty Ban list, typed `10.0.2.2` in IP with
empty Info, and used Cancel without Add or Save. During C67, one Add produced a
checked `10.0.2.2` row; the held two sockets stayed quiet. The root-reviewed
trigger and one Save followed at 04:50:49 UTC. The corpus separates the trigger
timestamp, UI click receipt, and first notice timestamp; a trigger alone does
not prove Save occurred.

After Save, **both** connected clients received a type 104, marker 0, reply
flag 0, error 0 notice containing field 101 with exactly the 42 ASCII bytes
`You are permanently banned on this server.` Both then reached EOF. The
23-action recorder completed, and both the generic capture verifier and fixture
outcome gate accepted its raw events. Complete SYN-scoped namespace and guest
TCP lifetimes agree byte for byte for five connections across all four phases,
including both held sockets and their tails. The source plans, reports, source
hashes, and PCAPs remain in the corpus; the offline verifier checks their
inventory, identity, timing, outcomes, and paired bytes. The parent approved a
270-line test cap in place of 240 to retain all 16 semantic fault controls
after formatting; the source and corpus caps did not change.

The retained C67 oneshot had `MainPID=0`, `Result=success`, and
`ExecMainStatus=0`; it was terminal, not a live process. Only that owned unit
was then stopped, with its earlier exit receipt preserved. The native server
was quit, then the actual emulator required an owned-PID termination because
the generic user unit did not reliably supervise it. This was forced emulator
retirement after server Quit, not an orderly Mac OS shutdown. The PID, ports,
and managed units were gone; the original primary and client identities were
unchanged. Stopped FD-free image checks found the two original UserData records
unchanged, one owned record, unchanged 175-byte Prefs, and a 49-byte Banned
file (SHA-256 `671c8164…`). The stopped working image was `bd8ddf21…`.

## Limits

This proves the configured-address Save path emitted matching connected-client
notices and closed both clients in this one isolated control fixture. It does
not establish the Banned file schema, expiry, reload, post-ban Login 107,
universal source-address behaviour, or full-file health. The earlier C35, C45,
and C50 full-file baseline failures remain separate. No native producer stall
explanation follows from this small control fixture, and the connected client
producer's broader behaviour remains untested.
