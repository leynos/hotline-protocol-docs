# Native 1.9 permanent ban control witness

This witness records one option 2 ban in a disposable native server lab on
14 November 2026. It uses the **control-only** readiness profile. The full-file
A7 baseline was **not exercised** in this lab; the failed C35, C45 and C50
full-file baselines remain part of the evidence. The control result does not
resolve the transfer stall or establish general native-server health.

## Scope and provenance

The
[frozen corpus](evidence/gap-remediation/2026-11-14/native-ban-control-01/manifest.json)
includes the C53 no-contact retirement, C55 boot and recorder readiness, five
C56 as-run plans and captures, six complete TCP lifetimes in both namespace and
guest views, the host primary-port SYN capture, managed unit and teardown
receipts, and the stopped-image `Banned` data fork. `SHA256SUMS` covers every
payload. `packet-views.json` binds each scoped stream and its tail to the
recorder report. The controller ran as root within the owned lab namespace
because inspecting the non-dumpable emulator's `/proc` links required it; the
emulator itself ran as UID 1000.

The source image was copied from the immutable `e5cbbaaf…` base. The native
server DATA and RSRC hashes were `ad7040db…` and `fe83a2cf…`. The owned lab
used frontend `127.0.0.1:15750`; its fixed bridge to primary ports 15500/15501
was present but unused. The host capture recorded zero packets and zero drops
on those primary ports. C55's namespace recorder reported zero drops. C53's
earlier boot had no frontend contact.

## Observed sequence

The 18-action readiness read back two original accounts, 41 Files entries,
fixture metadata and idle behaviour without invoking download 202/HTXF. A guard
proved `m-ban52-only` absent. A seed added exactly one zero-access owned
account and read it back. The root controller then logged in the target,
obtained its UID from a 301 announcement, checked that UID/name against the
current roster and zero effective access, and sent one 110 request with field
113 option 2 and no optional reason field 101.

The target received unsolicited 104 with field 101 equal to the 42 ASCII bytes
`You are permanently banned on this server.` and then the connection closed.
The admin received a successful correlated ACK and a 302 departure. The same
admin connection subsequently read back three accounts, the original account
attributes, 41 Files entries, the fixture metadata and a one-user roster. A
fresh connection completed the 12/8-byte TRTP handshake and sent a valid Login
107 for the owned target. Native returned type 0, ID 1, error 1 and field 100
with the same 42-byte text. This probes the login-stage ban predicate; it does
not assert an EOF deadline.

After capture, the owned emulator and all seven managed units were stopped. The
actual emulator PID was checked gone independently of the generic user-unit
cgroup. The original primary and client disk FDs were unchanged, ports
15750–15753 were absent, and the primary SYN capture remained empty. Only after
the owned image was stopped and FD-free was its `Banned` data fork exported. It
is 49 bytes, SHA-256 `53bec376…`; no `.bak` existed. Its internal format,
expiry, and behaviour after restart are **not established**.

The separate configured-ban application producer at `10006590` still needs its
own 104 fixture. This witness does not close that question or establish option
1 expiry, persistent reload, or complete GAP-044 coverage.

## Offline replay

From the protocol repository with the adjacent Mothra evidence export:

```sh
python scripts/verify_native_ban_control.py evidence/gap-remediation/2026-11-14/native-ban-control-01
python -m unittest discover -s scripts -p test_native_ban_control.py -q
```

The verifier checks the full corpus inventory and hashes, source/runtime
identity, managed capture readiness and terminal state, all five semantic
reports, six paired packet streams and TCP tails, zero primary contact, raw
stopped ban bytes, and the three retained failed full-file baselines. Its fault
controls reject altered identity, target, notice, EOF, readback, fresh Login
107, packet drops, teardown and persisted bytes.
