# Classic client trials against an isolated mxd fixture

This document records two Classic Mac client trials against an isolated
`mxd-wireframe-server` fixture, the limits of those trials, and the procedure
for running a Classic peer against such a fixture. The state of the validation
work is set out in the [validation status][validation-status]. The scope and
pinned revisions of the set are in the [README][readme].

## Trials and their limits

### Revisions examined

The identifiers below appear in this document.

| Identifier                                                         | Type           | Stated in                                                                             |
| ------------------------------------------------------------------ | -------------- | ------------------------------------------------------------------------------------- |
| `cb907885cc2a61df2d708f38a3cf42da85c2a016`                         | mxd revision   | [Pin the binary and prepare a new fixture](#pin-the-binary-and-prepare-a-new-fixture) |
| `3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375` | Binary SHA-256 | [Pin the binary and prepare a new fixture](#pin-the-binary-and-prepare-a-new-fixture) |

_Table 1: Revision and binary identifiers used in this document, with the
section that states each._

### Shared trial conditions

Both mxd trials used a separate loopback-only namespace, an owned SQLite
fixture and one manually selected connection (VAL-025). In the 48-character
trial, one Connect click was made, followed by File > Quit (CLG-012).

### Client build identity

The identified client archive is labelled 1.9.2, while its embedded version
resource says 1.9.1.0 (VAL-022). Its fork hashes and the
[isolated native session][isolated-session] identify the tested candidate
(VAL-023), and the session is linked as evidence for that candidate (VAL-026).
Vendor authenticity and a universal version profile are not established
(VAL-024).

### Failed trial with a 48-character password

The first actual Classic Mac client attempt reached the isolated
`mxd-wireframe-server` fixture (CLG-001). That fixture is the C20 workflow set
out in the
[procedure](#procedure-for-a-classic-peer-against-an-isolated-fixture) below
(CLG-002). This attempt is the 48-character trial, and it is the failed trial
(VAL-032).

The client sent `TRTPHOTL00010002` and received `TRTP00000000`, and the
handshake succeeded (CLG-008, VAL-027). It then sent request 107/ID 1 with
fields 105 length 12, 106 length 31 and 160 length 2 (CLG-009).

mxd returned a type-0/reply-marker-1/ID-1 **status-1 empty** reply (CLG-010):
type `0` and status `1` with no payload (VAL-029). The client reported
Connection Closed (VAL-030), and the GUI reported that the connection was
closed (CLG-011). The namespace capture was ready before the attempt and
reported 14 packets, zero kernel drops (CLG-013).

The owned seed password was 48 ASCII characters (CLG-015). Field 106 held only
the complemented first 31 bytes of the password (CLG-016), and login 107
carried only the complemented first `31` password bytes (VAL-028). The full
password was not transmitted (CLG-017, VAL-031).

The truncation to 31 bytes is a measured truncation on this input, with no
evidence whether the UI or encoder imposed it or whether 31 is a universal wire
limit (CLG-018). The 31-byte observation does not distinguish a UI limit from
an encoder limit, or establish a universal wire-password limit (VAL-047).

Authentication failed before successful-login fields 161/162, roster 300 or
banner 212 could be observed (CLG-019). The 48-character trial did not reach
login extras or the roster (VAL-031). This result therefore does **not** test
those mxd behaviours, nor show a login-extras incompatibility (CLG-020).

Unreconciled: this document records the 48-character trial's reply as type 0
with reply marker 1 (CLG-010). The [direct-replies correction][corrections]
states that at the pinned mxd base the normal login route transmitted type 107,
not merely an internal dispatch label (ACK-011). No revision is stated for the
48-character trial in this document, so these two statements are not decided
here.

A future retry needs a newly authorized, owned, shorter-secret fixture and
another bounded one-connect capture (CLG-023). Do not relabel this failed
attempt as a successful Classic compatibility witness (CLG-024).

### Partial startup with a 24-character password

In the separate 24-character fixture trial, all 24 password bytes were
transmitted (VAL-033). Login 107 succeeded with `161=0000` and `162=mxd`
(VAL-034). The UI displayed Connected to: mxd, then remained at Loading
Agreement with zero users (VAL-035). No 121, 300 or 212 request followed
(VAL-036).

mxd has no specialized `DownloadBanner` 212 handler and no evidenced port-15651
data service (PCW-049).

The 24-character trial is a successful authentication and a partial startup
witness, not a completed client session (VAL-037). The trial links to
[redacted evidence][redacted-short] (VAL-038).

Unreconciled: the [compatibility matrix][compatibility-matrix] states that the
ASCII 162 trial reaches login, roster and banner data with all other bytes
unchanged. In this trial, no 121, 300 or 212 request followed (VAL-036). The
matrix links the ASCII 162 trial to a separate record outside this set, and the
[validation status][validation-status] says to complete one identified Classic
startup before claiming roster, banner or general interoperability. These
statements are not decided here.

### Timing deviation in the second observation

The second observation lasted **93 seconds**, exceeding its authorized
30-second settle window (VAL-039). The overrun is retained as a process
deviation; it cannot support a claim of a compliant timed trial (VAL-040).
Future timed observations need an independent cutoff (VAL-041).

### Retained evidence and private replay

The redacted A22 corpus retains one masked-dialog screenshot, failed-login
alert, quit screen, exact control headers and C19 service receipts (CLG-003).
It is linked as the [redacted A22 corpus][redacted-a22] (CLG-004).

Credential-bearing raw PCAPs, the owned secret and seed files remain in ignored
private state, because the login packet contains complemented credential bytes
(CLG-005, VAL-043).

Public metadata alone cannot replay the credential-prefix finding. The
[private verifier][verifier] can (CLG-006, CLG-007).

The public witnesses contain redacted decoded metadata, screenshots and raw
file hashes (VAL-044). They are not complete portable packet proofs (VAL-045).

Private replay checked the password-prefix and full-password comparisons and
host/guest stream parity without publishing the credential bytes (VAL-046).
Guest and namespace application streams matched in the private replay, and no
new native 15500/15501 SYN occurred (CLG-014).

### Teardown after the trials

Both clients were quit, both trial daemons were stopped, and their recorded
PIDs and port-15650 listeners were absent (VAL-042). The
[C20 runtime record][runtime] is linked here (CLG-021, PCW-002). It pins the
first prepared fixture and its observed process identities (PCW-003), and it
confirms that the separate mxd daemon was stopped afterwards and port 15650 was
clear (CLG-022).

## Procedure for a Classic peer against an isolated fixture

The C20 workflow prepares a disposable SQLite-backed `mxd-wireframe-server` for
one Classic Mac client connection (PCW-001). A TCP listener or a successful
login alone does not establish native 1.9 parity (PCW-004). The fixture
workflow retains the offline build, owned config and database setup, and
namespace supervision (VAL-078). This procedure is that fixture workflow
(VAL-089).

### Pin the binary and prepare a new fixture

Use a clean mxd checkout at the accepted revision
`cb907885cc2a61df2d708f38a3cf42da85c2a016` (PCW-006). The explicit
`mxd-wireframe-server` binary uses the Wireframe runtime; the default
`legacy-networking,sqlite,toml` features still compile the separate legacy
binary (PCW-007). The C14 build used the existing private target cache
(PCW-008).

The build command changes into the batch-02-mxd `mxd` workspace, checks that
git diff is clean, and runs the build (PCW-009). As recorded for the C14 build:

```bash
cd /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd
git diff --exit-code && git diff --cached --exit-code
git rev-parse HEAD
target_root=../mothra/state/delegation/mxd-target
CARGO_TARGET_DIR="$target_root" \
  CARGO_NET_OFFLINE=true CARGO_BUILD_JOBS=1 \
  cargo build --locked --offline --bin mxd-wireframe-server
```

Record the revision, Cargo.lock/compiler/binary SHA-256, command, exit and
binary build ID (PCW-010). C14 built in 2m26s (PCW-011), and its binary SHA-256
was `3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375`
(PCW-012). Recheck hashes on every run; this path and hash are an as-run
example (PCW-013).

Create a **fresh** mode-0700 directory below `mothra/state/native-sessions/`,
with `home`, `xdg-home`, `xdg-dirs`, `xdg-data` and `xdg-cache` subdirectories
(PCW-014). Use an absolute SQLite path inside the fresh fixture directory
(PCW-015). Create two empty mode-0600 TOML files, `seed.toml` and `daemon.toml`
(PCW-016). Create a separate mode-0600 `home/.mxd.toml` containing
`[cmds.create-user]` and a random high-entropy ASCII password (PCW-017).
Generate the password into that file without printing it, putting it in an
argv, or copying it to evidence (PCW-018). Use exclusive creation to refuse an
old fixture (PCW-019). The chosen username belongs only to this SQLite
database, and native `admin`/`mothra19` and test-only `alice` are not seeded
automatically (PCW-020).

**Config locations.** `MXD_CONFIG_PATH` selects the top-level `AppConfig` file
(PCW-021). The current `create-user` helper independently searches standard
subcommand paths such as `HOME/.mxd.toml` and does **not** consult
`MXD_CONFIG_PATH` (PCW-022). The initial seed failed because the subcommand
loader searched `HOME/.mxd.toml` separately from top-level `MXD_CONFIG_PATH`
(VAL-079). The first failure is retained as a discovery witness (see
[History](#history)), and the recommended fresh setup puts the secret only in
`home/.mxd.toml` (PCW-025).

**Seeding.** Seed once with the pinned binary and an empty process environment
except for owned HOME/XDG paths, selected top-level config and minimal PATH
(PCW-026). The seed command runs the binary with `--database fixture.sqlite` and
`create-user mxd-peer`, with `MXD_CONFIG_PATH` set to `seed.toml` (PCW-027):

```bash
env -i HOME="$FIXTURE/home" XDG_CONFIG_HOME="$FIXTURE/xdg-home" \
  XDG_CONFIG_DIRS="$FIXTURE/xdg-dirs" XDG_DATA_HOME="$FIXTURE/xdg-data" \
  XDG_CACHE_HOME="$FIXTURE/xdg-cache" \
  MXD_CONFIG_PATH="$FIXTURE/seed.toml" PATH=/usr/bin:/bin \
  "$BINARY" --database "$FIXTURE/fixture.sqlite" create-user mxd-peer
```

Save a redacted command, exit and log. Stop on failure; do not try a CLI
password (PCW-028). Open SQLite with `mode=ro`, run `PRAGMA integrity_check`,
and check that `SELECT username FROM users` returns the single intended user
(PCW-029). Do not publish the database, the secret config or password hashes
(PCW-030).

### Supervise inside the existing client namespace

The fixture runs in the existing isolated client namespace, which the
[isolated runtime guide][isolated-runtime] describes. The general steps for
supervising a service in that kind of namespace are in the
[namespace guide][namespace-guide]. This section keeps the fixture-specific
steps.

Identify the actual isolated SheepShaver process from its managed unit,
executable hash, working-disk file descriptor (FD), guest packet capture (PCAP)
FD and net namespace, as the [namespace guide][identify] describes (PCW-031).
Check that the route table has no nonlocal route and that port 15650 is free in
the namespace and on the host (PCW-032). Do not infer the PID from an old
receipt (PCW-034).

The guest's `10.0.2.2:15650` should map through SLiRP, the user-mode network
stack, to a namespace-local `127.0.0.1:15650` listener (PCW-033). The fixture
does not use or replace the fixed 15500/15501 bridges, and the native bridges
and oracle are kept unchanged (PCW-005, PCW-033).

Start the Wireframe binary **directly** under a fresh system unit, as the
[namespace guide][start-unit] describes (PCW-039). Set `FIXTURE`, `BINARY`,
`EMULATOR_PID` and `UNIT` to the verified absolute paths, the current actual
PID and an unused unit name. The [namespace guide][user-service] explains why a
user service that enters the namespace with `sudo nsenter` is not the form used
here; the history is in [History](#history).

C19 used this form, as recorded (PCW-040):

```bash
sudo -n systemd-run --unit="$UNIT" --property=Type=exec \
  --property=User=1000 --property=Group=1000 \
  --property="NetworkNamespacePath=/proc/$EMULATOR_PID/ns/net" \
  --property=RuntimeMaxSec=20min --property=RemainAfterExit=yes \
  --property=Restart=no --no-block /usr/bin/env -i \
  HOME="$FIXTURE/home" XDG_CONFIG_HOME="$FIXTURE/xdg-home" \
  XDG_CONFIG_DIRS="$FIXTURE/xdg-dirs" \
  XDG_DATA_HOME="$FIXTURE/xdg-data" XDG_CACHE_HOME="$FIXTURE/xdg-cache" \
  MXD_CONFIG_PATH="$FIXTURE/daemon.toml" PATH=/usr/bin:/bin \
  "$BINARY" --database "$FIXTURE/fixture.sqlite" \
  --bind 127.0.0.1:15650 --server-name mxd
```

The command above sets `Type=exec`, `User=1000`, `Group=1000`,
`NetworkNamespacePath=/proc/$EMULATOR_PID/ns/net`, `RuntimeMaxSec=20min`,
`RemainAfterExit=yes` and `Restart=no`, and it runs the binary with
`--bind 127.0.0.1:15650` and `--server-name mxd` (PCW-041). The configured
server name is ASCII at most 31 bytes, and native raw high-byte 162 and
clipping remain separate gaps (PCW-050).

Require `MainPID` to be the actual binary with the pinned hash, running as user
ID (UID) and group ID (GID) 1000, with zero effective capabilities, in the
unit's exact control group and in the emulator's network namespace (PCW-042).
Require the journal's listening line, only namespace-local 15650 listening, no
host 15650 or data listener 15651, and empty nonlocal routes (PCW-043). The
general checks are in the [namespace guide][readiness]. If a check fails, stop
only the newly owned system unit and preserve its logs, and do not connect the
guest until an independently authorized client step (PCW-045).

Stop only the owned system unit, as the [namespace guide][stop-verify]
describes (PCW-046):

```bash
sudo -n systemctl stop "$UNIT"
```

Prove that the recorded PID is gone and that 15650 is absent in the namespace
and on the host, and confirm that the 15500/15501 bridges still run (PCW-047).
Retain a filtered guest-PCAP delta and the unit and identity receipts
separately from the password-bearing fixture (PCW-048).

## History

- C14's first seed selected a password-bearing `seed.toml` alone and exited with
  `missing password` before making a database (PCW-023).
- C16 copied the exact secret bytes into the owned home candidate, and one retry
  succeeded (PCW-024). The corrected owned file supplied the seed secret
  (VAL-080).
- The C17 user service entered the namespace through `sudo nsenter` and then
  dropped privileges (PCW-035). Although it listened correctly, sudo moved both
  its MainPID and the mxd child into a root session control group outside the
  user unit (PCW-036). A stop removed both processes once, but the
  control-group lifecycle was not accepted (PCW-037).
- A root 20-second sleep sentinel then proved that a direct system service with
  `User=1000`, `Group=1000` and
  `NetworkNamespacePath=/proc/<actual-emulator-pid>/ns/net` keeps its main
  process in the unit's control group and enforces a runtime cap (PCW-038). A
  user-service sudo launch put the daemon outside its control group, and the
  accepted direct system service used UID/GID 1000 and `NetworkNamespacePath`,
  with actual PID and group checks and a tested timeout (VAL-081).
- C19 met those readiness conditions (PCW-044).

[validation-status]: validation-status.md
[readme]: README.md
[corrections]: corrections.md
[compatibility-matrix]: compatibility-matrix.md
[isolated-session]: ../peers/mac-peer-isolated-session.md
[redacted-short]: ../../evidence/gap-remediation/2026-11-13/mxd-classic-short-login-01/redacted-witness.json
[redacted-a22]: ../../evidence/gap-remediation/2026-11-13/mxd-classic-login-01/manifest.json
[verifier]: ../../scripts/verify_mxd_classic_login.py
[runtime]: ../provenance/records/mxd-peer-runtime.md
[isolated-runtime]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/network-isolated-mac-runtime.md
[namespace-guide]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md
[identify]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md#identify-the-emulator-and-its-namespace
[user-service]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md#do-not-enter-the-namespace-from-a-user-service
[start-unit]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md#start-the-service-directly-under-a-system-unit
[readiness]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md#check-readiness-before-connecting-the-guest
[stop-verify]: https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/docs/peer-service-in-network-namespace.md#stop-the-service-and-verify
