# Run an actual Classic peer against an isolated mxd fixture

This procedure prepares a disposable SQLite-backed `mxd-wireframe-server` for
one Classic Mac client connection. The [C20 runtime record][runtime] pins the
first prepared fixture and its observed process identities. A TCP listener or
successful login alone does not establish native 1.9 parity. Keep the native
15500/15501 bridges and oracle unchanged.

## Pin the binary and prepare a new fixture

Use a clean mxd checkout at the accepted revision
`cb907885cc2a61df2d708f38a3cf42da85c2a016`. The explicit `mxd-wireframe-server`
binary uses the Wireframe runtime; the default `legacy-networking,sqlite,toml`
features still compile the separate legacy binary. The C14 build used the
existing private target cache:

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
binary build ID. C14 built in 2m26s; its binary SHA-256 was
`3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375`. Recheck
hashes on every run; this path and hash are an as-run example.

Create a **fresh** mode-0700 directory below `mothra/state/native-sessions/`,
with `home`, `xdg-home`, `xdg-dirs`, `xdg-data`, and `xdg-cache`
subdirectories. Use an absolute SQLite path inside it. Create two empty
mode-0600 TOML files, `seed.toml` and `daemon.toml`. Create a separate mode-0600
`home/.mxd.toml` containing `[cmds.create-user]` and a random high-entropy
ASCII password. Generate the password into that file without printing it,
putting it in an argv, or copying it to evidence. Use exclusive creation to
refuse an old fixture. The chosen username belongs only to this SQLite
database; native `admin`/`mothra19` and test-only `alice` are not seeded
automatically.

The two config locations have different jobs. `MXD_CONFIG_PATH` selects the
top-level `AppConfig` file. The current `create-user` helper independently
searches standard subcommand paths such as `HOME/.mxd.toml` and does **not**
consult `MXD_CONFIG_PATH`. C14 first selected a password-bearing `seed.toml`
alone: it exited `missing password` before making a database. C16 copied those
exact secret bytes into the owned home candidate and one retry succeeded.
Retain that first failure as a discovery witness; the recommended fresh setup
puts the secret only in `home/.mxd.toml`.

Seed once with the pinned binary and an empty process environment except for
owned HOME/XDG paths, selected top-level config, and minimal PATH:

```bash
env -i HOME="$FIXTURE/home" XDG_CONFIG_HOME="$FIXTURE/xdg-home" \
  XDG_CONFIG_DIRS="$FIXTURE/xdg-dirs" XDG_DATA_HOME="$FIXTURE/xdg-data" \
  XDG_CACHE_HOME="$FIXTURE/xdg-cache" \
  MXD_CONFIG_PATH="$FIXTURE/seed.toml" PATH=/usr/bin:/bin \
  "$BINARY" --database "$FIXTURE/fixture.sqlite" create-user mxd-peer
```

Save a redacted command, exit and log. Stop on failure; do not try a CLI
password. Open SQLite with `mode=ro`, run `PRAGMA integrity_check`, and check
that `SELECT username FROM users` returns the single intended user. Do not
publish the database, the secret config, or password hashes.

## Supervise inside the existing client namespace

Identify the **actual** isolated SheepShaver process from its managed unit,
executable hash, working-disk FD, guest-PCAP FD, and net namespace. Check its
route table has no nonlocal route and port 15650 is free both there and on the
host. The guest's `10.0.2.2:15650` should map to a namespace-local
`127.0.0.1:15650` listener through SLiRP; it does not use or replace the fixed
15500/15501 bridges. Do not infer the PID from an old receipt.

The C17 user service entered the namespace through `sudo nsenter`, then dropped
privileges. Although it listened correctly, sudo moved both its MainPID and mxd
child into a root session control group outside the user unit. A stop removed
both processes once, but the control-group lifecycle was not accepted. The root
20-second sleep sentinel then proved a direct system service with `User=1000`,
`Group=1000`, and `NetworkNamespacePath=/proc/<actual-emulator-pid>/ns/net`
keeps its main process in the named unit's control group and enforces a runtime
cap.

Start the Wireframe binary **directly** under a fresh system unit. Set
`FIXTURE`, `BINARY`, `EMULATOR_PID`, and `UNIT` to the verified absolute paths,
current actual PID, and unused unit name. C19 used this form:

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

Require `MainPID` to be the actual binary with the pinned hash, UID/GID 1000,
zero effective capabilities, the unit's exact control group, and the emulator's
network namespace. Require its journal listening line, only namespace-local
15650, no host 15650 or data listener 15651, and empty nonlocal routes. C19 met
those readiness conditions. If a check fails, stop only the newly owned system
unit and preserve its logs. Do not connect the guest until an independently
authorized client step.

On completion, stop only the owned system unit:

```bash
sudo -n systemctl stop "$UNIT"
```

Prove that its recorded PID is gone and 15650 is absent in the namespace and
host; confirm 15500/15501 bridges still run. Retain a filtered guest-PCAP delta
and unit/identity receipts separately from the password-bearing fixture. mxd
has no specialized `DownloadBanner` 212 handler or evidenced port-15651 data
service. Its configured server name is ASCII at most 31 bytes; native raw
high-byte 162 and clipping remain separate gaps.

[runtime]: docs/delegation/mxd-peer-runtime.md
