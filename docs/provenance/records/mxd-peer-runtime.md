# Isolated mxd fixture for a Classic client capture

Status: C14–C19 prepared, started, and stopped one SQLite-backed Wireframe
listener. The [protocol runbook][runbook] supersedes the ignored C13 proposal's
seed-file assumption. The [redacted receipt][evidence] freezes build, seed,
namespace, and service evidence. The separate Classic client attempt is not
assessed here.

This document belongs to the [provenance](../README.md) set; the
[glossary](../../glossary.md) defines the terms it uses.

## Progress and provenance

- [x] Built `mxd-wireframe-server` from clean private mxd
  `cb907885cc2a61df2d708f38a3cf42da85c2a016` with
  `cargo build --locked --offline --bin mxd-wireframe-server`, one Cargo job
  and an owned target cache. Cargo.lock SHA-256 is
  `a75916c2eba9add420b656323df9717c91c052417f2ffcdcf1c95c2787372192`; binary
  SHA-256 is
  `3da44eac362e1a5433eee4cace8f030e383a9c4a8ea8f587055610299c879375`. The first
  build exited 0 in 2m26s; no source was changed.
- [x] Made `state/native-sessions/mxd-peer-c14/` mode 0700 with owned
  HOME/XDG directories. The secret config and database are mode 0600 and remain
  only in ignored local state. The first `create-user` exited 1
  (`missing password`) before creating SQLite: `MXD_CONFIG_PATH` selects
  top-level config but not the independent subcommand file discovery.
- [x] Copied the same secret bytes to the discovered owned
  `home/.mxd.toml` without display. Exactly one authorized retry exited 0.
  Read-only SQLite integrity is `ok`; the users table contains only
  `mxd-peer-c14`. No native admin credential or test-only alice fixture was
  imported.
- [x] Reidentified the isolated client's actual SheepShaver PID 1012834
  through unit, executable SHA-256
  `9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`, FD 6
  working disk, FD 16 guest PCAP, and `net:[4026532479]`. Its route table had
  only a header; namespace and host ports 15650/15651 were free.

## Supervision decision

C17 launched a user service through sudo/nsenter/setpriv. mxd PID 2275040 had
the expected executable hash, UID 1000, zero effective capabilities, and
namespace-local listener, but it and sudo MainPID 2274636 had moved to
`/user.slice/user-0.slice/session-c155.scope`, outside the service's reported
user control group. Readiness was rejected. The approved stop of only that unit
removed both PIDs and port 15650; SQLite SHA-256 and the single user were
unchanged. This one cleanup is not a lifecycle guarantee.

A 20-second root-managed sleep sentinel in the same namespace retained its
MainPID inside `/system.slice/mothra-mxd-netns-probe.service`. Its runtime cap
ended the owned process with `Result=timeout`, exit status 15, and PID gone.
The later C19 service therefore used **system** `systemd-run` with `Type=exec`,
`User=1000`, `Group=1000`, `NetworkNamespacePath=/proc/1012834/ns/net`,
`RemainAfterExit=yes`, `RuntimeMaxSec=20min`, and `Restart=no`. It executed
`env -i` directly, then the pinned binary with the owned database, empty
`daemon.toml`, bind `127.0.0.1:15650`, and ASCII server name `mxd`. No sudo or
namespace wrapper ran inside this unit.

C19 started at 20:54:09 UTC as `mothra-mxd-peer-c19.service`, invocation
`392dbcb6ecda46ed9bc83ef1a0b059bb`. Its actual MainPID 2349333, start-time tick
2795470, was the pinned binary with UID/GID 1000, zero effective capabilities,
exact control group `/system.slice/mothra-mxd-peer-c19.service`, and the
emulator's namespace. The journal recorded the listening line; namespace `ss`
showed only its 127.0.0.1:15650 listener, host `ss` showed no 15650/15651, and
routes were empty. The native 15500/15501 bridges remained active. Readiness is
a server-side receipt; it does not report a client connection or protocol
conformance.

After the separate client step, the supervisor stopped only the C19 unit at
21:02:04 UTC. Its terminal receipt records inactive state, `MainPID=0`,
`Result=success`, actual PID 2349333 absent, and no namespace 15650 listener.
The client capture and interpretation remain separate; no second mxd fixture
run was performed in this packet.

## Verification and next gate

The evidence directory contains redacted commands, build and seed exits,
read-only DB summary, the failed user-unit identity and cleanup, the root
sentinel, and the direct system-unit readiness properties, journal and
namespace sockets. It excludes the secret TOML, SQLite file, and any password
or stored hash. Check its inventory with:

```bash
cd evidence/gap-remediation/2026-11-13/mxd-peer-runtime-01
sha256sum --quiet -c SHA256SUMS
```

For another session, stop only its owned system unit and prove the recorded PID
has gone, namespace/host 15650 are clear, and the native bridges remain active.
Read SQLite in `mode=ro` to check integrity and user count. The client's
observed outcome belongs in a separate capture record. Native high-byte field
162, local 31-byte clipping, banner 212/data transfer, release owner/subset,
and other GAP criteria remain unresolved here.

[runbook]: ../../mxd/classic-client-trials.md
[evidence]: ../../../evidence/gap-remediation/2026-11-13/mxd-peer-runtime-01/manifest.json
