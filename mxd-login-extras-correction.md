# mxd successful Login107 extras correction

Status: accepted in canonical mxd by exact fast-forward from
`20e891a059de7dd9dec5a657d7099570987d860d` to
`cb907885cc2a61df2d708f38a3cf42da85c2a016`. The
[canonical import receipt][import] records the 28-blob comparison and passing
live verifier. The [portable C11 acceptance corpus][evidence] pins the source
snapshots, patch, red witnesses, controlled full gate and retained service
exit. This note updates the reconciliation record; it does not close GAP-085 or
select a release owner or subset.

## Native baseline and corrected mxd behaviour

The Mac 1.9 client, identified shx client and historical SynHX source share
handshake sub-version 2. It is an observed framing fact, not a unique peer
identity. A reported Login field 160 is also an observed value. The native
server's successful Login107 direct ACK includes server version 190 in field
160 and opaque two-byte `0000` in field 161 for absent, 0, 150, 151 and 190
reported versions. A configured nonempty server name appears in 162; an empty
name omits 162. Failed Login ACKs receive no success extras. See the
[native captures](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh)
and [identified client sessions](identified-client-source.md).

mxd now preserves raw handshake and reported-version facts without using them
to infer peer identity or suppress success fields. All peers use the same
default authentication strategy. The router retains the original Login107
request kind even though its direct ACK uses wire type 0; augmentation still
requires marker 1, type 0 and status zero. It emits raw two-byte field 161 and
field 162 when a configured name is nonempty. Correlated IDs, failed replies
and nonlogin ACKs retain the
[direct reply correction](mxd-direct-ack-correction.md). The existing outbound
XOR path transforms field 162 after router augmentation on connections with XOR
enabled; it leaves field 161 unchanged.

The `--server-name`, `MXD_SERVER_NAME` and configuration-file value resolve
through OrthoConfig. The resolved product default is `mxd`. Rust's
`AppConfig::default()` retains the repository's derive convention and has an
empty `String` for this field; direct programmatic construction must set it
explicitly. The wireframe bootstrap validates configured names before the
listener starts: only ASCII bytes of length at most 31 are accepted. An empty
name omits 162; a 31-byte ASCII name is emitted intact. Non-ASCII and longer
names are rejected rather than transcoded or truncated.

This is a declared mxd configuration limitation. The native 1.9 fixture retains
raw byte `9a`, and a 32-byte typing attempt stores its first 31 bytes. Neither
raw high-byte representation nor native local clipping is reproduced by this
mxd setting. Field 161's purpose remains unknown; its exact two-byte value does
not establish a banner download reference.

## Acceptance and replay

Two router tests failed before production changes: the old field 161 was four
bytes, and sub-version 2 suppressed it. Final focused router, policy, config,
CLI and BDD checks passed. `make check-fmt`, `make lint`, and Markdown gates
passed. A managed, retained `make test` unit passed all seven nextest profiles
and both doctest groups with a fresh owned PostgreSQL root,
`NEXTEST_TEST_THREADS=2`, offline dependencies, one Cargo build job, and the UI
target's layout override. The corpus records one verification skip and four
ignored mxd doctests. This proves the controlled execution; the cause of an
earlier default-parallelism PostgreSQL startup failure remains unknown. Kani
source was updated but Kani was not run, so there is no new proof claim.

From an adjacent two-repository export, run:

```bash
python3 hotline-protocol-docs/scripts/verify_mxd_login_extras.py
python3 -m unittest discover -s hotline-protocol-docs/scripts \
  -p 'test_mxd_login_extras.py'
```

The default verifier reads only the exported protocol-docs and mothra
repositories. `--mxd /path/to/mxd` additionally checks exact mxd HEAD, tracked
cleanliness, the 28 changed source files, and the base-to-commit patch. It
tolerates untracked local directories. Four unittest controls include the
baseline and checksum-consistent source, unit-exit and count forgeries; each
forged corpus fails for its semantic mismatch.

GAP-018/019/026/080/081/082/085 and the release owner/subset remain subject to
their own acceptance criteria. No new native client or Ghidra query ran for
this correction.

[evidence]: evidence/gap-remediation/2026-11-13/mxd-login-extras-01/manifest.json
[import]: evidence/gap-remediation/2026-11-13/mxd-login-extras-import-01/manifest.json
