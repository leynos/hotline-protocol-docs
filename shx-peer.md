# Historical shx peer build and capture

The repository retains shx 0.1.48 source at commit
`adb1bf8c8cb12f7eb2fa2c01673295a6312f262b` and a repeatable modern Linux build.
This identifies a build of historical source, rather than an original
historically distributed executable. The recorded profile is terminal UI, IPv4,
HFS/CAP forks and fork-based transfers, without GTK, HOPE, cipher or
compression. Other profiles require separate evidence.

The frozen
[build inputs](evidence/gap-remediation/2026-11-13/shx-build-01/inputs.json)
include the complete source archive, license notices and modern GNU host
identification helpers. The [compatibility patch](patches/shx-modern-c.patch)
replaces four obsolete GCC cast-as-lvalue expressions with explicit pointer
advances in cached file-list traversal/rendering. Login callback, handshake,
wire constants and serialization code are unchanged.

## Local dependencies and build

On this Fedora 43 host, these packages were downloaded and extracted inside
`tools/shx-deps`; nothing was installed system-wide. Their exact identities and
hashes are in the
[package record](evidence/gap-remediation/2026-11-13/shx-build-01/dependency-packages.json).
Use a compiler, make, patch, Python 3.13+, rpm2cpio and cpio from the host.

```bash
mkdir -p tools/shx-deps/rpms
mkdir -p state/shx-build/dnf-cache state/shx-build/dnf-log
mkdir -p state/shx-build/dnf-persist
dnf --setopt=cachedir="$PWD/state/shx-build/dnf-cache" \
  --setopt=logdir="$PWD/state/shx-build/dnf-log" \
  --setopt=persistdir="$PWD/state/shx-build/dnf-persist" \
  download --destdir="$PWD/tools/shx-deps/rpms" \
  readline-8.3-2.fc43.x86_64 readline-devel-8.3-2.fc43.x86_64 \
  ncurses-libs-6.5-7.20250614.fc43.x86_64 \
  ncurses-devel-6.5-7.20250614.fc43.x86_64
```

Verify the package hashes against the record before extracting. From
`tools/shx-deps`, extract only the x86-64 packages with rpm2cpio and cpio. Then
build from the mothra root:

```bash
python3 scripts/build-shx.py --deps-root tools/shx-deps \
  --output tools/shx-peer
```

The output must be new. The script verifies frozen inputs, applies the patch,
configures and builds the complete terminal client. It retains compiler flags,
configuration, logs, executable identity and dependency-library hashes. CFLAGS
and CPPFLAGS both carry the local header path so the legacy configure probe
finds termcap declarations. The initial manual probe omitted CPPFLAGS; that
separate exploratory build is not the final recorded executable.

## Contained execution

Use the capture driver in the adjacent protocol-docs repository, with bwrap and
strace installed on the host. It gives the child a read-only system root,
repository-backed private home and temporary directories, and a private working
directory under the capture output. The HOME environment value is unchanged;
its filesystem view is mapped to the repository. Loopback networking is shared
so the peer can reach the native guest forwarding ports.

The legacy client loads startup rc files unless `-q` is used, and **always saves
`~/.hxvars` on normal exit**. `-q` does not prevent that write. Run through
the contained driver; it also records before/after state of the real home file.
An initial uncontained probe truncated an existing real `.hxvars`; its earlier
contents could not be verified or restored. Subsequent smoke/native runs wrote
only their private repository-backed copy and left the real file unchanged.

```bash
python3 scripts/capture_shx_session.py \
  state/native-sessions/runtime-17/basic-plan.json \
  --binary tools/shx-peer/source/hx \
  --peer-profile tools/shx-peer/manifest.json \
  --oracle-binary evidence/hotline-server-1.9/inputs/HLserver19.pef \
  --output state/shx-session-new
```

Plans retain exact terminal commands, expected output and runtime provenance.
Capture both host loopback and the emulator's guest Ethernet boundary, as in
the native protocol workflow. A successful terminal match alone does not prove
native conformance, completed file writes or historical-peer identity. Verify
packet streams and downloaded fork bytes independently. The seven isolated
callback tests remain separate from these full-process sessions.
