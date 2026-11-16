# Isolated legacy message board fixture preparation

This prepares the finite GAP-046 101/102/103 case; it does **not** run it. The
runner accepts only control port 15860 and a receipt for a new disposable Mac
guest. It changes that guest's board through ordinary native requests. Keep the
immutable base and primary guest untouched. Retire the disposable working image
after the stopped-image board witness; do not reuse it for another baseline.

## Evidence and source boundaries

- The pinned server data fork is SHA-256
  `ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. A75
  `state/delegation/legacy-board-oracle-01` read the actual `10082694` format,
  `100826bc` Pascal separator, and `1008f87e` Pascal `MessageBoard.txt` under
  the independent PPC32 project (1,840 functions). `10004110` supplies the
  formatter and file-write call path. Its 60 emitted separator bytes are CR, 58
  underscores, CR; `3c` is the Pascal length and is **not** emitted. The source
  format is NUL-terminated `From %#s (%s%2.2hu %2.2hu:%2.2hu):\r\r`; runtime
  date/name bytes remain measured rather than guessed.
- Stopped immutable base catalogue ID 11191 is `Hotline19/MessageBoard.txt`,
  DATA=0, RSRC=0, Finder `TEXT`/`ttxt`. Preserve its catalogue and fork
  receipt. A newly prepared owned working image must independently show the
  same empty file before boot; the source plan rejects any other baseline value.
- `1000f130` supplies bit20 read permission and 65,535-byte field101 clipping;
  `1000f260` supplies bit21 posting permission and the inclusive 8,192-byte
  accepted size; `10004110` prepends the formatted segment and writes the whole
  board. These source facts do not substitute for a successful live case or a
  stopped-fork comparison.

## Separate guarded epochs

The parent must choose a fresh owner-free image, ROM, display and control-only
guest namespace, then verify actual emulator executable hash, PID/start ticks,
image inode, guest/host/namespace recorder FDs, loopback-only routes, and a
managed exclusive oracle lock. The inherited
`native_ban_expiry_control.runtime_gate` checks the live receipt against
`plan.json`, including capture unit lifetime covering the <=12-minute epoch
plus margin. The runner checks the exact native data fork hash before creating
its exclusive output leaf. The root controls boot and the two separate
unchanged 18-action control-only preflight and postflight captures. Full
A7/FILP is `not_exercised`; the board runner never claims it.

Create a plan only after the stopped-board and runtime identity receipts have
been prepared:

```sh
python scripts/native_board_cases.py --runtime <owned-runtime.json> \
  --output <new-plan-dir>
python scripts/native_board_control.py --plan <new-plan-dir> \
  --receipt <live-capture-receipt.json> \
  --binary <pinned-server-data-fork> --output <new-empty-output-dir>
```

The output directory must **not** exist. The case has four simultaneous-at-most
control sockets: admin sender, admin eligible reader, zero-ACL `fixture-low`
denied reader, and admin delayed-login waiting session without
icon104/activation121. The waiting session is closed after P2 before the
preonline age threshold. Six TCP lifetimes total include the separate pre/post
controls. The source plan declares 32 numbered case requests: four107, nine101,
thirteen103, and six500; no extra probes. The first three posts use eligible
and denied 500/ACK barriers. No preonline 500 is sent. Posts are unique and
paced at least one host second apart to avoid the repeated-hash spam path,
without claiming native clock equality.

P0 carries explicit empty101; P1/P2 are `board-A`/`board-B`; P3 is 8,191 bytes;
P4–P9 are six distinct 8,192-byte posts. After measuring aggregate L at P9 and
the actual stable rendered overhead H, P10 is exactly `65,535 - L - H` bytes
(must fit 0..8,192), and its read must equal 65,535 bytes. P11 adds a distinct
byte and its 101 must be the newest 65,535-byte prefix. P12 is 8,193 bytes,
expects status1/field100, no102, and unchanged clipped read. The run checks
each successful 102 segment against sender and eligible bytes, and checks
prepend reconstruction against every selected101. It records waiting-session
102 if delivered and rejects denied 102. No cross-socket total order is
inferred.

The custom nonblocking collector retains all send/receive chunks, decoded
physical frames, timestamps, EOF or bounded no-EOF observations, and tails.
FIN/RST classification requires the paired PCAPs. Malformed tails fail the case
but still close and remove the owned socket; the raw receive event and original
parser error remain in `report.json`. Limits: 8 MiB of recorded bytes, 300
frames, 180-second case window inside a hard 210-second runner cap. Missing
expected replies, changed semantic fields, header/date overhead,
source/identity mismatch, timeout, or exceeded limits fail the case and retain
`report.json`; do not retry or retune the post matrix. The report's
`whole_board_sha256` is a **reconstruction** from 102 segments, not storage
proof.

After a completed case, stop only the disposable guest, prove no working-image
holder, and extract the exact named board DATA fork. Compare its full bytes
(including the portion after the 65,535-byte read prefix) to the concatenated
twelve 102 segments and preserve resource/Finder metadata and inode/path
evidence. Preserve primary/base hashes, raw host and guest SYN lifetimes,
capture drops, lock/FD/unit terminal receipts, plan and source hashes. No raw
HFS restore write is necessary: quarantine this mutated disposable image. The
fixture cannot establish crash durability, every date/text encoding, or all
delivery interleavings. Root adjudicates GAP-046 after raw and storage replay.

> Status note (2026-11-16): the register now lists
> [GAP-046](../../gap-analysis.md#gap-046) as Resolved. Its closure text
> records the legacy-board serialization and mutation rules as met with the
> native empty, multi-post, size-boundary and recipient fixtures.

Focused offline checks use the canonical protocol scripts as dependencies when
this private clone predates their import:

```sh
PYTHONPATH=scripts:/data/leynos/Projects/hotline-protocol-docs/scripts \
  python -m unittest discover -s scripts -p test_native_board.py -v
ruff format --check scripts/native_board_cases.py \
  scripts/native_board_control.py scripts/test_native_board.py
ruff check scripts/native_board_cases.py scripts/native_board_control.py \
  scripts/test_native_board.py
ty check --extra-search-path \
  /data/leynos/Projects/hotline-protocol-docs/scripts \
  --python /data/leynos/Projects/mothra/tools/ghidramcp/.venv/bin/python \
  scripts/native_board_cases.py scripts/native_board_control.py \
  scripts/test_native_board.py
```

## Readiness receipts and the aborted first lab

The [first board lab](native-board-readiness-failure.md) stopped before any
protocol request. Its manually assembled lease receipt and correction script
failed setup checks; it supplies no board-operation evidence. The
[successful second lab](native-board-witness.md) supplies the paired protocol
and stopped-file evidence for the fixture described here.

Use the
[validated receipt builder](https://github.com/leynos/mothra/blob/57aeaac4f12065bfb2de3d47943f4b45622392a9/docs/native-capture-receipt.md)
from the host as root. It reads the exact managed-unit properties, rechecks
capture and emulator identity, and creates one new receipt exclusively.
Prewrite and check readiness scripts before launching their units, and wait for
the actual capture header before its first readiness check. Run the readiness
and board coordinators inside the owned emulator namespace. A failed gate still
stops the group; neither this helper nor its rehearsal authorizes a new native
case or extends its fixed deadline.
