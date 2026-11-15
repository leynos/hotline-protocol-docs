# C132: retained Finder and extfs basis for GAP-054

Read-only, 2026-11-14. This note supplies UI and volume evidence to B109. It
does not authorize a VM, Finder input, host file creation/unlink, or protocol
request. B109 owns native 206 wire/schema and the coordinator.

## What the retained UI actually shows

- `state/native-sessions/mac-peer-first-01/file-menu-hold-02.png` is a
  1024×768 Mac OS 9 screen with **Finder** active and its **File** menu open.
  The menu visibly contains **Make Alias** and shows the Command-M shortcut.
  `finder-file-menu.png` is **Launcher** active and offers only Close/Quit;
  it is not evidence for a Finder command. The active application must be
  checked from the menu bar/window before any proposed action.
- `state/native-sessions/mac-peer-first-01/unix-open.png` shows the **Unix**
  desktop volume icon with Finder active. `unix-return-folder-named.png`
  shows an open Unix volume with `HotlineClientCandidate` and `returnfinder`
  folders. The path labels identify an extfs volume in that former runtime;
  they are not positions or identities in a new lab.
- `state/native-sessions/mac-peer-first-01/edit-menu.png` shows Finder's
  **Edit** menu with Copy and Paste entries, disabled in that screenshot.
  The preserved `mac-peer-isolated-session-01/B20-observation.txt` records a
  Finder copy from `Unix:HotlineClientCandidate` to a new System 9 folder and
  then back to `Unix:returniso20`. Its `return-finder.txt` and copy hashes
  retain type/creator and fork observations. Thus cross-volume Finder copying
  has a prior positive example for an **application**, not for an alias.
- `state/native-sessions/mac-peer-first-01/x11_input.py` records the earlier
  XTest input method: motion, `XFlush`, 80 ms delay, button/key events and
  screenshots while a menu button is held. It hardcodes display `:101` and
  cannot be used unchanged on a new lab. Old screen coordinates are not an
  operational contract; use newly observed window positions and menu text.

No retained image or log shows selecting an owned extfs leaf and invoking
Finder Make Alias, or copying that resulting `alis` resource/flag into HFS.
The exact alias-creation placement/name and any confirmation prompt remain
unknown. Finder File > Make Alias is a grounded **named** action, not a
preapproved click coordinate or a demonstrated successful operation.

## Source boundary

`scripts/mac_runtime.py:245,280` creates runtime `shared/` and sets
`extfs R/shared`. `tools/macemu/SheepShaver/src/extfs.cpp:438-442` verifies
the root directory; its file-info paths call host `stat(full_path)` at
1299 and 1352 and use `get_finfo`. This supports a real owned host leaf in
the guest Unix volume, but says nothing about Alias Manager retargeting.

`tools/macemu/SheepShaver/src/Unix/extfs_unix.cpp:76-84` documents
`<path>/.finf/<leaf>` and `<path>/.rsrc/<leaf>`. `open_helper` at 119-138
creates a missing helper directory/file on write; `get_finfo` reads the
32-byte Finder record at 222-255; `set_finfo` writes it at 258-274; the
resource fork uses `.rsrc` via `open_rfork` at 300-303. These are concrete
source mechanisms; the future packet must pin the built emulator source.
They do not prove Finder creates a valid alias on extfs or that Finder's HFS
copy retains its `alis` ID 0. The first 206 and stopped-HFS fork inspection
must test those propositions.

## Minimal separately approved UI rehearsal

1. On a fresh owned lab, capture a Finder-active screenshot identifying the
   Unix desktop icon and the staged uniquely named leaf in the Unix window.
   Stop if a different app/window or same-name leaf is selected. One leaf and
   its sidecars are the only extfs subject; all host data bytes are recorded
   before guest interaction.
2. Select only that leaf. Open Finder **File** and confirm **Make Alias** is
   enabled for this selection; capture menu state. Invoke that named action
   once. Retain the resulting Unix window and any prompt; an unexpected
   prompt stops input. Prove the new icon/name is separate from the target
   before considering a cross-volume copy. No guessed Command-M execution
   if File menu state is not confirmed.
3. Open the already identified owned HFS Files destination, use the observed
   Finder Copy/Paste sequence once for only the resulting alias, then capture
   both windows and destination icon/name. Stop if Copy/Paste is disabled,
   destination uncertain, an overwrite dialog appears, or the source target
   itself appears in HFS. The earlier application round trip does not waive
   this alias-specific check.
4. B109's separately reviewed native 200/206 positive gate must identify
   the copied HFS alias and the known live extfs target. After the owned VM
   is retired and its working image FD-free, extract HFS catalogue, Finder
   flag and full alias resource fork/`alis` ID 0. Never use live-image `icat`
   to accelerate the gate. No host unlink occurs in this rehearsal.

The UI phase proposes one Make Alias and one Copy/Paste of one selected
object, with fresh screenshots at each identity gate. It cannot presently
specify coordinates, prompt dismissal, exact menu enablement or elapsed time
from retained evidence. If the future live packet requires these before it
can safely start, first authorize a bounded **passive UI inspection** in a
new disposable lab; do not infer them from the :101 screenshot. Any failure
quarantines that image and stops before deletion or another attempt. An
actual missing-target test remains a separate epoch after B109's positive
resolution and parent review.
