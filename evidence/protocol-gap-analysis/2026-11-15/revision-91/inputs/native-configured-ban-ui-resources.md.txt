# Configured-ban Options resource reconnaissance

The
[C60 resource corpus](evidence/gap-remediation/2026-11-14/configured-ban-ui-resources-01/manifest.json)
catalogues the native Server 1.9 resource fork without starting a guest or
opening Ghidra. The fork was previously extracted read-only from catalogue
record 11183, `/Hotline19/HLserver19`, in the immutable base image. The current
base hash is `e5cbbaaf…`; the 38,460-byte fork hash is `fe83a2cf…`, matching
the recorded native server. The full fork remains outside the new corpus.
`selected-resources.json` contains 8 selected resources totalling 1,636 decoded
payload bytes, with IDs, names, offsets, hashes, hex and visible ASCII runs.
The parser and original extraction record are retained beside it.

The resource map has one `DLOG`/`DITL` pair, both ID 9437; the dialog is named
`Error`. `MENU` ID 131 contains `Options...` among its Hotline menu items. No
`STR#`, `PPob`/`PPOb` or `CNTL` type appears in this fork. The `plst` resource
is bundle metadata, and the selected `HTLS` owner resource does not identify
the ban-list editor. These results identify the menu entry only. They do
**not** identify the permanent-ban control, its field encoding, or how entered
addresses become the range consumed by `10009960`.

The next bounded step is a separately authorized **read-only inspection** of
the owned guest's Options window in a fresh disposable lab. Capture screenshots
and control labels without applying Options, editing a ban, connecting a
client, or changing the primary server. Correlate the visible ban-list control
with frozen `100023a0` and `CMyPermBanListView` evidence before designing any
live `10006590` application fixture. The exact 42-byte compiled notice is
separately established in [C59](native-configured-ban-static.md); this resource
pass adds no wire observation or GAP-044 closure.
