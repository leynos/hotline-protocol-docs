# Recorded Alias Record v2 identity

`scripts/alias_record_v2.py` accepts an **extracted AliasRecord payload**. The
caller separately proves a unique resource-map `alis` ID 0, the stopped Finder
[alias](../glossary.md#alias) flag and the exact fork/payload hashes. The
decoder does not parse resource forks, call Alias Manager or resolve a live
target.

This document belongs to the [files and transfers](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

`decode(payload)` requires a size-exact, big-endian version-2 file or folder
record. It bounds the Pascal volume and target names, records parent and target
CNIDs without resolving them, and walks only tags 0, 1 and 2 followed by the
final tag -1. Unknown versions, tags, duplicates, truncated values, invalid
padding and trailing bytes fail. Raw names and Carbon path are hex in a
JSON-serializable result labelled `recorded identity only`. For this reviewed
subset, odd-length tag padding must be zero and tag 1 must have a four-byte
CNID-array length. These are fail-closed acceptance rules for the retained
controls, not claims about every valid Alias Record.
`compare_recorded(record, volume, name, full_carbon_path)` requires exact
caller-supplied byte identities and a supported tag-2 path. It does no text
normalization, inode comparison or type/creator inference at offsets 122/126.

The three fixed controls in `scripts/fixtures/alias-record-v2-controls.json`
contain extracted payload hex, source resource-fork paths and fork/payload
SHA-256 hashes. They came from the older `native-alias-01` read-only live
catalogue, **not** a stopped durability snapshot. Dedicated tests cover those
controls and malformed bytes. Fresh export runs without `state/` or the old
resource forks because the bounded payloads are frozen in the JSON.

The layout basis is the [Apple Alias Manager manual], the [Apple-authored XNU
alias structure], and the [author-maintained mac_alias v2 format guide].
Apple's manual states that stored names may be stale; the decoder cannot
replace a positive native 206 result or the reviewed operator receipt. A future
Unix alias also needs the stopped Finder/resource-map proof. Its recorded
volume/name/path are only one binding witness and do not authorize host unlink,
M3 or GAP-054 closure.

[Apple Alias Manager manual]: https://developer.apple.com/library/archive/documentation/mac/pdf/Files/AliasManager.pdf
[Apple-authored XNU alias structure]: https://unix.superglobalmegacorp.com/xnu/newsrc/bsd/hfs/hfs_link.c.html
[author-maintained mac_alias v2 format guide]: https://mac-alias.readthedocs.io/en/v2.0.0/alias_fmt.html
