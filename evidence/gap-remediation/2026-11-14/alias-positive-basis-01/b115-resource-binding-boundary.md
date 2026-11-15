# B115: post-stop `alis` binding feasibility (read-only)

2026-11-14. Scope: retained `native-alias-01` files only. No live image,
Finder input, native traffic, parser change, or new dependency.

## Existing local parser and cross-check

- `state/delegation/workspaces/batch-02-account/peer-acquisition-01/inspect_mac.py:34-56`
  parses the standard Mac resource-fork header/map/type list/reference list to
  find a resource type and signed ID. It was written for client `vers`, but
  the map walk can identify `alis` ID 0 without interpreting its payload.
- `evidence/gap-remediation/2026-11-13/native-alias-01/native-final/catalog-11444.rsrc`
  is 546 bytes, SHA-256
  `52ec71de9969cd4e7fdf7d505d9e7ec203dc85faaf95b2b49aa065a97fdae62d`.
  Its header says data offset 256, map offset 496, data length 240, map length
  50. Map type list at offset 524 has exactly one type `alis`, one reference,
  signed resource ID 0. The resource's length word is at offset 256 and its
  payload is 236 bytes, SHA-256
  `7a7df6da8c2f615130a679b8bff9033fe0f439ca688bea277e14f55b282d851e`.
  The retained `catalog-11444.stat.txt` independently reports `Is alias`
  and `Type: alis ID: 0 Offset: 260 Size: 236`; it identifies the physical
  HFS file `/Hotline19/Files/mothra-alias20/A/file` with TEXT/MOTH tags.
- The payload contains the byte run
  `System 9:Hotline19:Files:mothra-alias20:file`. Another retained alias,
  `catalog-11445.rsrc`, has a different tail naming `...:dir`; `11446`
  names `...:A:file`. These comparisons show embedded path-like bytes but
  are **not** a parsed Alias Manager target field. Their position/meaning
  must not be inferred from byte search alone.

## Proof boundary for M2

The existing map parser and `hfsstat` can establish a stopped owned HFS
file's Finder alias flag and exactly one `alis` ID 0 resource, with fork and
payload hashes. They cannot currently certify that its Alias Manager target
volume and leaf are `Unix:m-alias54-target`. No local `AliasRecord`/Alias
Manager payload decoder or primary structure header was found under
`tools/macemu`, `/usr/include`, `/usr/local/include`, or `/opt` in this bounded
search. The earlier alias payload and path-like strings are useful controls,
not a general format schema. A 206 reply with distinctive U54T/M54X fields
positively supports resolved target metadata, but does not itself name the
host path. The Finder UI receipt identifies the selected leaf and copied
alias; it is a human observation, not a machine-parsed resource binding.

**Minimum further proof:** after the M2 VM is stopped and FD-free, extract
its exact copied HFS alias's catalogue stat, DATA, RSRC and resource ID 0.
Pair this with the already required live UI screenshots and positive 206.
For a *machine-checked* target binding, obtain a reviewed AliasRecord parser
with a primary format source and fault tests, or a separately authorised
read-only Alias Manager/Get Info observation that reports the original Unix
volume and basename for that same HFS alias. A Finder Get Info proposal is
only a possible observation, not permission for more UI input. If neither
exists, label the M2 result positive 206 plus an unparsed `alis` resource,
not proven Unix-leaf binding, and defer M3 unlink.
