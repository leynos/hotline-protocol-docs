# A131: field 207 size ownership in alias replies

Read-only comparison of the retained native-alias-01 source, 206 reports,
and read-only direct HFS catalogue observations. No runtime or oracle query
was made. `native-live/extraction.json` records the catalogue read from
`hotline20/working.dsk` at 05:30 UTC; it has no PID-gone or FD-free proof.
These positive fork observations are not a consistent stopped-image
snapshot or a durability claim.

`AL-D-10016ba0.c` resolves the addressed field-201/202 FSSpec, then takes
`iVar2 = FUN_1002b250(local_a3c)`. It calls `FUN_1002cf90(iVar2,
local_a50)` before reading type/creator or size. `AL-D-1002cf90.c` delegates
to `AL-D-1002f600.c`; there the classifier calls either `1002f310` or
`ResolveAliasFile` with **the same FSSpec pointer as input and output**.
On successful file-alias resolution it sets kind 4. The 206 handler then
passes that resolved `iVar2` to `FUN_1002c800` for type/creator and to
`FUN_1002c4d0(iVar2,0)` for field 207. It separately takes field 201 from
the original `local_a3c` via `FUN_1002bce0`. This distinction is source
visible even though `1002b250`'s own body is not retained here.

`AG-D-1002c4d0.c` returns DATA EOF plus resource-fork byte count when
its FSSpec is not an already open fork (`+0x50 == 0`); it uses `GetEOF`
for an open fork. Handler 206 passes flag 0 and the resolved info object.
The measured native-alias-01 reports give the decisive ownership contrast:

| 206 subject | 207 | Read-only catalogue fork observations |
| --- | ---: | --- |
| Ordinary target `file` | `014d` = 333 | Catalogue 11431: DATA 16 + RSRC 317 = 333 |
| File alias `A/file` | `014d` = 333 | Catalogue 11444: own DATA 0 + RSRC 546 = 546 |
| File alias chain | `014d` = 333 | Catalogue 11446: own DATA 0 + RSRC 540 = 540 |

The alias rows' 333 matches the target forks and differs from the aliases'
own fork totals in these retained observations. Together with the in-place
resolution and `1002c4d0` call, this identifies field 207 as the
**resolved target's DATA-plus-RSRC aggregate** in this positive file-alias
case, not the alias file's aggregate. The absence of FD-free proof limits
the catalogue's temporal and persistence interpretation, not that bounded
source-and-wire size distinction.
It is still not the target DATA length by itself. A new extfs target with
DATA 20 and no RSRC could yield 20 if the same resolution/size path runs,
but the proposed positive gate must observe it; no value is pre-required
from the host leaf size alone.

Correction to A130: replace both occurrences of “alias aggregate” with
“resolved target aggregate” for the measured kind-4 path. The exact
205/206/213 distinct-tag predicate is unchanged and remains the strong
pre-unlink positive gate. In `filesystem-and-board-contracts.md`, the first
file-info table's alias size should say “resolved target aggregate” rather
than generic “numeric value”; the target-in-Trash paragraph's “aggregate
size 332” should likewise identify the resolved target, while preserving
that particular measured 332 value and not treating it as alias resource
bytes. Neither table needs a universal alias-size guarantee.
