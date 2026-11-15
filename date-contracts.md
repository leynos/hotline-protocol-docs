# Native 1.9 date fields and clock boundaries

This registry separates the eight-byte wire/storage form from the clock and
catalogue values that feed it. It answers the original
[GAP-020 question](gap-analysis.md#gap-020) to the extent supported by retained
server source and controlled native captures. A fixed year word is a format
marker in these producers; it is **not** the timestamp's calendar year. No
inbound field in this registry is shown to accept an arbitrary eight-byte date
and convert it into a native calendar time.

## Byte grammar, units and range

The retained [builder `10058070`][file-builder] writes exactly eight bytes:

| Offset | Width | Source-derived output                                                  |
| -----: | ----: | ---------------------------------------------------------------------- |
| 0      | BE16  | `0770`, decimal 1904, regardless of the supplied timestamp             |
| 2      | BE16  | `0000`; the labelled millisecond slot is not populated by this builder |
| 4      | BE32  | The supplied native catalogue timestamp word, copied unchanged         |

[Apple's `GetDateTime` reference][apple-time] defines its 32-bit word as
**seconds elapsed since midnight, 1 January 1904**.
[Apple's File Manager reference][apple-file] assigns the same seconds unit and
epoch to the native catalogue creation/modification words returned by
`PBGetCatInfo`. The server copies these words into the eight-byte form; it does
not divide by a year or subtract a UNIX epoch. The raw seconds slot can
represent `00000000` through `ffffffff` (0 through 4,294,967,295 as an unsigned
bit pattern), at one-second granularity. If treated as a continuous 32-bit
count, its **mathematical** next value after `ffffffff` is zero modulo `2^32`.
This is not a measured native rollover, calendar year 2040 response, or
successful year/millisecond input case. The builder emits no fractional
precision.

No timezone identifier or offset is present in these eight bytes. Apple's
[date/time utilities][apple-time] and [File Manager][apple-file] establish the
nominal epoch/unit, but the retained Hotline calls neither read a timezone
setting nor apply a visible offset. The guest's clock configuration, HFS/HFS+
date interpretation, local-versus-GMT conversion and display timezone were not
controlled together in a native fixture. Do not label the copied seconds as
verified UTC, local time, UNIX time, or milliseconds. Two raw values can be
compared as words within one clock/catalogue context; cross-host absolute-time
comparison needs a separately measured timezone basis.

## Producer and consumer registry

| Context                                                                   | Producer to wire/storage                                                                                                                                                                                                                                                                         | Receiver, copy or effect                                                                                                                                                                                                           | Evidence boundary                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File-info reply to request **206**, fields **208/209**                    | `1002c910` calls `PBGetCatInfo` and applies `10058070` to the two catalogue timestamp words. `10016ba0` emits both eight-byte values via `100568b0`. The protocol labels these creation and modification respectively.                                                                           | Client receives opaque 8-byte field values. File alias replies can use resolved target dates; fields may be omitted by the target-kind branch.                                                                                     | [206 handler][file-info], [catalogue helper][file-catalogue], [captured file-info variants](filesystem-and-board-contracts.md#file-info-presence-and-values). No general client date decoder is proved.                                                                                  |
| Ordinary download **FILP/INFO** fork, offsets **52/60** inside INFO value | `1002d130` reads native file metadata, calls `10058070` for creation and modification and serializes the values inside `AMAC` INFO. These are not outer TLVs 208/209.                                                                                                                            | A downloading peer receives the INFO bytes. [Native INFO layout](transfer-contracts.md#info-metadata-value) and selected full FILP captures preserve both forks and eight-byte dates.                                              | [INFO builder][info-builder]; no peer timezone/rendering claim.                                                                                                                                                                                                                          |
| Uploaded **FILP/INFO** offsets **52/60**                                  | Client-supplied bytes can occupy the two INFO date slots.                                                                                                                                                                                                                                        | Restoration `1002d2c0` **does not read either transmitted date**. It applies type/creator/selected flags, takes native `GetDateTime` for modification, and adds one second if that equals the current catalogue modification word. | [INFO restoration](transfer-contracts.md#info-restoration-after-upload) and [restorer source][info-restore]. Zero dates transmitted in the selected upload led to nonzero native 206 dates; no arbitrary date-restoration rule follows.                                                  |
| New article **410** stored date                                           | The network post handler `10010470` passes no explicit date to create helper `100229b0`; the helper calls `10057de0`, which calls `GetDateTime` and writes `0770 0000` plus that 32-bit word at stored article offset `0x38`. An internal non-null date argument instead copies its eight bytes. | The stored record is read by subsequent list/body builders; no field 330 in the 410 request sets its date.                                                                                                                         | [Create source][news-create], [clock wrapper][news-clock], [posting path](news-contracts.md#posting-partial-effects-and-deletion). The internal supplied-date branch is not an observed wire-input path.                                                                                 |
| Article-list **371** field **321**                                        | Rebuild serializes each stored article's eight date bytes at record offset **4**; cached output retains the same bytes.                                                                                                                                                                          | Client parses 321's packed list, not an outer numeric date scalar.                                                                                                                                                                 | [List layout](news-contracts.md#article-list-field-321) and [native cache/rebuild equivalence](news-contracts.md#captured-category-versions-and-header-metadata). Category-list 370 fields 320/323 are separate structures; their opaque metadata are not assigned a date by this trace. |
| Article-body **400** reply field **330**                                  | Builder `10005ac0` reads the article and emits its stored eight bytes through `100568b0(..., 0x14a, ..., 8)` without a second `GetDateTime`.                                                                                                                                                     | Client receives field 330 alongside title, poster, navigation and body.                                                                                                                                                            | [Read builder][news-read] and [captured 321/400 equality](news-contracts.md#captured-category-versions-and-header-metadata). Equality for those native-created articles proves shared stored bytes, not universal 330/208 time equality.                                                 |

Board request 103 formats a human-readable `From` line using a separate
date/time path; it does not emit one of these eight-byte date fields. GUI log
seconds and the request limiter likewise make separate `GetDateTime` calls;
[their source trace](../mothra/docs/native-clock-evidence.md) cannot calibrate
a specific 206, INFO, 321 or 330 timestamp after the fact.

## What would settle conversion and rollover

The following are **future controlled fixtures**, not observed Hotline 1.9
outcomes. Each needs an exact source/runtime identity, a disposable guest,
unchanged clock settings recorded before and after, paired packet captures, and
independent stored/catalogue byte reads. Mutating a user's working image or
clock is outside this document's authority.

| Question                          | Smallest decisive comparison and stop rule                                                                                                                                                                                                                                                                                                                                                                                                     |
| --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| File epoch and field ordering     | In one disposable volume, set two owned files' catalogue creation/modification seconds to distinct known values, read them through 206 and INFO download, compare each raw BE32 word with the catalogue and each corresponding field/offset. Use values on different calendar years and second boundaries. Stop if the filesystem normalizes either input or ownership is ambiguous.                                                           |
| News 321 versus 330               | Create one owned article at a recorded guest `GetDateTime` bracket, then compare stored offset `0x38`, 371/321 record+4 and 400/330 byte-for-byte, including cached/rebuilt 321. A second creation after a recorded clock tick distinguishes copies from one constant fixture. No extra date input is inferred from the 410 request.                                                                                                           |
| Milliseconds and other year words | None of the identified ordinary network producers emits them; INFO upload ignores them. To test a _consumer_, use a separately identified peer decoder or an explicitly approved disposable stored-record fixture with `0770/0000` controls and `0771/0001` contrasts. A raw copy alone does not prove calendar interpretation. Reject any plan that silently patches the primary image or labels an unsupported input an accepted server API. |
| Signed edge and wrap              | Under a separately approved disposable clock/catalogue arrangement, compare `7fffffff`, `80000000`, `fffffffe`, `ffffffff` and the next tick for 206/INFO and native-created 321/330. Retain full eight bytes, guest date display, clock-setting and timezone receipts, stored words and output/status. If the OS refuses or normalizes a value, record that boundary rather than claim native wrap.                                           |
| Timezone                          | Repeat one ordinary-file and one article comparison in two independently recorded guest timezone configurations while holding the intended instant and catalogue words explicit. Compare raw seconds and rendered dates; a displayed hour alone cannot establish the offset used by the server. This is separate from the source-level fixed-1904 byte grammar.                                                                                |

GAP-020 remains open for native timezone, nonzero millisecond/other-year
consumer behaviour and rollover. Source gives the second unit and 1904 base;
the native captures corroborate selected byte equality and ignored uploaded
dates. No mxd date-policy conclusion is made here.

[file-builder]: ../mothra/evidence/hotline-server-1.9/queries/D-10058070.c
[file-catalogue]: ../mothra/evidence/hotline-server-1.9/queries/D-1002c910.c
[file-info]: ../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c
[info-builder]: ../mothra/evidence/gap-remediation/2026-11-12/batch-04/queries/B04-D-1002d130.c
[info-restore]: ../mothra/evidence/gap-remediation/2026-11-12/batch-13/queries/B13-D-1002d2c0.c
[news-create]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/queries/B05-D-100229b0.c
[news-clock]: ../mothra/evidence/gap-remediation/2026-11-12/batch-05/queries/B05-D-10057de0.c
[news-read]: ../mothra/evidence/gap-remediation/2026-11-13/native-news-01/oracle-queries/NW-D-10005ac0.c
[apple-time]: https://leopard-adc.pepas.com/documentation/mac/OSUtilities/OSUtilities-105.html
[apple-file]: https://leopard-adc.pepas.com/documentation/Carbon/Reference/File_Manager/Reference/reference.html
