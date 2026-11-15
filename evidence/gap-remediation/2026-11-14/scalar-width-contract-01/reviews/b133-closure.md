# GAP-015 independent closure review (B133)

## Scope and identity

- Original question and criterion: `../hotline-protocol-docs/gap-analysis.md`,
  GAP-015, lines 1315–1337: identify which numeric fields take 1/2/4 bytes,
  fixed or signed widths, boolean and sentinel effects, and invalid widths;
  give each core scalar an explicit wire type, allowed width/range and
  invalid-width outcome, including references and privilege bitmaps.
- Reviewed `../hotline-protocol-docs/native-wire-details.md` SHA-256
  `877c0c7551de6ae7ee93735470d451deb12f3cea74205871ccb00b9f644d8a87`
  against `core-field-schemas.md` SHA-256
  `00b7af54c4ef8c153fcc495927e131dad2753b89cbe10b80a37d233f454f791c`.
  The former was an uncommitted A164 edit at the review time; recheck the hash
  when adjudicating its committed form. No live or oracle query was made.

## Clause check

| Original clause | Reviewed evidence and assessment |
| --- | --- |
| Explicit wire type and widths for every core numeric input | `native-wire-details.md` lines 38–58 and 63–69 distinguish generic unsigned `N` from direct-copy four-byte reference 107, nested roster BE16 words, news inner BE16 and eight-byte bitmap `A8`. `core-field-schemas.md` lines 34–153 supply direction/occurrence. **Met.** |
| Effective range, signedness and contextual meaning | The same rows give 32-bit generic access, icon low16, UID signed16 lookup, full32 room lookup, option-specific 113/109/337 semantics, signed icon promotion on 301, and sender BE16/BE32 emission. Retained `D-10056a90.c` confirms the `uint32` writer. **Met for the documented wire and read result;** successful target lookup is conditional. |
| Invalid-width outcome | Generic zero for absent/empty/three bytes and first-four for overlong bytes is distinguished from handler outcome. Reference214 instead zero-fills short direct copies and caps long copies at four. Account110 zero-fills short input and caps nine to eight; nested record length failures are separate grammar errors. Sender-only invalid client width is inapplicable. **Met.** |
| References and privilege bitmaps | `native-wire-details.md` lines 62–63 cover fixed four-byte 107 and MSB-first eight-byte 110, including account348/352 and notification354 output, nested349 input, and native bitmap width controls. **Met.** |
| Complete core output context mapping | Corrected line59 covers 104/106/112/113/117/118/119/301/302/355 numeric emissions without assigning 114 to 302/355; line66 includes 206 file-info size207 and transfer size/count through the 32-bit writer. **Met.** |

## Recommendation and bounds

I found no remaining unmet clause in the **original** GAP-015 criterion and
recommend bounded closure after the A164 hash is pinned. This is a source-backed
wire/read contract with native corroboration where cited. It does not establish
an ACK for every malformed value, a 64-bit file size, meanings of all bitmap
bits, date-record conversion, or arbitrary peer acceptance. Those are different
questions, not missing scalar types or widths under this criterion.
