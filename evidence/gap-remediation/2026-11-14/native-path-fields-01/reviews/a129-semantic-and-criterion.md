# A129 semantic and original-criterion review

Reviewed private protocol verifier HEAD `cf042bf928e9c5bbbf4e5890b0601b3b2415abc3`
and its canonical three-file copy, the native path corpus, the separate
202/212/325 tables in `native-wire-details.md`, and the frozen GAP-047 entry.
This is a bounded independent review; only the supervisor changes status.

## Verifier acceptance

- The B108 correction walks the corpus tree before manifest parsing or
  retained-source import. It rejects a symlinked root, file, or directory.
  I repeated the A128 counterexample: replacing `derived/flows.json` in
  a copy with a symlink to the original corpus's identical file now fails
  with `Corpus symlink is not portable`.
- Four focused test methods pass against the canonical corpus. They cover
  both file and directory symlinks, forged approved source bytes rejected
  before execution, 17 refreshed semantic faults, and a mutually consistent
  altered report/frame/event/stream rejected by independent PCAP bytes.
- The verifier pins approval-file hashes before any retained Python import,
  exact 37 protocol and three helper names/bytes, and the regenerated
  twelve-cell plan. It checks dynamic UID, 82 requests, 20 mutations,
  reply-frame/raw/event/request timing, per-cell selected parent, candidate
  200/206 views, and the News category row. It maps both closed SYN
  lifetimes in namespace and guest PCAPs to the complete sent and received
  report bytes and terminal flags, including empty unread tails. Primary
  capture has no service SYN in its filtered scope.
- Runtime pin, fixed deadline, source identity, managed recorder receipts,
  zero-drop terminal journal, app Quit followed by forced emulator TERM,
  FD-free gate, 11 allocated owned Trash IDs, category DATA hash and zero
  RSRC, original two users and unchanged fork receipts are checked. Original
  fork bytes are not distributed, so their saved stopped-read receipts
  cannot be independently rehashed by the portable verifier. No orderly
  guest OS shutdown or crash durability is asserted.

## Frozen GAP-047 clauses

The frozen criterion asks for traced encoders/resolvers, separate field
grammars, root/nested/non-ASCII/invalid-component fixtures, and proof for
any claimed equivalence. The question also asks about component count,
word, limits, and normalization.

| Clause | Evidence and scope | Assessment |
| --- | --- | --- |
| Record frame and resolver | `native-wire-details.md` gives BE16 count, per-component BE16 word and Pascal byte string. Frozen traversal/last-component helpers, 208 `100177d0`, and 370 `100102c0` trace the shared record route. | Met for framing. The word remains opaque; no reserved/ignored meaning is invented. |
| Separate fields | Distinct 202, 212, and 325 tables state Files paths, Files move destinations, and News paths, with different operation roots and checks. | Met. No all-field parser or policy equivalence is claimed. |
| Roots | Native mkdir controls cover 202 Files root forms; native move controls cover absent/empty/zero-count 212 destination to Files root; native News controls and this case cover `325=0000` News root. | Met for tested forms; Files and News roots remain distinct. |
| Nested and non-ASCII | Prior mkdir and News controls cover nested locations. This case's literal high byte `9a` selects the owned nested Files H folder and high News folder, with 200/206 and distinguishing 323 evidence. | Met for finite pre-OS-X cases; no universal codec claim. |
| Invalid component/count/word | Prior 202 controls plus six 212 and six 325 cells include empty suffix, excess count, `ffff` word, and valid-prefix trailing padding. The selected objects are proved by views/replies, not success status alone. | Met as per-field measured fixtures. Acceptance of all malformed values is unproved and unclaimed. |
| Limits and normalization | 208 and 370 readers copy at most `0x800` bytes; submitted 2048/2049 cases select the same owned object. 202 has separately measured colon/NUL behavior; 212/325 reach shared sanitizer but lack their own colon/NUL fixtures. | Met for source-backed copy cap and bounded normalization wording. Parsing byte 2049, universal depth, and cross-field transformation identity are not claimed. |
| Equivalence | Tables claim common record framing and individually measured prefix selections only. They explicitly decline identical roots, permissions, alias containment, and universal malformed-input acceptance. | Claimed equivalence is supported; broader equivalence is left unknown. |

The original criterion is met at its finite native 1.9 evidence scope, subject
to the supervisor's final corpus hash/export and publication gates. I
recommend closing GAP-047 with the explicit limits above. This does not
resolve other path, alias, durability, or mxd validation requirements.
