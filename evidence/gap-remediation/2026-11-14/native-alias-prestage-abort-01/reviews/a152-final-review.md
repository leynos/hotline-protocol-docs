# A152 final P03 offline review

Reviewed only the prewritten P03 assets; no approval pins, service, VM, X
input, Hotline connection or image-byte read was performed.

The ten-script inventory is byte- and line-exact against
`proposed-script-SHA256SUMS`: 1,291 physical lines, within the 1,300 cap.
The source proposal SHA is `0a753d37de184b11b1cfa3a819da789d1509bad91f4e821ea5f038720b75bb38`;
its 35 protocol modules, three helpers and two launchers match canonical
and proposed snapshot bytes at head `beaf0b598081990be63e59403b9c90b85b3eaa3b`.
The B123 stopped receipts report `prepared_stopped` and
`stopped_finf_staged`. The five approval pins are absent.

The A151 pin-writer defect is fixed: its exact set now names
`candidate-closure-03.py` and `freeze-after-import-03.py`, matching the
present ten scripts. It still demands the new M1 source hashes
`5c497aec…`/`c467976e…`, exact 2/35/3/2/10 sets, exclusive file creation
and descriptor `fchmod(0444)` before writing/fsync. The parent reviewer
retains regenerated-plan byte equality, live runtime/sidecar and
disk/capture identity checks, root-0600 Finder receipt, HFS Files parent
visibility, three screenshot hashes and >=390 seconds before case grant.

The P03 operational scripts use fresh R/D/O03, `:124` and 15980–15983,
and preserve the P02 phase and source gates. Differences beyond the literal
profile are the corrected ten script basenames, new port-filter range and
operator checkpoint. The packet asks for target selection and a reviewed
Files/Unix/Finder view by epoch +270 seconds; it explicitly leaves the
hard >=390-second case gate intact. These are prepared controls, not a
claim of actual P03 readiness.

Validation: root-run `models/offline_no_x.py` passed display/executable/
FD16 replacement and attempted Quit replay faults without X. Bash syntax
and ShellCheck passed on five shell scripts; 19 Python or embedded-Python
AST blocks parsed. Source and script SHA inventories passed. The only
failed check was an initial review-only AST extraction command that split
a redirected heredoc incorrectly; the corrected line-delimited extraction
passed all 19 blocks. No production defect was found by this review.
