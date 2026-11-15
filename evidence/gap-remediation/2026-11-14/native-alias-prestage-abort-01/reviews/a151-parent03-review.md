# A151 read-only parent P03 adaptation review

The two prepared parent scripts parse as Python. Neither was executed and no
approval pin, service, UI input or protocol request was created.

One pre-pin blocker remains in `approve-alias-live-03.py` line 28: its exact
ten-script set still demands `candidate-closure-02.py` and
`freeze-after-import-02.py`. P03 currently contains `candidate-closure-03.py`
and `freeze-after-import-03.py`, with the two `-02.py` files absent. The writer
would reject the supplied proposed inventory before creating pins. Correct
the two literal expected basenames after C's final P03 inventory freezes.

The rest of the writer is a literal adaptation of accepted P02: P03 root,
new M1 case/control hashes `5c497aec…`/`c467976e…`, exact 35+3+2 source
set, ten script hashes, exclusive `O_EXCL|O_NOFOLLOW` files, descriptor
`fchmod(0444)`, write and fsync. The reviewer uses O03, `:15980`, the same
dynamic plan and exact byte comparison, capture and disk identity, live
runtime/sidecar hash, root-0600 prestage receipt, HFS Files parent visible,
three screenshot hashes and a hard >=390-second case reserve. There are no
stale live-02 runtime paths or old M1 source hashes in those guards.

This is a static source review. P03's script inventory is still being
prepared; final ten-script bytes and any live readiness remain separate
gates.
