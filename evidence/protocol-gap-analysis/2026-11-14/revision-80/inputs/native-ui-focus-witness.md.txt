# One server Log focus event during a stalled native download

The C50 disposable Mac server ran the original 29-action A7 readback once on
14 November 2026. Only its runtime and endpoints changed to the isolated lab
at `127.0.0.1:15750/15751`. The recorder failed after 21 actions with
`TimeoutError: timed out`. It received 98,304 of the expected 1,049,073
flattened FILP bytes, SHA-256
`b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c`.
This is a **failed mandatory baseline**, with no account guard, seed, ban
option two or post-ban probe.

The frozen corpus is
`../mothra/evidence/gap-remediation/2026-11-14/native-ui-focus-01/`. It
contains source and as-run A7 plans, the failed report, the corrected
observer as inert text alongside its original six-argument version, both
focus screenshots, complete guest and namespace PCAPs, primary-port capture,
runtime/source identity receipts and terminal cleanup proof. ROM, disk,
emulator, Ghidra project and live RAM bytes are excluded. The manifest and
`SHA256SUMS` bind every exported file to its frozen source.

## Measured event and result

The observer associated the same data connection in both packet views using
its SYN, local port `47452` and the A7 connection time. Each view contained
exactly the recorded 98,304-byte prefix; no suffix remained after the
recorder timed out. The last payload packet preceded the single click by
more than five seconds in both views. The original A7 reader was still live
and had no final report when the observer acted.

At `01:07:20.661146Z`, the observer sent one XTest click to blank white
content in the inactive Hotline Server Log window at `(450,180)`. The
captured 1024×768 screenshots measure zero active-title gold pixels before
and 278 afterwards in the Log title crop. This is a bounded visual proxy
that the guest received the focus event. Ten seconds after XTest returned,
both packet views still contained exactly 98,304 bytes. The unchanged A7
reader subsequently timed out at its original read boundary.

That observation falsifies the specific claim that **one ordinary Log focus
event resumes this recorded plateau**. It neither identifies the scheduler
or transport cause, nor proves that no other UI event could affect progress.
The repeat at this prefix is not a native 98,304-byte transfer limit: C32
previously delivered the full 1,049,073 bytes in both wire views. A focus
event did not turn the failed A7 baseline into a control success.

The original server and isolated client identities remained unchanged. Both
lab captures show the same byte prefix, the host primary-port capture has
only its 24-byte header, and the namespace capture contains no 15500/15501
traffic. The owned emulator exited after a validated TERM; all owned
recorders, display and bridges stopped. The sheep user unit had already
auto-collected, so its separate stop returned exit 5; that intermediate
failure remains in the receipt. Both recorders reported zero packet drops.

Replay without a VM, live socket, Ghidra or execution of the captured
observer script:

```sh
python3 scripts/verify_native_ui_focus.py \
  ../mothra/evidence/gap-remediation/2026-11-14/native-ui-focus-01
python3 -m unittest discover -s scripts -p 'test_native_ui_focus.py'
```

The verifier reconstructs both SYN-scoped streams, validates the failed A7
report, measures pixels from the frozen screenshots, checks event times and
observer revision, and confirms the source/retirement pins. Rehashed fault
controls reject a false zero-click claim, inactive after-image, changed
guest payload and recast A7 success. Further low-level emulator investigation
is outside this packet. GAP-044's option-two notice and enforcement evidence
remain open for a separately authorised control fixture.
