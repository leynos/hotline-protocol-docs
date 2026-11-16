# Native clock and log source evidence

This note fixes the source provenance for the Hotline Server 1.9 clock path. The
[portable corpus](../../evidence/gap-remediation/2026-11-14/native-clock-log-source-01/manifest.json)
contains the exact read-only Ghidra queries, earlier frozen bodies, as-run
capture script, program identities, source hashes, and one retained guest
screenshot. It contains no server binary, Ghidra project, ROM, or disk.

This document belongs to the [native evidence](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

## What the code links

The settings limiter at `10016ad0` calls `10057d00`, which directly calls
Classic Mac `GetDateTime` and returns its first 32-bit word. The limiter
compares the unsigned difference from session offset `+0xa8` with **60**; when
it is greater, it resets the timestamp and the counter at `+0x146`. This is a
code path and threshold, not a measured elapsed interval.

The GUI event path is independently linked. The terminal 304 branch calls
`100068e0` with the flooding message; that calls `10006a70`. The retained
untruncated `10006a70` body calls `10057e30(buffer, 0x7f, 0x22)` before
formatting and inserting text into the GUI log. `10057e30` makes a **separate**
`GetDateTime` call and passes that word to `10057e90`. For option `0x22`,
`10057e90` takes its date branch through `SecondsToDate` and its time branch
through `TimeString(word, 1, ...)`.

The
[Apple-authored `TimeString` reference](https://leopard-adc.pepas.com/documentation/Carbon/Reference/Date_Time_an_nt_Utilities/DeprecationAppendix/AppendixADeprecatedAPI.html#TimeString)
defines the Boolean argument as “whether the seconds are to be included in the
resulting string.” This is an archival mirror of Apple's documentation; the
corpus records its URL and attribution, not a copy of the page. The retained
[guest screenshot](../../evidence/gap-remediation/2026-11-14/native-clock-log-source-01/ui/awake-before-retirement.png)
has SHA-256 `bb1c16c592048fa40d118cd881835d2001437810a849fb2ae81e75ee3dcf6f1e`
and visibly shows GUI log seconds, including a successful login at
`10:29:50 AM` and a close at `10:29:53 AM`. Thus seconds were requested by the
traced formatter and are visible in this finite guest observation.

The separate `10006e80` login-file logger is conditional on server option bit 8
at `server+0xac`. It also formats with `10057e30(..., 0x22)` and appends to a
TEXT file. The read-only memory query resolves its pointer to Pascal string
`Connect Log`. This is a different destination from the GUI log. The prepared
rate experiment has not established that bit 8 is enabled or that paced and
burst login rows exist in a stopped `Connect Log`. No logging option was
changed.

## Measurement boundary

The limiter and GUI formatter call the same Mac API **at different times**. A
GUI row does not reveal the word sampled by a particular 304 handler, the
session's counter origin, or every intermediate clock value. The first native
rate304 capture ended after one 304/500 pair when its fixture wait expired; it
contains no completed 26/27 boundary or 70-second quiet period. The screenshot
is not a clock calibration for that aborted case.

A later authorized case would need the actual source-correlated log rows and
request/response timestamps, an unchanged guest clock and source identity, and
explicit upper/lower time brackets before applying the `>60` source predicate
to a measured result. Neither every 304 nor every counter reset is logged. The
original GAP-020 timestamp and GAP-045 limiter criteria remain open; this
packet changes no status or native configuration.

To check this source packet independently, verify root-relative hashes in
[`SHA256SUMS`](../../evidence/gap-remediation/2026-11-14/native-clock-log-source-01/SHA256SUMS),
compare the before/after program identities in `oracle/report.json`, and read
the three new query results beside the frozen helper bodies. The query was
read-only (`--no-analyze --discard`) against the independent PowerPC project
and made three content calls after identity checks.
