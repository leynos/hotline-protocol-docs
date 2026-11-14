# Native 1.9 configured-ban application: static preparation

This note narrows the remaining GAP-044 type-104 producer. It is static
evidence, not a configured-ban network fixture. The accepted option-two
control witness is in [native-ban-control-witness.md](native-ban-control-witness.md).

## Raw text and source path

The [C59 corpus](../mothra/evidence/gap-remediation/2026-11-14/configured-ban-static-01/manifest.json)
records a single 160-byte memory read from a fresh independent Ghidra import
of Server 1.9 DATA SHA-256 `ad7040db…`. The import explicitly selected
`PowerPC:BE:32:default`, returned the expected address range and 4-byte
pointer size, and had **zero analysed functions**. Identity before and after
the read matched. The earlier automatic import chose a different PowerPC
language, so it was rejected before a content query; both identities are
retained. Neither import opened the GUI-owned project.

At `1008fdac`, the raw byte `2a` is the Pascal length 42. The following
42 bytes are exactly `You are permanently banned on this server.`. At
`1008fdd7`, the raw bytes begin a NUL-terminated format string
`Disconnect & permanent ban \xd2%#s\xd3`, where `d2`/`d3` are the retained
MacRoman quote bytes. The second string is passed to a separate helper;
its formatted output and delivery are not asserted here. `decoded.json`
contains both exact hex sequences and the address offsets.

Frozen `10006590` builds field 101 from `1008fdac`, walks connected
sessions, matches each session's address against active permanent-ban
ranges through `10009960`, and sends type 104 on a match. Frozen Options
handler `100023a0` refreshes the active ban list with `10009d10` before
calling `10006590`. This call order supports an apply-while-connected
fixture. The class string `CMyPermBanListView` exists in the frozen string
export, but its exact control path and address-field transformation are
not established by these exports.

## Next preparation gate

Use a new disposable image copied from the pinned immutable base. The C56
stopped image now contains a permanent ban and must not be reused as an
unbanned baseline. Before a live fixture, identify the actual permanent-ban
UI control and prove that its input matches the server-observed shared
guest address `10.0.2.2`; the host frontend destination `127.0.0.1` is not
that proof. Then a separately authorised control-only trial can connect
owned admin and zero-access target before applying Options, capture both
type-104 notices and closes without assuming the admin survives, and retire
the lab with zero primary-port SYNs. No 110 request belongs in that trial.

The exact 42-byte compiled string is established statically. Its configured
application on the wire, exact UI mapping, close timing, and GAP-044 closure
remain open.
