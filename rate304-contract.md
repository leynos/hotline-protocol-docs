# Native 1.9 settings rate path: source prediction

The [frozen source corpus](../mothra/evidence/gap-remediation/2026-11-14/rate304-static-01/manifest.json)
copies the existing PowerPC decompilation bodies and query metadata for the
native server DATA fork SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`.
A93 made no new oracle call or native request. The 26/27 boundary below is a
**source prediction**, pending a bounded packet and native-clock witness.

## Counter and ordinary response

The online dispatcher `1000acf0` tests its per-session complete-request
counter before selecting type304. If its native-time window is older than
60 seconds, it resets the counter; when the **existing** count is greater
than 120 it closes/bans, otherwise it increments. Login and numbered
barriers on that session must be included when testing this counter.

The 304 handler `10016ad0` has a separate session counter at offset
`+0x146` and window origin at `+0xa8`. The admitted session was allocated
through zeroing `10052b70` → `10079e30`; inspected 107/121/settings helpers
do not alter these offsets before 304. If native elapsed time since `+0xa8`
is **greater than** 60 seconds, 304 stores the current time and resets its
counter. It then accepts when the existing count is **less than 26**,
increments it, and calls settings helper `10004d50`. At an existing count
of 26 or more it calls socket close, timed address-ban insertion
`100063c0`, then log formatter `100068e0`. The ban helper stores native
time plus 1,800 seconds. This call order does not prove exact wire FIN/RST
timing or a delivered log notice. With a positively established zero counter
and 26 304s in one native window, the 27th takes this source close path.

`10004d50` reads field102 display name, field104 icon, field113 option
bits, and conditionally field215 default response, then calls `10004f30`.
That helper constructs and broadcasts 301 with UID103, name102, icon104
and status112. The direct 304 chain does not compare old and new settings
before that call: even identical admitted inputs reach 301 construction.
It does not construct a normal numbered 304 ACK. Delivery and packet order
remain wire observations, not deductions from construction alone.

With the naming privilege bit26 clear and 304's account-record argument
absent, the submitted field102 updates the session's input name but does
not replace effective display name `+0x38`; 301 uses that effective name.
The numeric field104 is assigned as icon. A finite fixture can vary only a
two-byte icon across updates and compare each measured 301 against the
current UID/account name, avoiding a false rename conclusion. The native
Login107 **early online** branch requires nonempty name102 and nonzero
icon104; when it succeeds, it marks the session online and sends its own
announcements. Transaction121 belongs to a positively delayed login path,
not an automatic follow-up to an early online107.

The traced 304 close branch and timed-ban helper contain no local bit23
protection check. Bit23 protects against explicit kick110 in a separate
fixture; it does not establish exemption from this automatic limiter.
This is a bounded callgraph observation, not an exhaustive statement about
all admission or permission paths.

## Measurement boundary

A native fixture must establish the current session identity/ACL, count
every complete request, bracket the native 60-second window, compare each
301 and terminal TCP bytes across both packet views, and test the later
valid login separately. A host-duration bracket alone is not native-clock
calibration. The existing eight-stage 304 transition corpus proves ordinary
settings effects, not this 26/27 boundary. No rate boundary, mxd parity
policy, general exemption, or GAP-045 closure is claimed here.

Related repeat-hash branches are separately frozen in the corpus. For board
103, the hash input is the **formatted segment**, whose header includes
native date/time; equal posted field101 bytes can produce different segment
bytes across a header-time change. A future spam fixture must compare actual
formatted bytes and distinguish an ACK queued by source from one delivered
before a close. Chat105, PM108 and broadcast355 have their own counter and
permission ordering. Their limits cannot be inferred from the 304 path.
