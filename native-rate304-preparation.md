# Native 304 rate and reset preparation

Version 2 is an **offline prepared** GAP-045 fixture. This version has not
contacted Hotline Server 1.9. The source prediction is a session-local 304
counter: existing values 0–25 enter settings helper `10004d50`; a 27th request
in the same native `GetDateTime` window closes the socket, inserts a
1,800-second address ban and logs. After age greater than 60 seconds the
counter resets. A complete online request also increments the separate
dispatcher flood counter. See retained `D-1000acf0.c`, `D-10016ad0.c`,
`D-10004d50.c`, `D-10004f30.c`; A92's read-only source review is retained in
Mothra delegation state.

## Prepared scope

The fixture uses one **new disposable** Mac runtime and process from a stopped
immutable base. Candidate display `:120`, `R native-rate304-03`, and control
port `15880` require parent conflict review. The host and namespace captures,
guest PCAP, owned executable/ROM/image fork hashes, actual emulator
PID/start/exe/working-image inode/FD6/FD16, loopback-only routes, managed
capture units and exclusive oracle lock are live gates. Do not run this in the
primary server or an existing lab. `native_rate304_control.runtime_gate`
checks the actual root caller namespace, capture FD/inode/PID/start, managed
lock and current deadline before first contact, each new connection and at
end. The producer refuses other ports/profiles. The run needs at least 390
seconds remaining in a fixed <=12-minute capture epoch; units have
<=900-second caps. Case hard stop is 210 seconds. Missing gate evidence stops
before contact.

The failed version-1 runtime `native-rate304-01` is retired and quarantined;
its earlier permissions do not authorize reuse or another boot.

The later `native-rate304-02` startup also retired before protocol contact:
its immediate capture gate expired while the actual VM held its disk but
had not opened the packet-triggered guest PCAP. See the
[startup witness](native-rate304-startup-gate.md) and
[source boundary](../mothra/docs/guest-capture-startup.md). A future lab needs
the separate disk and capture stages described by the
[readiness helper](../mothra/docs/native-emulator-readiness.md); neither
earlier runtime is a retry target. Each new lab requires its own absent paths
and reviewed command packet.

Run an unchanged separate 18-action control-only preflight on that **same new
process** before the coordinator. Verify two original accounts, 41 Files
entries, exact agreement and no primary SYN. The preflight's one same-address
admission counts toward the independent server-wide burst counter. The
coordinator opens only four additional control connections, with at most three
simultaneous: admin observer, `fixture-low` paced subject, `fixture-low` burst
subject, then one fresh `fixture-low` ban probe. No accounts are created. This
is not a full A7 baseline or a board/room/file/news mutation fixture.

Early Login107 includes nonempty 102/nonzero 104, so the online branch emits
107 ACK, 354 and 109; no unconditional 121 is sent. The observer's initial 300
proves its sole known row. Each subject's 300 and the observer's 301 identify
its actual UID, effective `fixture-low` name, icon1 and eight-zero access.
Source allocation zeroes the 304 count/timestamp, and first 304 resets that
counter under an ordinary positive native clock; a clock-origin anomaly makes
the boundary inconclusive. Every 304 contains **only** field104 with
big-endian two-byte icon, varying 2–27. It has no normal direct ACK.
Send a same-subject numbered 500 immediately after each 304. The version 2
schedule pipelines all 26 ordered 304+500 pairs, then drains subject and
observer sockets concurrently. Before declaring the **phase** complete, require
all 26 exact subject 301, all 26 exact observer 301, and all 26 numbered 500
ACKs; their cross-socket arrival order is not fixed. The as-run report records
first send, final send, final required arrival, and contiguous validated pairs.
On a failed run, that progress count may include bytes received during bounded
cleanup; it is evidence of observed frames, not proof that the trial completed.
Complete each 26-pair phase within <=20 host seconds, or retain a timing-invalid
report.
The paced subject then sends no request for
>=70 host seconds while the separate observer sends 500 every five seconds.
Its next 304 icon28 plus 500 ACK waits up to five seconds for both 301 views
and its ACK; this does not extend the 26-pair host bracket. It tests the reset,
after which it closes and
the observer's 302 is retained. A new subject sends 26 pairs within <=20 host
seconds; its icon28 27th 304 has no 500 barrier. Retain EOF/RST or bounded
no-close and the observer's 302. One new valid Login107 probes the known
temporary-ban field100 error; a generic failure is not accepted as ban proof.
No automatic retry.

The still-open observer sends only five read-only controls 348, 200, 206, 300
and 303 afterward. Their known `framing-fixture` field hashes, one-row roster
and live replies are a **retained-session control**, not fresh Login107,
18-action postflight or full A7. The ban applies to the shared lab IP; another
fresh admin login would confound this stage. The runner retains every
sent/received chunk, parsed frame, action ID/timestamp, dynamic UID, all
observed tails, finite EOF/RST/no-EOF classification and an explicit unparsed
tail. Its notification inventory rejects extra 301/302/104, except for at
most one recorded terminal 104 on the burst flow and one observer 302 after
the ban probe with a UID different from observer and both departed subjects.
Neither exception assigns meaning to an unknown notice or UID. Its verifier
reconstructs per-flow streams and action bytes; it does not
substitute generic `verify_capture` for this custom multi-socket schedule. The
parent must pair host/namespace/guest PCAP lifetimes, check primary SYN/drops,
and read stopped original account/Prefs/server/board forks plus any Banned
file under a separately approved read-only stopped-image gate. The original
five forks and primary must remain unchanged; do not infer power-loss
durability from the stopped readback.

Actual guest `GetDateTime` progression is **not calibrated** by a host
20/70-second interval. A separately retained read-only guest clock witness
could support the native 60-second premise. The code reports host timing and
`native_60_seconds_proven=false`; no native threshold claim follows if the
guest clock/window premise fails. A missing 301, unexpected third user, early
close, wrong ban text, route/capture/identity drift, clipped tail, or missed
deadline fails closed and retains the raw report. One bounded failed run is
not permission to retry. The fixture addresses only the native 304 local
limiter; dispatcher/burst/chat/PM/board thresholds and mxd policy remain open
GAP-045 work.

The [clock source evidence](../mothra/docs/native-clock-evidence.md) links
GUI log formatting and the limiter to separate GetDateTime calls. The
observed log displays seconds; it does not expose each counter origin or
calibrate this prepared experiment's native reset interval.

C107 was a fixture failure after the first 304/500 pair: the old 0.55-second
wait expired before the subject's 301 and 500 ACK were observed at about
0.75 seconds; observer cleanup began first. The failed report remains unchanged.
This synthetic pipeline rehearsal proves only that delayed two-socket responses
can be collected within its declared bracket. It does not establish ordinary
native latency, why the observer update was absent in C107, a native clock
threshold, or a new native result. A separate live grant is required.
The bounded [recipient-predicate trace](rate304-recipient-predicate.md)
identifies the handshake path that sets the connection bit checked by 301
fan-out. It finds no direct icon-only 304 edge clearing observer eligibility;
delivery remains a measured question.

## Offline commands

Use `--runtime` with an actual new lab runtime JSON; `--output` must not
exist. Root owns the live start and receipt construction.

```sh
python3 scripts/native_rate304_cases.py --runtime "$RUNTIME_JSON" --output "$PLAN_DIR"
sudo nsenter -t "$EMULATOR_PID" -n python3 scripts/native_rate304_control.py \
  --plan-dir "$PLAN_DIR" --capture-receipt "$CAPTURE_RECEIPT" \
  --binary "$ORACLE_DATA_FORK" --output "$CASE_OUTPUT"
python3 -m unittest discover \
  -s scripts -p test_native_rate304.py -v
```

The second command is a future **authorised live action**, not an instruction
to run during preparation. The first and third can be used offline with
synthetic identity JSON. The private checkout needs the canonical dependency
overlay for `native_ban_control_cases` and related inherited helpers; the
parent must import those exact dependencies into an adjacent export before
claiming portability. No committed ROM, disk or guest app is part of this
packet.
