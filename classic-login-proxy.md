# Classic Login107 field-161 proxy

The [B46/B47 baseline corpus][baseline] records actual Classic client
connections through this proxy. B47 reached the 121/300 roster, automatic
212 request and 16/58-byte data attachment before the independent
ACK-plus-28-second cutoff. The baseline ACK was byte-identical to native.
The later [B52 matrix][matrix] delivered three modified zero-valued 161
shapes and reached those same measured stages. Earlier B29 synthetic rehearsal
and B30/B31 zero-contact failures remain separate evidence. This tool is
protocol-specific; it did not change the mothra generic bridge or native
server configuration.

## Fixed topology and authority boundary

The proxy ran **inside the isolated client network namespace** under a direct
system service with `User=1000` and `NetworkNamespacePath=` set to the
verified client namespace. A user service
that runs `sudo`/`nsenter` is not an approved substitute. The CLI requires
trusted operator-supplied
`--expected-netns-inode` and `--host-netns-inode` values. The guard compares
`/proc/self/ns/net` to both, then uses `socket.if_nameindex()` to require
only `lo` and checks empty IPv4/IPv6 main route tables. It does not inspect
`/proc/1/ns/net` or `/sys/class/net`: both gave misleading/inaccessible
views to UID 1000 in the actual service context. Wrong, equal or nonpositive
inodes fail before binding. It binds only `127.0.0.1:15652` for control and
`127.0.0.1:15653` for automatic banner data. Those listeners connect only to
the existing namespace-local `127.0.0.1:15500/15501` native bridges. The
Classic app used guest `10.0.2.2:15652` and automatically attached to
15653 for the banner data in B47. There is no arbitrary backend address or
production port option. Recheck the service and namespace identities on
every future run.

The process accepts at most one control connection and at most one data
connection, then closes the listeners. It has a 180-second monotonic deadline,
short socket timeouts, and an aggregate raw/forwarded JSON log cap below 1 MiB.
A future service must also set `RuntimeMaxSec=180` as an independent process
stop. Failure after output creation closes owned sockets and writes a failed
report under a fresh, exclusive output directory. All traffic stays local
to the known native bridge. The output may include the controlled fixture
credentials and should remain ignored until reviewed for portable evidence.

## Wire transformation

The proxy verifies the Classic 12-byte `TRTPHOTL 00010002` greeting and the
native 8-byte `TRTP 00000000` reply. It requires the first complete client
control frame to be Login107 and learns that request's ID. All later client
frames pass byte-for-byte. It parses full physical control frames with a
65,535-byte body cap and rejects a fragmented `total != data_size`, truncated
TLV, malformed count or incomplete body. The first native frame must be the
matching successful direct ACK (`is_reply=1`, type 0, status 0). It requires
exactly one field 161 with raw bytes `0000` before forwarding anything from
that ACK.

| Variant | ACK change sent to Classic client |
| --- | --- |
| `baseline` | Original two bytes `0000`, with exact full ACK byte equality |
| `omit-161` | Field removed; count and body sizes rebuilt |
| `one-byte-161` | One byte `00`; count and body sizes rebuilt |
| `four-byte-161` | Four bytes `00000000`; count and body sizes rebuilt |
| `server-name-162` | Keep 161=`0000`; append 162=`fixture-native` |

All other ACK fields retain their order and raw values; flags, ID, status and
other frames are preserved. The automatic banner data stream is relayed
unchanged, with each direction's EOF forwarded by half-close. Every accepted
handshake, control frame and data chunk logs original and intended forwarded
hex **before** `sendall`. In a failed report, those entries are not delivery
proof. Even a successful local send requires packet and peer observations for
acceptance.
Proxy `completed` means only that its ACK and relay ran to completion. It is
**not** proof the Classic app accepted a variant. B46/B47 established the
baseline across client, namespace, host and server captures. B52's modified
cases have separate five-view delivery and subsequent client-request proof.
The `server-name-162` variant requires native 161=`0000` and **no** existing
162, then appends one 14-byte ASCII value. The [native login-extra
corpus][native162] proves that the server's nonempty configured name is emitted
as 162. One [actual Classic session][classic162] accepted `fixture-native`
through login, roster, and banner data. Its UI meaning remains unproved.
The expected full 52-byte ACK and SHA-256 are:

```text
0001000000000001000000000000002000000020000300a0000200be00a10002000000a2000e666978747572652d6e6174697665
3f5185b7bc222e684697fd2fce46ff0f625bc13ddf301e8a787bfe47594caedb
```

B56 stopped before connection because its proxy output leaf already existed;
B57 used a fresh leaf and completed the single ASCII case. B57's 28-second
cutoff was intentional, not a client rejection. No alternate payload, width,
codec, banner rendering or whole-profile policy is established.

## Automatic observation cutoff (B27 preparation)

An independent proxy watchdog starts before the first control accept. Only
**after** the first matching successful Login107 ACK `sendall` returns does it
arm at monotonic ACK time plus 28 seconds. Its receipt records the original
and forwarded ACK SHA-256 values, trigger, due time, actual firing time and
last owned-socket close and final relay-teardown times. The latter determines
30-second validity even when a relay join finishes late. The ACK trigger is
a local write completion; packet captures must still prove client delivery.
The 28-second target leaves
margin for the required <=30-second observation limit. A later close is
`timing-invalid`, never successful tolerance evidence.

At expiry the watchdog closes only proxy-owned control/data sockets and
listeners. Accepted sockets racing with expiry are closed on registration.
Relay errors from this intentional close are kept separate from real source,
protocol or I/O failures. One control half-close leaves the timer armed;
completion of both control relay directions cancels it. A native
source mismatch remains a failure. A valid timer stop is reported as
`intentional-observation-cutoff`, distinct from the proxy's natural
`completed` status and from peer acceptance. The proxy writes the final
bounded report with its PID and timing receipt; unexpected timer or report
failure invalidates the case. The app and native server remain separately
owned. The existing 180-second process cap and system-service
`RuntimeMaxSec=180` still apply.

The route check calls fixed `/usr/sbin/ip`, so it does not depend on the
service's minimal `PATH`. A read-only guard call under `env -i PATH=/usr/bin`
as UID 1000 inside the actual client namespace returned inode `4026532479`.
It opened no listener or backend connection. Recheck identity on future use.

## Offline checks and remaining gate

The [B29 synthetic corpus][rehearsal] records a direct UID/GID 1000 system
service in a fresh private namespace with fake local 15500/15501 upstreams.
It passed the exact baseline ACK, later 109 and data bytes, then closed after
a client half-close at ACK plus `28.097680969` seconds with a valid intentional
cutoff. The child PID was gone and the owned unit stopped. B30 timed out before
Connect; B31's one Connect click left the dialog open and produced no SYN.
Both are zero-contact failures. B42/B43/B45 also stopped before client
contact. B46 reached Login107/109 before its cutoff; B47 accepted the known
agreement and reached 121/300/212 plus automatic banner data. Their
[portable corpus][baseline] has the five-view raw bytes and finite UI
observations. These two baseline cases do not test altered 161 widths or
omission; the later [B52 matrix][matrix] does. Neither corpus tests field 162
or broader interoperability. The [Mothra handoff][handoff]
details the earlier synthetic and zero-contact evidence limits.

From the protocol-docs repository:

```sh
ruff format --check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ruff check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ty check --python ../mothra/tools/ghidramcp/.venv/bin/python \
  scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
python3 -m unittest discover -s scripts -p 'test_classic_login_proxy.py'
```

Sixteen tests cover ACK preservation and rebuilt widths/counts, ID/status and
native-value rejection, malformed/fragmented input, socket-pair byte and EOF
relay, no-forward rejection, deadline/log bounds, and the host namespace
check, plus inaccessible `/proc/1` and host-sysfs discrepancy regressions.
A nonlocal-route fault also fails the guard. New fake-clock and socket-pair
controls cover ACK-only arming, failed send, shared socket closure, one-sided
half-close, and late close or relay-teardown invalidity. They open no native
or guest listener. The B46/B47 live receipts establish direct-system-service
lifecycle, namespace route proof, client data-port selection and baseline
wire/UI continuation. For a future run, frontload the exact A7 242-byte
agreement check, stage the dialog before starting the proxy, and use one
Return to activate Connect. Escape may dismiss the exact known idle Aros
display if it obscures the guest. On the known agreement dialog, click Agree
promptly within the independent 28-second window; B46 shows why a delayed
click cannot test acceptance. Recheck identities, capture readiness and
housekeeping prompts on every run. Unexpected egress, extra connection,
packet gap or app-route ambiguity stops any modified case.

The supervisor raised source limits from 350 to 430 for frame, thread,
deadline and log safeguards, then to 500/540 for watchdog and cleanup.
Tests rose from 180 to 230 for real UID 1000 `/proc` and sysfs guards, then
to 300/325/375 for half-close and timing controls. B54 allows 560 source,
450 test and 190 guide lines for the fixed 162 variant; no guard was waived.

## Read-only actual namespace guard receipt

On 2026-11-13, the live client emulator PID was `1012834`, with executable
SHA-256 `9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`.
The host netns inode was `4026531840`, and the emulator netns inode was
`4026532479`. A read-only `nsenter -t 1012834 -n` followed by UID/GID 1000
`setpriv` called only `namespace_guard(4026532479, 4026531840)`. It returned
`4026532479`. This proves that guard call in that observed context, not
listener, backend, proxy or Classic-client readiness. Recheck both inodes and
process identity before any future service launch.

[rehearsal]: ../mothra/evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01/
[handoff]: ../mothra/docs/delegation/classic-proxy-rehearsal.md
[baseline]: classic-native-baseline.md
[matrix]: classic-field161-matrix.md
[classic162]: classic-server-name-162.md
[native162]: ../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json
