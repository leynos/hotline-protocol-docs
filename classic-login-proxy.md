# Classic Login107 field-161 proxy: preparation only

This tool prepares a bounded *future* GAP-081 Classic client experiment. It
has not opened listeners or connected to the native server. A guard-only,
read-only call ran as UID 1000 inside the actual client namespace.
It is protocol-specific: no mothra generic bridge, client app, native server,
account, or configuration changes were made in this milestone.

## Fixed topology and authority boundary

The proxy is intended to run **inside the already isolated client network
namespace** under a future direct system service with `User=1000` and
`NetworkNamespacePath=` set to the verified client namespace. A user service
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
Classic app would use guest `10.0.2.2:15652`, allowing its automatic data
fetch on 15653; confirming that client data-port selection needs a separate
runtime baseline. There is no arbitrary backend address or production port
option. This route must be reviewed with the actual service and namespace
identity before any client run.

The process accepts at most one control connection and at most one data
connection, then closes the listeners. It has a 180-second monotonic deadline,
short socket timeouts, and an aggregate raw/forwarded JSON log cap below 1 MiB.
A future service should also set `RuntimeMaxSec=180` as an independent process
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

| Variant | Field 161 sent to Classic client |
| --- | --- |
| `baseline` | Original two bytes `0000`, with exact full ACK byte equality |
| `omit-161` | Field removed; count and body sizes rebuilt |
| `one-byte-161` | One byte `00`; count and body sizes rebuilt |
| `four-byte-161` | Four bytes `00000000`; count and body sizes rebuilt |

All other ACK fields retain their order and raw values; flags, ID, status and
other frames are preserved. The automatic banner data stream is relayed
unchanged, with each direction's EOF forwarded by half-close. Every accepted
handshake, control frame and data chunk logs original and intended forwarded
hex **before** `sendall`. In a failed report, those entries are not delivery
proof. Even a successful local send requires packet and peer observations for
acceptance.
Proxy `completed` means only that its ACK and relay ran to completion. It is
**not** proof the Classic app accepted the variant. The first authorised live
case must be `baseline`, with host/client/server wire and UI parity against
B21. Only a separate review may allow modified cases after that baseline.
No 162 mutation is implemented here.

## Automatic observation cutoff (B27 preparation)

An independent proxy watchdog starts before the first control accept. Only
**after** the first matching successful Login107 ACK `sendall` returns does it
arm at monotonic ACK time plus 28 seconds. Its receipt records the original
and forwarded ACK SHA-256 values, trigger, due time, actual firing time and
last owned-socket close time. This is a local write-completion trigger; the
packet captures must still prove client delivery. The 28-second target leaves
margin for the required <=30-second observation limit. A later close is
`timing-invalid`, never successful tolerance evidence.

At expiry the watchdog closes only proxy-owned control/data sockets and
listeners. Accepted sockets racing with expiry are closed on registration.
Relay errors from this intentional close are kept separate from real source,
protocol or I/O failures. Natural control EOF cancels the timer; a native
source mismatch remains a failure. A valid timer stop is reported as
`intentional-observation-cutoff`, distinct from the proxy's natural
`completed` status and from peer acceptance. The proxy writes the final
bounded report with its PID and timing receipt; unexpected timer or report
failure invalidates the case. The app and native server remain separately
owned. The existing 180-second process cap and future system-service
`RuntimeMaxSec=180` still apply.

The route check calls fixed `/usr/sbin/ip`, so it does not depend on the
service's minimal `PATH`. A read-only guard call under `env -i PATH=/usr/bin`
as UID 1000 inside the actual client namespace returned inode `4026532479`.
It opened no listener or backend connection. Recheck identity on future use.

## Offline checks and remaining gate

From the protocol-docs repository:

```sh
ruff format --check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ruff check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ty check --python ../mothra/tools/ghidramcp/.venv/bin/python \
  scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
python3 -m unittest discover -s scripts -p 'test_classic_login_proxy.py'
```

Fifteen tests cover ACK preservation and rebuilt widths/counts, ID/status and
native-value rejection, malformed/fragmented input, socket-pair byte and EOF
relay, no-forward rejection, deadline/log bounds, and the host namespace
check, plus inaccessible `/proc/1` and host-sysfs discrepancy regressions.
A nonlocal-route fault also fails the guard. New fake-clock and socket-pair
controls cover ACK-only arming, failed send, shared socket closure, early-EOF
cancellation and late-cutoff invalidity. They open no native or guest
listener. Actual direct-system-service
lifecycle, namespace route proof, client data-port behavior, baseline wire/UI
parity and error cleanup remain untested runtime gates. A future failed
baseline stops before any modified 161 case; unexpected egress, extra
connection, packet gap or app-route ambiguity also stops the experiment.

The original 350 physical production-line budget was increased to 430 by the
supervisor. This **+80-line allowance** retains explicit frame validation,
thread/deadline cleanup and bounded audit logging. The test budget increased
from 180 to 230 physical lines to model actual unprivileged `/proc` denial
and namespace-independent sysfs observations. No safeguard was waived.
B27 then raised production to 500 and finally 540 physical lines for explicit
watchdog receipt, outcome arbitration and owned-socket cleanup. Tests rose to
300 and then 325 to keep natural-EOF and data half-close controls. Production,
tests and this document remain within their revised bounds.

## Read-only actual namespace guard receipt

On 2026-11-13, the live client emulator PID was `1012834`, with executable
SHA-256 `9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4`.
The host netns inode was `4026531840`, and the emulator netns inode was
`4026532479`. A read-only `nsenter -t 1012834 -n` followed by UID/GID 1000
`setpriv` called only `namespace_guard(4026532479, 4026531840)`. It returned
`4026532479`. This proves that guard call in that observed context, not
listener, backend, proxy or Classic-client readiness. Recheck both inodes and
process identity before any future service launch.
