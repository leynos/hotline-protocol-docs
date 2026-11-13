# Classic Login107 field-161 proxy: preparation only

This tool prepares a bounded *future* GAP-081 Classic client experiment. It
has not been launched in a guest namespace or connected to the native server.
It is protocol-specific: no mothra generic bridge, client app, native server,
account, or configuration changes were made in this milestone.

## Fixed topology and authority boundary

The proxy is intended to run **inside the already isolated client network
namespace** under a future direct system service with `User=1000` and
`NetworkNamespacePath=` set to the verified client namespace. A user service
that runs `sudo`/`nsenter` is not an approved substitute. On startup it rejects
the host network namespace, any interface besides `lo`, and any IPv4/IPv6 main
table route. It binds only `127.0.0.1:15652` for control and
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
handshake, control frame and data chunk logs original and forwarded hex.
Proxy `completed` means only that its ACK and relay ran to completion. It is
**not** proof the Classic app accepted the variant. The first authorised live
case must be `baseline`, with host/client/server wire and UI parity against
B21. Only a separate review may allow modified cases after that baseline.
No 162 mutation is implemented here.

## Offline checks and remaining gate

From the protocol-docs repository:

```sh
ruff format --check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ruff check scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
ty check --python ../mothra/tools/ghidramcp/.venv/bin/python \
  scripts/classic_login_proxy.py scripts/test_classic_login_proxy.py
python3 -m unittest discover -s scripts -p 'test_classic_login_proxy.py'
```

Nine tests cover ACK preservation and rebuilt widths/counts, ID/status and
native-value rejection, malformed/fragmented input, socket-pair byte and EOF
relay, no-forward rejection, deadline/log bounds, and the host namespace
check. They open no native or guest listener. Actual direct-system-service
lifecycle, namespace route proof, client data-port behavior, baseline wire/UI
parity and error cleanup remain untested runtime gates. A future failed
baseline stops before any modified 161 case; unexpected egress, extra
connection, packet gap or app-route ambiguity also stops the experiment.

The original 350 physical production-line budget was increased to 430 by the
supervisor. This **+80-line allowance** retains explicit frame validation,
thread/deadline cleanup and bounded audit logging instead of compressing
those safeguards. The preparation implementation is under the revised bound;
tests remain under 180 lines and this document under 120 lines.
