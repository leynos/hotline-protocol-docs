# Classic client acceptance of one ASCII server-name field

The [portable corpus][corpus] records one controlled field-162 ACK modification
on 14 November 2026. The
[native](../glossary.md#native) [Hotline Server 1.9](../glossary.md#hotline-server-19)
sent a successful 34-byte Login107 ACK with 160=`00be`, 161=`0000`, and no
162. The [fixed proxy][proxy] appended one field 162 containing the 14 ASCII
bytes `fixture-native` and forwarded a 52-byte ACK. Its SHA-256 is
`3f5185b7bc222e684697fd2fce46ff0f625bc13ddf301e8a787bfe47594caedb`; the native
ACK SHA-256 is
`814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0`. The other
fields, header ID/status/flags, all later control frames, and both data
directions were unchanged.

This document belongs to the [peer implementations](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

The identified Classic client sent Login107, received the exact controlled
242-byte 109 agreement, and accepted it once. It then sent 121, 300, and 212;
the native server returned the corresponding replies and roster. The 212
reference matched the 16-byte `HTXF` data header, and 58 `GIF89a` bytes reached
the client. The UI showed Connected and roster transfer. It still showed
**Loading banner image**; successful image rendering is unproved.

Five retained, complete SYN lifetimes include their TCP tails: client guest,
proxy namespace ingress and upstream, host loopback, and server guest. Their
streams show the one ACK delta. Proxy audit entries are checked against the
actual wire bytes by direction; audit order across threads is not a total
packet order. The proxy intentionally closed the connection after 28.196
seconds, within its 30-second teardown bound. The subsequent **Connection
Closed** alert is therefore not a peer rejection.

Before and after the trial, a full 29-action A7 readback passed: two accounts,
41 Files entries, the same 242-byte agreement, and a 1,049,073-byte FILP
transfer with matching DATA and MACR forks. Managed host and client-namespace
recorders passed PID, namespace, writable FD, header and deadline readiness
checks; both journals report zero kernel drops. The proxy and recorder units
ended with MainPID 0. Original server and client emulator PIDs, working-disk
FDs, guest-PCAP FDs and namespace identities remained intact.

The corpus also preserves B56, a separate **zero-contact setup failure**. Its
proxy was given an already-existing output directory and exited with
`FileExistsError` before listening. The client never activated Connect;
namespace PCAP contains only its 24-byte header, and client guest PCAPs match
before and after. Full A7 readbacks passed on both sides of that failed setup.
B56 supplies no field-162 acceptance or rejection evidence.

The archive and app label say **1.9.2** while embedded `vers` says **1.9.1.0**;
DATA/RSRC hashes, source paths and frozen as-run proxy/parser revisions are in
the manifest. Neither label proves vendor authenticity. This one ASCII value
was tolerated through the observed login, roster and data stages. The field's
UI meaning, non-ASCII values, alternative widths, banner rendering, and a
complete client interoperability profile remain unproved.

Replay in adjacent `mothra` and `hotline-protocol-docs` checkouts:

```sh
cd ../mothra
sha256sum --quiet -c evidence/gap-remediation/2026-11-14/classic-server-name-162-01/SHA256SUMS
cd ../hotline-protocol-docs
python3 scripts/verify_classic_server_name_162.py \
  evidence/gap-remediation/2026-11-14/classic-server-name-162-01
python3 -m unittest discover -s scripts -p 'test_classic_server_name_162.py'
```

> Record note (2026-11-16): the commands above are quoted as they were run. The
> tests have since moved to `scripts/tests/` and run under pytest; the same
> tests now run with
> `uv run --group dev pytest scripts/tests/test_classic_server_name_162.py`.

[corpus]: ../../evidence/gap-remediation/2026-11-14/classic-server-name-162-01/
[proxy]: classic-login-proxy.md
