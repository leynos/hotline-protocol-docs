# Native 1.9 persisted-ban reload witness

This is one read-only restart observation of the disposable server image that
held the [C56 option-two control ban](native-ban-control-witness.md). The
profile is `persisted-ban-reload-readonly`; `full_file_baseline=not_exercised`.
The C35, C45 and C50 full-file baseline failures remain linked through the C56
corpus. This witness does not validate the configured-ban application producer
`10006590` or a type-104 connected-session notice.

## Pinned stopped image and UI

Before boot, the owned image was FD-free and SHA-256 `3717cd5e…`, exactly the
C56 stopped-image hash. Its `/Hotline19/Banned` data fork was 49 bytes, SHA-256
`53bec376…`; the original `admin` and `fixture-low` UserData and the owned
zero-access `m-ban52-only` UserData were read back and hashed. The immutable
source base, ROM, emulator and server DATA identities were checked. No account
or ban entry was added, cleared or edited.

The C61 boot used a distinct loopback namespace and frontend `127.0.0.1:15750`.
Host primary-port and namespace recorders were active before any frontend
contact. The actual emulator was PID 415512, start 5324681, namespace
`net:[4026533397]`, UID 1000, with FD6 on the owned working image and FD16 on
the C61 guest capture. The original primary and client PIDs and disk/capture
FDs were recorded separately.

After the recognized disk-repair and sound prompts, the native server started
with zero clients. Opening Options and selecting **Ban** showed a checked
`10.0.2.2` row and `IP: 10.0.2.2`, with an empty Info field. The operator
clicked **Cancel** without editing, adding, deleting or saving. The
[C61/C62 corpus](../mothra/evidence/gap-remediation/2026-11-14/native-ban-reload-01/manifest.json)
retains timestamped UI actions, screenshots and their hashes. The resource
catalogue identifies menu `Options...`, but not the PowerPlant ban-list control
IDs; see [C60](native-configured-ban-ui-resources.md).

## One fresh Login 107

The sole C62 managed probe ran as UID 0 in the actual lab namespace. Its six
actions used the frozen C56 probe vector with only operator and GAP metadata
updated. It connected to the owned frontend, sent the 12-byte TRTP hello,
received the 8-byte server hello, sent a valid Login 107 for `m-ban52-only`
with ID 1, read one correlated reply and closed. Native returned wire type 0,
reply marker 1, status 1 and field 100 with the exact 42 ASCII bytes
`You are permanently banned on this server.`. No EOF deadline was asserted.
Complete namespace and guest TCP lifetimes match the recorder report byte for
byte, including their tails. No 110, account seed, ban change or Options Save
occurred in this run.

The server was quit normally. The guest emulator was then stopped with an
explicit **TERM** after verifying its PID, start, executable, image FD and
namespace. This was a **forced emulator termination**, not an orderly Mac OS
shutdown. The actual PID and all seven owned units were gone, and ports
15750–15753 were absent. The host primary-port SYN capture remained empty; both
recorders reported zero drops. The original primary and client identity/FDs
were unchanged. Only after the image was stopped and FD-free was `Banned` read
again; its 49 bytes match the preboot and C56 bytes exactly. This does not add
a second restart or a clean-shutdown durability proof.

## Offline replay and limit

From the protocol repository with adjacent Mothra evidence:

```sh
python scripts/verify_native_ban_reload.py ../mothra/evidence/gap-remediation/2026-11-14/native-ban-reload-01
python -m unittest discover -s scripts -p test_native_ban_reload.py -q
```

The replay verifies the C56 source corpus, C61 inventory and source hashes,
preboot Users/Banned state, read-only UI and capture gates, the exact
prepared/as-run probe relationship, managed root namespace, reply semantics,
paired packet streams, zero primary contact and terminal state. Its fault
controls change identity, error, handshake, vector, packet bytes, deadline,
drops, cleanup, stored ban bytes and UI claims while refreshing the outer
inventory where applicable.

The observed stored ban survived **one** restart sufficiently to appear in the
UI and reject a fresh Login 107. Connected-session application 104, expiry, all
protection cases and general server/full-file health remain open.
