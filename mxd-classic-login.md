# Classic client login against an isolated mxd fixture

The first actual Classic Mac client attempt reached the isolated
`mxd-wireframe-server` fixture described in the [C20 workflow][workflow]. The
[redacted A22 corpus][corpus] retains one masked-dialog screenshot,
failed-login alert, quit screen, exact control headers and C19 service
receipts. Its raw PCAPs and owned secret remain ignored because the login
packet contains complemented credential bytes. Public metadata alone cannot
replay the credential-prefix finding; the [private verifier][verifier] can.

The client sent `TRTPHOTL00010002` and received `TRTP00000000`, then sent
request 107/ID 1 with fields 105 length 12, 106 length 31 and 160 length 2. mxd
returned a type-0/reply-marker-1/ID-1 **status-1 empty** reply. The GUI
reported that the connection was closed. One Connect click was made, followed
by File > Quit. The namespace capture was ready before the attempt and reported
14 packets, zero kernel drops. Guest and namespace application streams matched
in the private replay; no new native 15500/15501 SYN occurred.

The owned seed password was 48 ASCII characters; field 106 held only its
complemented first 31 bytes. The full secret was not sent. That is a measured
truncation on this input, without evidence whether the UI or encoder imposed it
or that 31 is a universal wire limit. Authentication failed before
successful-login fields 161/162, roster 300 or banner 212 could be observed.
This result therefore does **not** test those mxd behaviours, nor show a
login-extras incompatibility. The [C20 runtime record][runtime] confirms the
separate mxd daemon was stopped afterwards and port 15650 was clear.

A future retry needs a newly authorized, owned, shorter-secret fixture and
another bounded one-connect capture. Do not relabel this failed attempt as a
successful Classic compatibility witness.

[workflow]: mxd-peer-capture-workflow.md
[corpus]: ../mothra/evidence/gap-remediation/2026-11-13/mxd-classic-login-01/manifest.json
[verifier]: ../mothra/scripts/verify_mxd_classic_login.py
[runtime]: ../mothra/docs/delegation/mxd-peer-runtime.md
