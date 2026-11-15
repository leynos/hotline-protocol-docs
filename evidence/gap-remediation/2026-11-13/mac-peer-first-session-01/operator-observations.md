# B13 operator observations and provenance limits

These notes transcribe observations from the B13 tool transcript and ignored
local report. They are **not** original recorder log files. The final PCAPs,
their bytes, and packet counts can be checked independently with
`verify_mac_peer_first_session.py`.

- Host recorder command observed before client launch:

  ```sh
  sudo -n tcpdump -i lo -s 0 -U \
    -w \
    state/native-sessions/mac-peer-first-01/b13-session-01/host-loopback.pcap \
    'tcp port 15500'
  ```

  The initial ready file was 24 bytes, the PCAP header only. The recorder was
  stopped with SIGINT at 17:53:21 UTC. Its terminal output was observed as
  `23 packets captured`, `46 packets received by filter`, and
  `0 packets dropped by kernel`; that output was not saved raw. The retained
  host PCAP has 23 packet records. The
  zero-drop line is an operator observation, not an independently replayable
  proof of zero capture loss.
- Client emulator PID 3696275, display `:101`, FD 6 on its disposable
  `hotline-client-candidate-01/working.dsk`, FD 16 on
  `state/native-sessions/mac-peer-first-01/client-guest.pcap`. Server emulator
  PID 1099659, FD 6 on its existing `hotline22-recovery/working.dsk`, FD 16 on
  `state/native-sessions/recovery-20261113-01/guest.pcap`.
  Both were still running after the client app quit. No VM was restarted for
  B13.
- 17:44:41 UTC: launched the HFS-installed Classic app once. The first-run
  wizard's Finish action offered external auto-connect, so it was cancelled.
  The proposed display name was not retained.
- 17:48:04 UTC: clicked manual Connect once for `10.0.2.2:15500` with the
  controlled fixture login. Host SYN: 17:48:04.729501. First external HTTP
  GET: 17:48:07.713126,
  before agreement acceptance.
- 17:49:17 UTC: first agreement click only woke the screen saver. 17:49:48 UTC:
  second click accepted the 242-byte controlled 109 text, previously compared
  with the UI. The client showed Connected and one roster user `unnamed`.
- 17:52:13 UTC: clicked Disconnect. Host FIN: 17:52:13.506772. 17:52:27 UTC:
  quit client with Cmd+Q. No second Connect or app restart occurred. The
  external HTTP exchange caused the local-only safety stop.
- The control PCAP's last numbered client request, kind 212 id 4, began at
  17:49:49.111363. The client FIN followed 144.395409 seconds later; the
  control SYN-to-FIN interval was 248.777271 seconds. No type 500 appears in
  the complete captured control stream. These finite observations do not
  validate the planned quiet test, a scheduling rule, or a generic tolerance
  policy because automatic external traffic occurred and the run was stopped
  for safety.
- A second client guest TCP lifetime to `10.0.2.2:15501` began at
  17:49:49.152668. The
  client guest source port was 49155; the server guest's NAT source port was
  36936 to server guest port 5501. Both guest views contain identical 16-byte
  HTXF request with reference `00038325` and identical 58-byte response
  beginning `GIF89a`.
  The host recorder filter selected only port 15500, so it cannot prove
  data-stream parity.
- The candidate archive was labelled 1.9.2, while retained Classic `vers`
  resources said 1.9.1.0. The executable's vendor authenticity and precise
  release identity remain unproved. The B12 report and staged-fork manifest are
  separately retained as a copied report and raw JSON manifest; the former
  reports the observed HFS Finder round trip and unchanged data/resource
  SHA-256 values.
