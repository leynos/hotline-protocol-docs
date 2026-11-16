# Peer implementations

This set records what the documents establish about the peers that the protocol
work uses as interoperability targets. It covers two client builds: the
[Classic client](../glossary.md#classic-client), an identified Classic Mac
candidate, and [shx](../glossary.md#shx), a client of the
[SynHX family](../glossary.md#synhx). For each it gives the build identities,
the rules for assigning a peer to a profile, and the exchanges observed with
controlled servers. Neither peer's release label is taken as its identity. The
archive label and the embedded version resource disagree for the Classic
candidate, and its vendor authenticity is unproved. The wire-level claims that
these observations support are in the
[protocol guide](../protocol/protocol.md). The native server runs that some
records use as their fixture are in the
[native evidence](../native-evidence/README.md) set, and the mxd checks against
these peers are in the [mxd](../mxd/README.md) set.

## Where to start

1. Read [Peer profile rules](peer-profile-rules.md) first. It defines what a
   profile is, gives the two evaluated builds and states the rule for a peer
   that matches no profile. Every other document assigns its results to one of
   these profiles.
2. Read the shx documents next:
   [Identified client source](identified-client-source.md), [shx build record](shx-peer.md)
   and [Peer tolerance matrix](peer-tolerance-matrix.md). The source profile
   comes first, because the matrix extends it.
3. Read the Classic documents, starting with
   [Classic login proxy](classic-login-proxy.md). The baseline, field-161 and
   field-162 records all run through that fixed proxy. Then read the
   [Classic native baseline](classic-native-baseline.md), the
   [Classic field-161 matrix](classic-field161-matrix.md), the
   [Classic server-name 162](classic-server-name-162.md) and
   [Classic roster subject 115](classic-roster-subject-115.md).
4. Read the two session records last,
   [Mac peer first session](mac-peer-first-session.md) and
   [Mac peer isolated session](mac-peer-isolated-session.md). Each records one
   connection from raw captures, so they are easier to compare once the
   proxy-based records are known.

## Documents

The documents use the glossary's names for the peers.
[Classic client](../glossary.md#classic-client) names the Mac PowerPC candidate.
[shx](../glossary.md#shx) names the client build evaluated here.
[SynHX family](../glossary.md#synhx) names the family as a whole, and no
document in this set concerns a SynHX server. The source documents also say
identified client for a client build identified by the hashes of its
executable. The [glossary](../glossary.md) has no entry for that phrase, so
this overview uses it only as those documents do.

Four kinds of document appear in the set. A reference is a profile, rule or
tool that other documents apply. A record is a retained account of how a build
was made, kept as written. A matrix is a table of cases and their observed
results. A witness is the retained record of a run that was executed, with its
observed exchanges.

| Document                                                    | What it covers                                                                                                                                                                           | Kind      |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------- |
| [Peer profile rules](peer-profile-rules.md)                 | The two evaluated profiles, the Classic client and shx 0.1.48, with their executable identities, and the rules for assigning a peer to a profile. Concerns both peers.                   | reference |
| [Identified client source](identified-client-source.md)     | The retained source revision of shx 0.1.48, its applicability to configured builds, and the bounded results of the callbacks recorded against it. Concerns shx.                          | reference |
| [shx build record](shx-peer.md)                             | The build of shx 0.1.48 from frozen inputs: its compatibility patch, local dependencies and the modern Linux build. Concerns shx.                                                        | record    |
| [Peer tolerance matrix](peer-tolerance-matrix.md)           | Five cases in which shx 0.1.48 received deliberately altered frames from a controlled loopback receiver. The document states that this is not execution of the Mac server. Concerns shx. | matrix    |
| [Classic login proxy](classic-login-proxy.md)               | The fixed proxy that carried Classic client logins to the native server, its network-namespace boundary and what it changes on the acknowledgement. Concerns the Classic client.         | reference |
| [Classic native baseline](classic-native-baseline.md)       | Two controlled attempts through the proxy's baseline variant, against native Hotline Server 1.9 (B46 and B47). Concerns the Classic client.                                              | witness   |
| [Classic field-161 matrix](classic-field161-matrix.md)      | Three zero-valued field-161 shapes in the Login107 acknowledgement, and the client progression that each produced. Concerns the Classic client.                                          | matrix    |
| [Classic server-name 162](classic-server-name-162.md)       | One appended ASCII field 162 in the Login107 acknowledgement, and the client's acceptance of it. Concerns the Classic client.                                                            | witness   |
| [Classic roster subject 115](classic-roster-subject-115.md) | One session in which the Classic client received a roster reply carrying an outer field 115. Concerns the Classic client.                                                                | witness   |
| [Mac peer first session](mac-peer-first-session.md)         | One manual connection from the Classic candidate to the controlled fixture on 13 November 2026. The replay stopped as a partial session. Concerns the Classic client.                    | witness   |
| [Mac peer isolated session](mac-peer-isolated-session.md)   | One controlled login by the Classic candidate against the native guest, in a loopback-only namespace, checked against the raw streams. Concerns the Classic client.                      | witness   |
| [Evidence index](evidence.md)                               | The corpora, ledger identifiers and gap identifiers that the documents of this set cite, with the documents and sections that cite each. Generated by `tools/check_evidence.py`.         | reference |

_Table 1: The documents of the peer set, the peer each concerns and their
kinds._

## Evidence

Each document cites its retained corpus under `evidence/gap-remediation/`, and
most name the check that replays it. Three representative corpora:

- [shx build inputs](../../evidence/gap-remediation/2026-11-13/shx-build-01/inputs.json),
  the frozen inputs of the shx 0.1.48 build.
- [Native shx full corpus](../../evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json),
  the complete shx sessions cited by the source profile.
- [Classic field-161 corpus](../../evidence/gap-remediation/2026-11-14/classic-field161-01/manifest.json),
  the three field-161 variants of the Login107 acknowledgement.

Some documents describe checks that run from an adjacent `mothra` checkout. The
toolset that captured the evidence is described in the
[mothra README](https://github.com/leynos/mothra/blob/2278968b622eab731e4ba2be0484cedfbab73bb7/README.md).
How each corpus is produced and re-verified is set out in
[Recreating the evidence](../native-evidence/recreating-evidence.md).

## Open questions

The gaps below are those that the documents of this set name. The
[ledger of remaining evidence work](../provenance/remaining-evidence-work.md)
gives a status and a title only for the gaps in its table of unresolved gaps.
For the other gaps it gives neither, and this overview gives neither.

| Gap                                      | Status in the ledger | Title in the ledger                  |
| ---------------------------------------- | -------------------- | ------------------------------------ |
| [GAP-018](../../gap-analysis.md#gap-018) | Investigating        | Text encoding and transformations    |
| [GAP-026](../../gap-analysis.md#gap-026) | Investigating        | Meaning and lifetime of login extras |
| [GAP-071](../../gap-analysis.md#gap-071) | Investigating        | Account field 111                    |
| [GAP-082](../../gap-analysis.md#gap-082) | Investigating        | Heuristic text-decoding policy       |
| [GAP-079](../../gap-analysis.md#gap-079) | Not in the ledger    | Not stated in the ledger             |
| [GAP-080](../../gap-analysis.md#gap-080) | Not in the ledger    | Not stated in the ledger             |
| [GAP-081](../../gap-analysis.md#gap-081) | Not in the ledger    | Not stated in the ledger             |
| [GAP-083](../../gap-analysis.md#gap-083) | Not in the ledger    | Not stated in the ledger             |

_Table 2: Gaps named by the peer documents, with the status and title that the
ledger gives them._

## Related sets

- [Protocol guide](../protocol/protocol.md): the wire claims that the peer
  observations support.
- [Native evidence](../native-evidence/README.md): the native server runs that
  the Classic records use as their fixture.
- [mxd validation](../mxd/README.md): the mxd checks against these peers, which
  are on hold.
- [Provenance](../provenance/README.md): the records of the Classic candidate's
  static identity, and the ledger of remaining evidence work.
- [Glossary](../glossary.md): the defined terms used here.
