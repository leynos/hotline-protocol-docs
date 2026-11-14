# Hotline 1.9 protocol documentation gap analysis

Reviewed on 2026-11-14: the corrected protocol guide, compatibility matrix and
correction map. This register tracks gaps in the specification after the
validity-ledger corrections. It does not reopen corrected findings or claim to
resolve the remaining unknowns.

The sweep records **87 gaps** across **477 reviewed document sections**. These
are documentation questions and proposed investigation priorities, not
confirmed binary defects, security severity ratings or mxd test failures.

## Scope, evidence and status

Preserve all87 original criteria and59 Resolved/27 Investigating/1 Open. Add
reviewed legacyboard preparation and explicitly pre-contact aborted lab
without claiming nativeboard outcomes. Record receipt/helper review and
managedlease/passivecapture rehearsal as tooling evidence, not protocol
conformance. Fresh runtime and future case remain separately gated. Further
mxd validation stays on hold.

The corrected documents deliberately contain unresolved statements. Unanswered
entries refine those into actionable questions. Missing and Ambiguous entries
record omissions or under-specified requirements found by this sweep. Evidence
entries need independent peer/runtime or mxd results; Decision entries need an
explicit scope or compatibility policy.

The prior oracle is the Mac PPC PEF data fork with SHA-256
`ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b`. The
[validity ledger](../mothra/docs/baseline-validity-ledger.md) and its hashed
snapshots are unchanged. Listed Ghidra functions are investigation leads from
that baseline. Dispositions cite subsequent evidence where available.

The initial audit had all entries Open and unassigned. Deferred means a
recorded scope/policy decision, not a solved protocol question. Resolved
requires cited evidence, the corrected documentation and a checked closure
criterion. A correction-map disposition or a function capture alone does not
close a gap.

### Priority meanings

| Priority | Meaning |
| --- | --- |
| P0 | Core codec, session/login or baseline-fixture work needed before claiming a usable core contract. |
| P1 | Blocks completion of the named feature or a cross-cutting compatibility policy if that feature is in scope. |
| P2 | Secondary operation semantics, evidence portability, peer coverage or project QA that still needs a recorded decision/result. |

These priorities are recommendations. GAP-001 and GAP-086 must establish the
actual supported subset and release criteria; this audit does not invent mxd
roadmap commitments. Client window rendering, tracker behaviour and HTTP
tunnelling remain outside the stated wire-guide scope and are not counted as
missing mandatory functionality.

### Counts

| Dimension | Counts |
| --- | --- |
| Priority | P0: 20, P1: 56, P2: 11 |
| Kind | Ambiguous: 10, Decision: 3, Evidence: 5, Missing: 12, Unanswered: 57 |
| Status | Investigating: 27, Open: 1, Resolved: 59 |

## Suggested investigation order

Begin with core field schemas, framing/error/ID rules, nonempty-password
encoding and the complete login state machine (GAP-002–GAP-025). Build
provenanced native session fixtures alongside that work (GAP-084). Then
complete presence/permission/message contracts, followed by the in-scope file,
transfer, news and administration schemas. Peer-corpus identification
(GAP-080) can proceed independently. Further mxd validation (GAP-085) remains
on hold; its findings and resumption instructions are retained in
mxd-validation.md. Dependency links identify shared prerequisite artefacts;
they do not imply the unknown question has already been answered.

## Input provenance

Audit captured at `2026-11-14T09:10:14.768919+00:00`. The source checkout has
Git HEAD `59de5f362fea36f0bd47e0a6fccbd7961f15501e` with modified/untracked
reviewed files. The hashes below identify the actual reviewed worktree
contents; HEAD alone does not. Source line ranges in entries refer to the
frozen snapshots, while section links point to the current documents.

| Reviewed input | SHA-256 | Frozen copy |
| --- | --- | --- |
| [protocol.md](protocol.md) | `c68c8c41b8b6524a5ec7f2390d9c5d14dea73d69474eea1b705378c8a31646d4` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/protocol.md.txt) |
| [internal-compatibility-matrix.md](internal-compatibility-matrix.md) | `dd8ec84cbc83bb8e6f94e157d8fea0bec3410e3196beff18ec37de110a5800d4` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/internal-compatibility-matrix.md.txt) |
| [baseline-correction-map.md](baseline-correction-map.md) | `08b3687d975dbd9ae9050d5d0b333d2c106b884f1d3d87a3a966cbbc604d7385` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/baseline-correction-map.md.txt) |
| [native-wire-details.md](native-wire-details.md) | `900303476877c62005ae71514728d74e7d5063d32e0a1cbf0ff26c4b6e31b565` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-wire-details.md.txt) |
| [operation-contracts.md](operation-contracts.md) | `7428f156f0924d9be1b36adfe013429041718a93ed22dea80c92e008af73adcb` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/operation-contracts.md.txt) |
| [transfer-contracts.md](transfer-contracts.md) | `6d2d069880c6b567caef5b46fac8ab8563b5f3e1d8273d5cec4221179aac8612` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/transfer-contracts.md.txt) |
| [news-contracts.md](news-contracts.md) | `9b935a8b19f0baf4cc19115692f80c40912d2d8683a40e991d67867483b88597` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/news-contracts.md.txt) |
| [presence-messaging-contracts.md](presence-messaging-contracts.md) | `23ee60d033c350837dde53239e5c2099119760ec852317f20a21453f02dc61b9` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/presence-messaging-contracts.md.txt) |
| [core-field-schemas.md](core-field-schemas.md) | `00b7af54c4ef8c153fcc495927e131dad2753b89cbe10b80a37d233f454f791c` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/core-field-schemas.md.txt) |
| [session-transport-contracts.md](session-transport-contracts.md) | `69c8ce987cad076344efe86d04391072f4c652e20becb7fe236c385dbde5cb1a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/session-transport-contracts.md.txt) |
| [filesystem-and-board-contracts.md](filesystem-and-board-contracts.md) | `2d658bdfb2947f2cd060facc5def374ceb348b32ee01cab6911fe8531683157f` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/filesystem-and-board-contracts.md.txt) |
| [evidence-portability.md](evidence-portability.md) | `571225c97f9a1a3cae23363fb4d215886c77746d5df9ebc266eae56cd0221c14` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/evidence-portability.md.txt) |
| [error-outcomes.md](error-outcomes.md) | `7c0ede126803b9c15c6c6dfa3017d8c3e885d326c653e6cae57f104445e9bb35` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/error-outcomes.md.txt) |
| [identified-client-source.md](identified-client-source.md) | `ea5097f26bad3bc396ca543a88d2cd644950e1a15cb539e9bb46208ec4a5128a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/identified-client-source.md.txt) |
| [privilege-contracts.md](privilege-contracts.md) | `18cd1ad6f83920ea7cdd69c10888151335da2edcb4df7a36f9ee5f651fb860e0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/privilege-contracts.md.txt) |
| [native-capture-workflow.md](native-capture-workflow.md) | `c7f9741d06fb6c4d92fbca5154b907446fded3a5b54eeddab19aeaa827d58f4d` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-capture-workflow.md.txt) |
| [diagnostic-replies.md](diagnostic-replies.md) | `4e1b8ed87288de3b4570df24d1f40fa47b8825ebfe8664e085cd8934f2f70b06` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/diagnostic-replies.md.txt) |
| [peer-tolerance-matrix.md](peer-tolerance-matrix.md) | `989c948279211ce001071d0048e1d7a2fbed9a5c68c0d2a1558377b1c68535dc` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/peer-tolerance-matrix.md.txt) |
| [mxd-reconciliation.md](mxd-reconciliation.md) | `b101c9f12721b5ed16ba40ac7f63ec3515fbf80f0205fe58594f6807ebd295c9` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-reconciliation.md.txt) |
| [bitmap-boundaries.md](bitmap-boundaries.md) | `e2fa41eab31ec8b6e1aed0a26f41adb015c9c0ea7db1fd9b84fffc4d29c4ec98` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/bitmap-boundaries.md.txt) |
| [account-attribute-trace.md](account-attribute-trace.md) | `b64bd4dfb584f0e4cbb42db6f86159c495d89d7af0dfb869c0c5500b204143b1` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/account-attribute-trace.md.txt) |
| [mxd-limit-contracts.md](mxd-limit-contracts.md) | `50fd48d0503f8d0a15e18ef268421d3b034288257911d020e7c8fae1c68731be` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-limit-contracts.md.txt) |
| [failure-representatives.md](failure-representatives.md) | `27dea3d30c579e4638c5aa54191d3c46f29977957fa445fa5c91e5ddaa100c56` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/failure-representatives.md.txt) |
| [runtime-recovery-20261113.md](runtime-recovery-20261113.md) | `3a0f4ede01062a0a3cfc147ad508ab991ffc0c65ba1746f8939cf142a9c7cbb7` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/runtime-recovery-20261113.md.txt) |
| [receive-limit-origin.md](receive-limit-origin.md) | `9b61b70f8929f55b4279e8ea5b01871302739e263d450d84d3b07bd0ccbb0347` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/receive-limit-origin.md.txt) |
| [diagnostic-transfer-boundaries.md](diagnostic-transfer-boundaries.md) | `fad0fb66796ef317e9a9a8f9b1b05addcd200ddb3c914860de0b8db47fdf95f0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/diagnostic-transfer-boundaries.md.txt) |
| [mac-peer-first-session.md](mac-peer-first-session.md) | `bf97eb61d36d39108e76df85dceaea03769d793c2d0f63204a8467da6b09af9a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mac-peer-first-session.md.txt) |
| [native-diagnostic-existing-preparation.md](native-diagnostic-existing-preparation.md) | `ad15c2ed5ff4fa2eaba8df9e2fc22f8972ed66e30cbaadd8ae2119f660379ba6` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-diagnostic-existing-preparation.md.txt) |
| [native-diagnostic-existing-witness.md](native-diagnostic-existing-witness.md) | `ffa30a1b5c624715b3c59f36284c5b701f4759409fe40e3b21d1cab90aec8ec9` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-diagnostic-existing-witness.md.txt) |
| [native-diagnostic-density-witness.md](native-diagnostic-density-witness.md) | `bd59a4c90a51c163eebea280acc3c4efb1a9c129daa0c57d84a2583d4f3b4b8f` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-diagnostic-density-witness.md.txt) |
| [mxd-direct-ack-correction.md](mxd-direct-ack-correction.md) | `72bda2e0d279b44976f480ba7651f0f6f8f19e4bd285e74f8a392043d5a41ffc` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-direct-ack-correction.md.txt) |
| [mxd-login-extras-correction.md](mxd-login-extras-correction.md) | `ff0cd8772ee38802350954c5322c490052217cdb07fe25439ca2407168a1e827` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-login-extras-correction.md.txt) |
| [native-diagnostic-near-preparation.md](native-diagnostic-near-preparation.md) | `4cb5e050b99b5ef2d2a806578fdfb4361eaca0ff8531de84864a36c8bb4b12bc` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-diagnostic-near-preparation.md.txt) |
| [native-diagnostic-near-witness.md](native-diagnostic-near-witness.md) | `98e3f2742654ac1f4b75d6c52c0c354a5be207227c5f6fe2684b3f1b26e22f01` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-diagnostic-near-witness.md.txt) |
| [mac-peer-isolated-session.md](mac-peer-isolated-session.md) | `33086d1bf8a631f2bf047b5ac388aa4aff4def53ec2a0dd0d847b43ddb06f12b` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mac-peer-isolated-session.md.txt) |
| [request-500-contract.md](request-500-contract.md) | `8362b1780d50b6042f91d044b9f9c8c0c25ce4f7646dc251002e2e9ee138cbb8` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/request-500-contract.md.txt) |
| [native-console-broadcast.md](native-console-broadcast.md) | `01693a42d90d00042d5c8a7f1603046c244313bb1256073b755928fbd695fece` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-console-broadcast.md.txt) |
| [mxd-peer-capture-workflow.md](mxd-peer-capture-workflow.md) | `abd18f4d3202faf4de1e87c0f77b67ab01c59adce93da8135ef7e3c11698e277` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-peer-capture-workflow.md.txt) |
| [mxd-classic-login.md](mxd-classic-login.md) | `1bebe6593339823f012eede3816ecc99501e3ed45254af010ef947f0bbec5ec8` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-classic-login.md.txt) |
| [classic-login-proxy.md](classic-login-proxy.md) | `f46a333447d02ee66bbd2e2d835e0bdb93c258fd3aafd2bb0baa22f11f062a66` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-login-proxy.md.txt) |
| [mxd-validation.md](mxd-validation.md) | `fc5179617167558a7958534ae4496f1892852718cdfef0844b70734a1b7a9330` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/mxd-validation.md.txt) |
| [native-pm-preparation.md](native-pm-preparation.md) | `28df4cdaa33bf02240e4e614b8e508d7de78018a2b7536c800723803648d2714` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-pm-preparation.md.txt) |
| [native-pm-witness.md](native-pm-witness.md) | `94b2af274067b60eaec0f75b243911b61962783f55d92b7f76874b4d3fc71934` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-pm-witness.md.txt) |
| [native-104-variants.md](native-104-variants.md) | `51426947f3f49c2fcdd2e875bed0d0e3e1ae32e6387e310d877582a288347457` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-104-variants.md.txt) |
| [native-settings-preparation.md](native-settings-preparation.md) | `f91d179af7f6468122a04058d36c5f2d84db231a858294c0e3613d6268a4cb1e` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-preparation.md.txt) |
| [native-settings-witness.md](native-settings-witness.md) | `e6e81bdf254f973837cd2e2f672a16ead054a19f234893b365849d452bc3da5a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-witness.md.txt) |
| [native-ban-notices.md](native-ban-notices.md) | `7879f06d73ffd49fec2087f70a5ce80234e8273699497ca1d90be046ccd1b30c` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-notices.md.txt) |
| [parameter-multiplicity.md](parameter-multiplicity.md) | `bd7cbdc8be0561ec1b22f74e4e6413775f38516138b17d2460c06efe3b8ffea3` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/parameter-multiplicity.md.txt) |
| [native-transfer-stall.md](native-transfer-stall.md) | `caaff7459dcdeafc055be01ead0b617c14da30f56d801cf3d19d588858075339` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-transfer-stall.md.txt) |
| [native-settings-transition-prep.md](native-settings-transition-prep.md) | `1e5b739bb537635c2f6e742a4629c54271045574eb9423d9d88bcfc4279dfaad` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-transition-prep.md.txt) |
| [native-settings-transition-witness.md](native-settings-transition-witness.md) | `7748151b8471180c8844609231395a4c7b9b8456426f2d290d660eafe2cfa202` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-transition-witness.md.txt) |
| [native-download-send-path.md](native-download-send-path.md) | `b85e5c92b96a7f09b9cbdb504f6ec0300913c49c3f813f81ab0890991a97bc4a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-download-send-path.md.txt) |
| [classic-account-constructors.md](classic-account-constructors.md) | `7e292d53804e7fdf274f9b5aa65f6fde8311be62a9d1db6854ec1452e5958152` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-account-constructors.md.txt) |
| [native-121-default-preparation.md](native-121-default-preparation.md) | `ddf4534145c9785ba6f8d1c95953504ad05435eeb5b92bdd1c04d77524bc8c9b` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-121-default-preparation.md.txt) |
| [native-121-default-witness.md](native-121-default-witness.md) | `2caf385aa9417859fea49b52c7910744c3357620a141928be8ace483d15dbfd8` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-121-default-witness.md.txt) |
| [classic-native-baseline.md](classic-native-baseline.md) | `36b560f7b864691377c75d500262ae8a7e973350db050d102ececd0b265fde88` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-native-baseline.md.txt) |
| [native-ui-focus-witness.md](native-ui-focus-witness.md) | `1199f5e79a3535ee554713c0fbd0f54de953bf6a8b8741598cb1f83697e14e1e` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ui-focus-witness.md.txt) |
| [native-control-readiness.md](native-control-readiness.md) | `e6245be4429cea9a571102b28612acf87002cf0178de452c284025f55b6e792f` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-control-readiness.md.txt) |
| [classic-field161-matrix.md](classic-field161-matrix.md) | `4b3853cc15d8271826833c2029e21bd80989e48b2502c2eab6ee661f74400357` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-field161-matrix.md.txt) |
| [native-ban-control-preparation.md](native-ban-control-preparation.md) | `4b42ca3e3e86dd9d395f06c82810d809324bd28972b65316308b5daddf2ef2ca` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-control-preparation.md.txt) |
| [notification-104-variants.md](notification-104-variants.md) | `1f56ba0d55ab9dbfb848276742f562f534963af70ee4910b051805cfa9e3affe` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/notification-104-variants.md.txt) |
| [peer-profile-rules.md](peer-profile-rules.md) | `e4cf33c959a103ed5fe5ee5ec3687186470781c0ae27ac524602a1eeb14c9e98` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/peer-profile-rules.md.txt) |
| [native-settings-persistence-preparation.md](native-settings-persistence-preparation.md) | `50b1a08dd784fade9d608b9abb19884bf812ec7a105ea746c4fdfb5e0192ef7a` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-persistence-preparation.md.txt) |
| [native-ban-control-witness.md](native-ban-control-witness.md) | `15847edc9474e8b9f72c3fcf1a9a365c28b49cef6a0d43764787b424a7517579` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-control-witness.md.txt) |
| [classic-server-name-162.md](classic-server-name-162.md) | `bf52554c2cc4e49d5c4db13ad8374d11ef401c6303f6b4f33641d204a95e52bf` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-server-name-162.md.txt) |
| [native-configured-ban-static.md](native-configured-ban-static.md) | `2c5f5ae4ebb55ce3633f1ddba4c9f119f38662fbff16a66d4a4119695f143989` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-configured-ban-static.md.txt) |
| [native-configured-ban-ui-resources.md](native-configured-ban-ui-resources.md) | `2617da153c6c1717dc813e4e741f8e4390b055ea0e70649e68f0360a346783a2` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-configured-ban-ui-resources.md.txt) |
| [native-ban-reload-witness.md](native-ban-reload-witness.md) | `11e7574f03852b952b552315ff99d720f4dc40546b50651e07069a3af4866515` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-reload-witness.md.txt) |
| [native-settings-persistence-witness.md](native-settings-persistence-witness.md) | `ffb816b323a38c1be5986605a5a289ddac6dfa078011463ec7be166b08643edc` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-settings-persistence-witness.md.txt) |
| [classic-roster-subject-115.md](classic-roster-subject-115.md) | `19393fc904c23bdb3e00aea53b037443c81ce4667cf5355d0ff1b936ad3a8f11` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-roster-subject-115.md.txt) |
| [native-configured-ban-preparation.md](native-configured-ban-preparation.md) | `5e99de6f51fb35a35038a905c489896acfe50a95d150310b588d69aa74662b26` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-configured-ban-preparation.md.txt) |
| [native-configured-ban-witness.md](native-configured-ban-witness.md) | `de2cde35bdebec4ba18610e53aca9a19744f8de1b7f15dfd317888e9677369b9` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-configured-ban-witness.md.txt) |
| [diagnostic-formatting-trace.md](diagnostic-formatting-trace.md) | `76c8e6f9e50e3f41addf1d3a1519900f9d3608b36ca1da7b50b8821629a8ac38` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/diagnostic-formatting-trace.md.txt) |
| [native-ban-file-format.md](native-ban-file-format.md) | `2a5e22954333d3ff78744a9a2064a947966efe070340a3c30a362ca1cfb35bd2` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-file-format.md.txt) |
| [native-ban-expiry-preparation.md](native-ban-expiry-preparation.md) | `d1c989f27077774557bf1e30c7cb7aa0487715a22d0f551a4ae80676cc9060f0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-expiry-preparation.md.txt) |
| [native-roster-overlap-preparation.md](native-roster-overlap-preparation.md) | `cabdf6ad27993279488f3b56ccdf891731e0dc56db16c57e52a179af1f2e2a38` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-roster-overlap-preparation.md.txt) |
| [native-ban-expiry-cleanup.md](native-ban-expiry-cleanup.md) | `d413ab7e657bb35512e51b0e373e83f15c2a05f9bb28dd9cfdf08fd75265f4f0` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-expiry-cleanup.md.txt) |
| [native-ban-expiry-first-witness.md](native-ban-expiry-first-witness.md) | `12fe3131bdf1f774966ee4a395d9f9b812f09802b439ca6e45f59550a0688679` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-expiry-first-witness.md.txt) |
| [native-ban-expiry-later-witness.md](native-ban-expiry-later-witness.md) | `980314e97529c167ca856dfd553fac264e15c306eb121285e6362a611b49a6dc` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-ban-expiry-later-witness.md.txt) |
| [native-roster-overlap-witness.md](native-roster-overlap-witness.md) | `6d6ec0cf7a2797dc5f54720850634c3ba53636869a00b3b5b5572feba4c70da3` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-roster-overlap-witness.md.txt) |
| [account-write-ordering.md](account-write-ordering.md) | `3d9694b8c6b5406dace8846ff55d697c45a231cca28bed37a0f5bb97ad03d840` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/account-write-ordering.md.txt) |
| [native-liveness-preparation.md](native-liveness-preparation.md) | `c15735a056eae8ea8c8f0c99837168a4b573bd4ae6b67bf6391db245f7a4d390` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-liveness-preparation.md.txt) |
| [classic-privilege-discovery.md](classic-privilege-discovery.md) | `815740c7709d15d3d1b1c087d31935187bde18fcfc75952a944ef1b5f537d197` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/classic-privilege-discovery.md.txt) |
| [native-liveness-witness.md](native-liveness-witness.md) | `3bf97b206773e6edb187dbdc33d82cdcd8df632b31a2cb55600bfe03e28e527e` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-liveness-witness.md.txt) |
| [legacy-board-format.md](legacy-board-format.md) | `79d090b20e1491f141539392f3329b3ff73c2488c71c989fd096418527004fb4` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/legacy-board-format.md.txt) |
| [native-board-preparation.md](native-board-preparation.md) | `48e550e2658e5335c23ae08f7216d1a98d6d20a21e50fc149cf9547f3476ba31` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-board-preparation.md.txt) |
| [native-board-readiness-failure.md](native-board-readiness-failure.md) | `9e1187db75a645e12e88c9fd4a7b6022dc562566076f5405f96cb32d778d4134` | [Snapshot](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/inputs/native-board-readiness-failure.md.txt) |

[Audit
manifest](../mothra/evidence/protocol-gap-analysis/2026-11-14/revision-75/manifest.json);
[machine-readable register](gap-register.json). No field or behaviour is
silently made normative by being listed as a question.

## Gap index

| ID | Priority | Kind | Area | Question | Status |
| --- | --- | --- | --- | --- | --- |
| [GAP-001](#gap-001) | P1 | Decision | Specification | Define the supported 1.9 subset | Open |
| [GAP-002](#gap-002) | P0 | Missing | Specification | Canonical transaction and field schemas | Resolved |
| [GAP-003](#gap-003) | P0 | Missing | Specification | Error-code and failure-outcome registry | Resolved |
| [GAP-004](#gap-004) | P0 | Unanswered | Session and transport | Transaction ID lifecycle and correlation | Resolved |
| [GAP-005](#gap-005) | P0 | Missing | Session and transport | Connection timers and liveness | Investigating |
| [GAP-006](#gap-006) | P1 | Missing | Specification | Complete direction and reply-contract catalogue | Resolved |
| [GAP-007](#gap-007) | P0 | Missing | Session and transport | Allowed operations by session state | Resolved |
| [GAP-008](#gap-008) | P0 | Unanswered | Session and transport | Handshake failures and stream boundaries | Resolved |
| [GAP-009](#gap-009) | P1 | Unanswered | Session and transport | Sub-version 3 and direct HTXF relationship | Resolved |
| [GAP-010](#gap-010) | P1 | Unanswered | Session and transport | Listening endpoints and data-port arithmetic | Resolved |
| [GAP-011](#gap-011) | P0 | Unanswered | Framing and parsing | Frame, transaction and buffering limits | Investigating |
| [GAP-012](#gap-012) | P0 | Unanswered | Framing and parsing | Fragment reassembly edge cases | Resolved |
| [GAP-013](#gap-013) | P0 | Missing | Framing and parsing | Accepted envelope values and reserved bytes | Resolved |
| [GAP-014](#gap-014) | P0 | Unanswered | Framing and parsing | TLV structural validation | Resolved |
| [GAP-015](#gap-015) | P0 | Ambiguous | Values and encoding | Field-specific scalar types | Investigating |
| [GAP-016](#gap-016) | P0 | Ambiguous | Values and encoding | Absent, empty and zero-valued fields | Investigating |
| [GAP-017](#gap-017) | P0 | Unanswered | Framing and parsing | Repeated scalar fields and ordering | Resolved |
| [GAP-018](#gap-018) | P0 | Unanswered | Values and encoding | Text encoding and transformations | Investigating |
| [GAP-019](#gap-019) | P0 | Missing | Values and encoding | Semantic length limits and truncation | Investigating |
| [GAP-020](#gap-020) | P1 | Unanswered | Values and encoding | Date and timestamp semantics | Investigating |
| [GAP-021](#gap-021) | P1 | Ambiguous | Specification | ACK versus completion, durability and retry | Investigating |
| [GAP-022](#gap-022) | P0 | Unanswered | Authentication and settings | Native nonempty-password encoding | Resolved |
| [GAP-023](#gap-023) | P0 | Ambiguous | Authentication and settings | Login-name lookup and guest fallback | Resolved |
| [GAP-024](#gap-024) | P0 | Ambiguous | Authentication and settings | Client-version and optional login inputs | Resolved |
| [GAP-025](#gap-025) | P0 | Unanswered | Authentication and settings | Complete login/agreement state machine | Resolved |
| [GAP-026](#gap-026) | P1 | Missing | Authentication and settings | Meaning and lifetime of login extras | Investigating |
| [GAP-027](#gap-027) | P1 | Unanswered | Authentication and settings | Agreement absence, bypass and text rules | Resolved |
| [GAP-028](#gap-028) | P1 | Ambiguous | Authentication and settings | Banner metadata variants and lifecycle | Resolved |
| [GAP-029](#gap-029) | P1 | Unanswered | Authentication and settings | Settings update defaults and persistence | Resolved |
| [GAP-030](#gap-030) | P1 | Unanswered | Authentication and settings | Settings option edge cases and automatic-response defaults | Resolved |
| [GAP-031](#gap-031) | P1 | Unanswered | Presence and permissions | Complete privilege bitmap registry | Investigating |
| [GAP-032](#gap-032) | P1 | Unanswered | Presence and permissions | Privilege composition and inheritance | Resolved |
| [GAP-033](#gap-033) | P1 | Missing | Presence and permissions | User, room, article and reference identifier lifetimes | Investigating |
| [GAP-034](#gap-034) | P1 | Unanswered | Presence and permissions | Colour/status bitmap semantics | Resolved |
| [GAP-035](#gap-035) | P1 | Unanswered | Presence and permissions | Roster and update ordering | Resolved |
| [GAP-036](#gap-036) | P1 | Unanswered | Presence and permissions | Disconnect notification and cleanup | Investigating |
| [GAP-037](#gap-037) | P2 | Ambiguous | Presence and permissions | Diagnostic-text output contract | Resolved |
| [GAP-038](#gap-038) | P1 | Unanswered | Chat and messaging | Room access and main-chat membership | Resolved |
| [GAP-039](#gap-039) | P1 | Unanswered | Chat and messaging | Invitation lifecycle and partial failures | Resolved |
| [GAP-040](#gap-040) | P1 | Ambiguous | Chat and messaging | Room snapshot and notification ordering | Resolved |
| [GAP-041](#gap-041) | P1 | Unanswered | Chat and messaging | Subject update validation | Resolved |
| [GAP-042](#gap-042) | P1 | Unanswered | Chat and messaging | Chat formatting and option 109 | Resolved |
| [GAP-043](#gap-043) | P1 | Unanswered | Chat and messaging | Private-message routing truth table | Resolved |
| [GAP-044](#gap-044) | P1 | Missing | Chat and messaging | Type-104 variant schemas | Resolved |
| [GAP-045](#gap-045) | P1 | Unanswered | Chat and messaging | Flood, spam and throttling outcomes | Investigating |
| [GAP-046](#gap-046) | P1 | Unanswered | Chat and messaging | Legacy-board data and update contract | Investigating |
| [GAP-047](#gap-047) | P1 | Unanswered | Files and paths | Structured path format | Investigating |
| [GAP-048](#gap-048) | P1 | Unanswered | Files and paths | File-list record layout | Resolved |
| [GAP-049](#gap-049) | P1 | Ambiguous | Files and paths | File-info variant matrix | Resolved |
| [GAP-050](#gap-050) | P1 | Unanswered | Files and paths | Delete semantics and failures | Investigating |
| [GAP-051](#gap-051) | P1 | Unanswered | Files and paths | Folder creation semantics | Resolved |
| [GAP-052](#gap-052) | P1 | Unanswered | Files and paths | Rename/comment partial updates | Resolved |
| [GAP-053](#gap-053) | P1 | Unanswered | Files and paths | Move collision and metadata behaviour | Investigating |
| [GAP-054](#gap-054) | P1 | Unanswered | Files and paths | Alias creation and resolution | Investigating |
| [GAP-055](#gap-055) | P1 | Unanswered | Transfer protocol | Sixteen-byte HTXF header and reference matching | Resolved |
| [GAP-056](#gap-056) | P1 | Unanswered | Transfer protocol | Flattened file and fork stream | Resolved |
| [GAP-057](#gap-057) | P1 | Ambiguous | Transfer protocol | Download and preview response conditions | Resolved |
| [GAP-058](#gap-058) | P1 | Unanswered | Transfer protocol | Resume-data format and offset negotiation | Resolved |
| [GAP-059](#gap-059) | P1 | Unanswered | Transfer protocol | Folder-download stream state machine | Resolved |
| [GAP-060](#gap-060) | P1 | Unanswered | Transfer protocol | Folder-upload stream state machine | Resolved |
| [GAP-061](#gap-061) | P1 | Unanswered | Transfer protocol | Queue notification 211 and scheduling | Resolved |
| [GAP-062](#gap-062) | P1 | Unanswered | Transfer protocol | Reference cleanup 214 semantics | Resolved |
| [GAP-063](#gap-063) | P1 | Unanswered | Transfer protocol | Banner data stream and absence | Resolved |
| [GAP-064](#gap-064) | P1 | Missing | Transfer protocol | Transfer completion, failure and persistence | Investigating |
| [GAP-065](#gap-065) | P1 | Unanswered | News | Category records and version threshold | Resolved |
| [GAP-066](#gap-066) | P1 | Unanswered | News | Serialized article-list format | Resolved |
| [GAP-067](#gap-067) | P1 | Unanswered | News | Article navigation, flavour and date semantics | Investigating |
| [GAP-068](#gap-068) | P1 | Unanswered | News | Posting and new-article discovery | Investigating |
| [GAP-069](#gap-069) | P1 | Unanswered | News | Recursive article deletion | Resolved |
| [GAP-070](#gap-070) | P1 | Unanswered | News | News hierarchy and structure mutations | Investigating |
| [GAP-071](#gap-071) | P1 | Unanswered | Administration | Account field 111 | Investigating |
| [GAP-072](#gap-072) | P1 | Unanswered | Administration | Account update, placeholder and identity rules | Investigating |
| [GAP-073](#gap-073) | P1 | Unanswered | Administration | Account changes and active sessions | Resolved |
| [GAP-074](#gap-074) | P1 | Unanswered | Administration | Kick/ban option branches | Resolved |
| [GAP-075](#gap-075) | P2 | Unanswered | Administration | Standalone transaction 111 | Resolved |
| [GAP-076](#gap-076) | P2 | Unanswered | Administration | Server-originated broadcast and eligibility | Resolved |
| [GAP-077](#gap-077) | P2 | Unanswered | Administration | Request 348 schema and purpose | Resolved |
| [GAP-078](#gap-078) | P2 | Unanswered | Administration | Request 349 schema and batch outcomes | Resolved |
| [GAP-079](#gap-079) | P2 | Unanswered | Session and transport | Request 500 purpose and scheduling | Resolved |
| [GAP-080](#gap-080) | P1 | Evidence | Compatibility and evidence | Identified peer corpus and fallback classifier | Resolved |
| [GAP-081](#gap-081) | P2 | Evidence | Compatibility and evidence | Client tolerance of extra fields | Resolved |
| [GAP-082](#gap-082) | P1 | Decision | Compatibility and evidence | Heuristic text-decoding policy | Investigating |
| [GAP-083](#gap-083) | P2 | Evidence | Compatibility and evidence | Historical SynHX source identity and applicability | Resolved |
| [GAP-084](#gap-084) | P0 | Evidence | Compatibility and evidence | Native conformance fixtures beyond one illustrative frame | Resolved |
| [GAP-085](#gap-085) | P2 | Evidence | Compatibility and evidence | mxd implementation and test evidence | Investigating |
| [GAP-086](#gap-086) | P2 | Decision | Compatibility and evidence | Release/proof acceptance criteria | Investigating |
| [GAP-087](#gap-087) | P2 | Missing | Documentation provenance | Portable, versioned evidence and document references | Resolved |

## Specification

### GAP-001

#### Define the supported 1.9 subset

- **Tracking:** P1; Decision; Open; owner: Unassigned.
- **Sources:** [protocol.md — Hotline Server Protocol 1.9: Transactions and
  Functionality
  Guide](protocol.md#hotline-server-protocol-19-transactions-and-functionality-guide)
  (snapshot lines 1–34); [internal-compatibility-matrix.md — Open
  compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 324–360)
- **Question:** Which of the 45 requests and server notifications must mxd
  implement now, defer explicitly, or reject, and which peer profiles are
  acceptance targets?
- **Implementation impact:** An open-ended baseline cannot define feature
  completion or compatible rejection behaviour.
- **Close when:** Publish an operation-by-profile scope matrix with required,
  deferred and excluded states, including replies to unsupported operations.
- **Prior ledger entries:** V001, V074, M008, M009
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:**  A delegated review maps current mxd scope/assertions to
  native evidence but does not select required/deferred/excluded
  operation/profile states or unsupported replies. The original scope decision
  remains open. User instruction13November2026: further mxd validation/fixes
  are on hold; consolidate completed evidence in mxd-validation.md. Canonical
  sourcecb907 has accepted framing/directACK/loginextras corrections. Actual
  Classic authenticates with fully transmitted24-byte fixture secret but waits
  for missing agreement handoff; no121/300/212 follows. This is partial
  startup, not release or complete compatibility evidence.
- **Evidence:** [Pinned mxd reconciliation](mxd-reconciliation.md); [Frozen
  mxd source and test
  evidence](../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json);
  [mxd validation findings and hold](mxd-validation.md)
- **Closure:** Not closed: the original scope/policy criterion remains unmet.

### GAP-002

#### Canonical transaction and field schemas

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 88–114);
  [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** For every in-scope request, reply and notification, which
  fields are required, optional, conditional or repeatable, with what widths
  and value domains?
- **Implementation impact:** Lists of fields that a handler reads are not
  sufficient to build a compatible encoder or validator.
- **Close when:** Provide a schema registry for the core operations, marking
  each remaining unknown with a gap ID; include direction, cardinality, width,
  conditions and defaults.
- **Prior ledger entries:** V013, V015, V023, V069
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [10056b90](../mothra/evidence/hotline-server-1.9/queries/D-10056b90.c)
- **Depends on:** No prerequisite recorded.
- **Evidence:** [Core schema registry](core-field-schemas.md); [Complete
  handler inventory](operation-contracts.md#request-catalogue); [Preserved
  native baseline](../mothra/evidence/hotline-server-1.9/manifest.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published a core operation registry with direction, logical
  scalar/repeated occurrence, widths/byte caps, default/absence behaviour and
  conditions. Remaining type, boundary, routing and fixture unknowns retain
  their separate gap IDs as required by this criterion. This closes the
  registry deliverable, not all codec/runtime acceptance questions.

### GAP-003

#### Error-code and failure-outcome registry

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 215–239);
  [protocol.md — Disconnecting a User (Transaction 110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 1154–1199)
- **Question:** Which statuses, field-100 forms and connection outcomes apply
  to each failure, including errors in operations without a normal ACK?
- **Implementation impact:** Implementations cannot distinguish recoverable
  failure, success, silent rejection and impending disconnect consistently.
- **Close when:** Document a failure table and representative bytes for
  authentication, permission, missing-object, malformed-request and
  unsupported-operation cases.
- **Prior ledger entries:** V012, V044, V053, V065, V067, V071
- **Investigation leads:**
  [10058a10](../mothra/evidence/hotline-server-1.9/queries/D-10058a10.c),
  [1000ef30](../mothra/evidence/hotline-server-1.9/queries/D-1000ef30.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Captured the108-entry native-result table, verified sorted
  keys and documented representative internal domain/code mappings with
  resource meanings. These are not wire statuses; enclosing catch translation
  and native error packets remain required. Retained native status1
  authentication, permission, missing room/file and unknown/replayed-operation
  replies, plus invalid zero-size closure. Internal exception translation and
  remaining failure/drain boundaries remain unresolved. Added missing-buffer
  null-size and zero-byte transfer-allocation internal SError1/2 traces, plus
  native RSTs on data/owner/observer for the present-empty fixture and a
  successful fresh post-reset session. No numbered wire mapping or general
  reset threshold is inferred. Added native online unknown types0/FFFF with
  incomingflagsFF/errorFFFFFFFF, yielding type0/reply1/status1 plus
  exactfield100 text; zero-size replymarker1/255 closes without numbered
  response. Full operation-error taxonomy remains required. Added
  Incorrectlogin versus nativebadfilename account failures: bothwirestatus1,
  but32-byte path diagnostics include internal4/119[-37] infield100 text.
  Premature121 returns account-read error; online107/121 replay yields
  Unknowntransactiontype. Fullerror taxonomy remains required. Agreement65536
  non-TEXT value loads but fails field101 serialization after successful107
  ACK. Early readiness survives with354/roster/500, delayed staysunlisted
  andcloses afternext500; no errorreply explains109failure. InternalSError1/10
  isnotwirestatus10. Fullerrorregistry remains required. Native-mkdir-01 adds
  exact status1/text100 permission, existing-file/directory/case-conflict and
  parent-resolution families, with before/after effects and liveness. Root
  absence/empty combinations fail as conflicts; malformed path prefixes can
  succeed. Other operation failure/partial-effect registries remain required.
  Native209sixcreationerrorcasesretainexactstatus1/text100,unchangedlistingandliveness.
  Same-location209successcanmakeunattachedalias;202missingfilemessagecanrefer
  tophysicallyexistingunattachedalias. Broaderregistryremainsrequired.
  Native-metadata01adds207permissionandcollisionfailureswithactualpartialcommentmutations;errorACKdoesnotimplyrollback.
  Broaderregistryremainsactive.
  Native-move01adds26moveand9deletecaseswithexactstatus1/text100permission,missingendpoint,collisionandhierarchyerrors,plusbefore/afterunchangedviewsandliveness.
  Sameparent208succeeds;missing204fails.
  Broaderfailure/partial-effectregistryremainsactive.
  Native-news01adds14structureerrorsandfour400article/flavourfailureswithcoarseinvalid-categorytextdespiteexistingcategory.
  Missing-body410returnsstatus1butleavesmetadata/indexrecord.
  Exactfamilies,livenessandbefore/afterviewsarecaptured;broaderregistryremainsactive.
  Article deletion adds exact missing-ID/category, omitted-ID, repeated-delete
  and permission errors, with unchanged lists and liveness. Broader failure
  registry remains active. Account deletion sends data-only 104/101 notice and
  native first FIN, not a numbered error or politequit111. A stopped
  application yields a guest RST diagnostic No listener, not a protocol error
  frame. Broader failure taxonomy remains active. Request 349 distinguishes
  collision notice 104/101/109 followed by success, saving-list errors with
  later effects, and permission errors that stop later items. General
  exception translation remains active. Native duplicate 350 and bit-23 kick
  denial have distinct exact status-1/100 families; 351 and self-delete
  instead ACK before deletion notice/FIN. These do not settle all
  filesystem/exception errors. Room create/join errors, no-ACK operations and
  denied-chat 104 families now have native contrasts. Two wrong recorder
  expectations remain failed, not server-crash/error outcomes. A clause-level
  review distinguishes the original representative-byte requirement from
  unresolved exception/no-ACK outcomes. Five retained native examples now
  publish exact request bytes and captured status1/text100 replies for
  authentication, permission, missing object and unsupported operation;
  malformed zero-size input records no numbered response and host EOF with
  explicit proxy limits. The broader exception-to-wire question remains open.
  Root acceptance revision56: The failure table and five retained
  request/result examples cover authentication, permission, missing-object,
  malformed-request and unsupported-operation cases. Parent replay matched the
  pinned reports, exact events/frames, error ID/status/text and host EOF. This
  meets the original representative criterion without claiming exhaustive
  SError catch translation or guest FIN/RST proof.
- **Evidence:** [Native format/recovery/reset
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json);
  [Banner type/recovery
  contract](transfer-contracts.md#captured-banner-formats-and-recovery);
  [Repeatable format/recovery
  workflow](native-capture-workflow.md#reproducing-banner-format-and-recovery-fixtures);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Native alias and metadata
  matrix](filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix);
  [Alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Native rename/comment
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Second delegated investigation](failure-representatives.md); [Captured
  failure representatives](failure-representatives.md)
- **Closure:** The failure table and five retained request/result examples
  cover authentication, permission, missing-object, malformed-request and
  unsupported-operation cases. Parent replay matched the pinned reports, exact
  events/frames, error ID/status/text and host EOF. This meets the original
  representative criterion without claiming exhaustive SError catch
  translation or guest FIN/RST proof.

### GAP-006

#### Complete direction and reply-contract catalogue

- **Tracking:** P1; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 215–239);
  [protocol.md — Sending a Chat Message (Transaction 105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 612–621); [protocol.md — Changing User Settings (Transaction
  304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575)
- **Question:** Which operation/direction/session-state combinations are
  accepted, and what direct success/error replies or subsequent notifications
  belong to each? The current ACK/Push prose is not a complete catalogue.
- **Implementation impact:** Implementers must infer dispatch direction and
  negative-outcome rules from scattered handler descriptions rather than one
  complete contract.
- **Close when:** Publish an operation-by-direction/state table distinguishing
  direct success replies, error replies, emitted notifications and
  acceptance/completion semantics.
- **Prior ledger entries:** V039, V038, V041, V044
- **Investigation leads:**
  [10058a70](../mothra/evidence/hotline-server-1.9/queries/D-10058a70.c),
  [10058ca0](../mothra/evidence/hotline-server-1.9/queries/D-10058ca0.c)
- **Depends on:** [GAP-002](#gap-002)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Reply and fan-out
  map](operation-contracts.md#per-operation-reply-and-fan-out-map);
  [Direction/state
  eligibility](operation-contracts.md#session-eligibility-and-invalid-transitions);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-02/review.json)
- **Closure:** Published all45 explicit request paths with direction/state
  eligibility, direct success and explicit-error outcomes, fan-out ordering
  and acceptance/completion semantics. This satisfies the unchanged table
  criterion. Exhaustive exception translation and runtime capture requirements
  remain GAP-003/084; the former is not a prerequisite of this static
  catalogue.

### GAP-021

#### ACK versus completion, durability and retry

- **Tracking:** P1; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 4 Reply
  semantics](protocol.md#4-reply-semantics) (snapshot lines 215–239);
  [protocol.md — Sending an Instant Message (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 667–699); [protocol.md — Posting a News Article (Transaction
  410) – Client
  Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates)
  (snapshot lines 1048–1069); [protocol.md — User Account Management – Client
  Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** When an ACK precedes routing or mutation side effects, what
  has it committed to, and what can fail or be retried afterwards?
- **Implementation impact:** A client may treat acceptance as
  delivered/durable success and duplicate non-idempotent operations on
  reconnect.
- **Close when:** Specify completion points, post-ACK failure signalling,
  persistence and retry/idempotency rules per operation with
  disconnect-boundary fixtures.
- **Prior ledger entries:** V044, V045, V065, V067
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** [GAP-003](#gap-003), [GAP-007](#gap-007)
- **Progress:** Added news structure order: Trash move or directory/category
  creation precedes ACK; creation activity logging follows ACK. INFO FlushVol
  return is unchecked. Disconnect-boundary, persistence, retry/idempotency and
  postACK failure fixtures remain required. Agreementfieldoverflow
  proves107successACK canprecede failed109construction withoutrollingback
  earlyreadiness. Noerrorreply oratomicrollback guarantee;
  broaderdurability/retry remains required. ImmediateURLPrefs snapshot
  retained stale188-byte forkextent despite liveURLwireconfiguration;
  independent203finalization invokes knownFlushVolpath and
  thenpositive222-byte fork iscomplete. Failedsnapshot/oldcontrols
  areseparate; final175-byte recordedbaseline isrestored exactly.
  NoACK/restartdurability rule inferred.
  Native208sameparentfile/foldermovesreturnemptysuccesswithoutvisiblechange.
  Native204missingtargetreturnsstatus1.
  Helpers/positivecataloguesseparateactualeffectsfromreplytext;lostACKretry,restartdurabilityandotheroperationcriteriaremainunproven.
  Missing-body410errorfollowsvisible/storedarticlecreationandcountincrement;rawHLNZcachepreservesthezero-flavourrecord.
  ErrorACKdoesnotimplyrollback.
  Ownedflushpublicationdemonstrateswhyaninitialzero-positiveprobeisnotabsence;restart/lostACKacceptanceremainsactive.
  Article deletion ACKs correspond to observed tree/index/cache changes;
  storage writes are staged without demonstrated rollback. Independent
  positive upload publication preserves 27 original objects in Trash; forced
  I/O interruption, lost ACK and restart durability remain unproved. Success
  ACK does not guarantee full list discovery: append 102 retains all 103
  indexed records but only 102 list entries. Direct orphan lookup still
  succeeds. Native cache/index mismatch is positively retained; interruption
  and restart outcomes remain required. Complete before/after 734-byte account
  files match replacement semantics, including cleared unused bytes;
  independent positive Trash observations preserve all 18 original
  objects/forks. No interrupted-write, lostACK or restart guarantee is
  established. Normal server application restart preserves account replacement
  and deletion, exact stored records and original catalogue objects.
  Application forks and complete Prefs bytes are unchanged. This does not
  establish OS/power-loss or interrupted-write durability. Native rename
  collision returns error after overwriting destination credentials and
  continues later creation; earlier effects remain. Error does not imply
  rollback or atomicity. Wider durability/retry rules remain active.
  Self-delete ACK precedes its notice on the same subject stream. Both
  deletions retain a stale administrator snapshot and a later unread
  target-specific 302. No new storage/restart durability claim. A 203
  status-zero reservation preceded an upload abort and an observed Incomplete
  File artifact. Recorder send completion exceeded bytes observed at host and
  guest, so it is not transfer completion. Guarded204 removed only the owned
  path and restored baseline views. No universal post-ACK error or retry
  guarantee follows. Latest A8 phase 1: A new live 202/HTXF example
  distinguishes a status-zero reservation from an active flattened transfer:
  the saved 303 had one active and one waiting row before cancellation. Its
  65,536-byte received prefix includes FILP/INFO framing, not that many
  DATA-fork bytes. Cancellation and restored idle state were verified; no
  universal durability or completion guarantee follows. Revision61: The static
  ordinary-download trace separates advertised, requested/enqueued and
  OpenTransport pending bytes from TCP ACKs. Reaching the producer count
  closes its file but does not prove client receipt or durability. Revision71
  stoppedHFS evidence corroborates351 movingownedfolders/UserData
  intoallocatedTrash; native352missingand348originaltwo
  proveactiveaccountremoval, notphysicalerasure. Originalnamedforks unchanged
  afterappQuit/forcedemulatorretirement. This isnot a353failed-writeratomicity
  fixture or allstorage guarantee. Revision72 independent Ghidra writer trace
  confirms353opensUserData, separatelySetEOF734, onePBWriteSync734 andclose
  beforeACK/liveupdate. OSerror invokesSError; actualwritecount
  returnedbylowlevelhelper isignoredbywriter. No localrollback/temp/swap
  appearsindirectchain, butouterrecovery/failed-writebytes/OScrashatomicity
  remainunmeasured. FinderLockedmayrejectbeforewrite,
  whichwouldnotprovewrite-phaseatomicity.
- **Evidence:** [Structure
  effects](news-contracts.md#structure-operation-effects-and-conflicts);
  [Internal errors](error-outcomes.md#internal-exceptions-and-text-resources);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Second delegated investigation](diagnostic-transfer-boundaries.md); [Active
  and queued native diagnostic](native-diagnostic-existing-witness.md);
  [Native documentation evidence](native-download-send-path.md); [Allocated
  Trash records after account
  deletion](operation-contracts.md#account-deletion-and-allocated-trash-records);
  [Direct account write ordering and limits](account-write-ordering.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Session and transport

### GAP-004

#### Transaction ID lifecycle and correlation

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 88–114);
  [protocol.md — 3 Fragmentation rules](protocol.md#3-fragmentation-rules)
  (snapshot lines 185–214)
- **Question:** Are zero, duplicate, wrapped or reused IDs accepted, how are
  client and server ID spaces separated, and how are unsolicited replies
  treated?
- **Implementation impact:** Correlation and reassembly can attach a reply or
  payload to the wrong outstanding operation.
- **Close when:** Specify ID allocation, lifetime, wrap/reuse and notification
  correlation rules; exercise zero, collision and late-reply cases.
- **Prior ledger entries:** V007, V008, V010, V022
- **Investigation leads:**
  [10058d70](../mothra/evidence/hotline-server-1.9/queries/D-10058d70.c),
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published allocation, 32-bit wrap/zero-skip,
  dispatch/connection lifetime and notification correlation rules with25
  identified oracle queries and24 native sessions. Native zero/high-bit IDs,
  completed reuse, same-ID queued collision, mixed-type collision, late
  replies and independent notification counters are verified. Server counter
  wrap is proven from PowerPC instructions rather than a live2^32-message
  trial.
- **Evidence:** [Native ID/reassembly
  contract](session-transport-contracts.md#transaction-ids-reassembly-and-correlation);
  [Native envelope
  acceptance/emission](session-transport-contracts.md#native-envelope-acceptance-and-emission);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Prior framing
  matrix](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-13/review.json)
- **Closure:** Resolved against the unchanged criterion:
  allocation/lifetime/wrap/reuse and notification rules are published and
  zero/collision/late-reply fixtures retained. Other identifier domains,
  universal timers, retry/durability and peer compatibility remain separate
  requirements.

### GAP-005

#### Connection timers and liveness

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  43–87); [protocol.md — 4 Reply semantics](protocol.md#4-reply-semantics)
  (snapshot lines 215–239); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 1224–1271)
- **Question:** What are the handshake, login, agreement, idle and
  partial-frame deadlines, and what traffic resets them?
- **Implementation impact:** A client can wait forever or disconnect a
  compatible session prematurely without a liveness contract.
- **Close when:** Provide a timer/state table with units, reset conditions,
  configurable values and close outcomes, distinguishing native observations
  from mxd limits.
- **Prior ledger entries:** V012, V020, V074
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published timer origins/reset conditions: only selected
  logical requests refresh session activity; upload entry clocks begin at
  request creation and attachment does not reset them; consumed file chunks
  refresh them. Added bounded pending/partial-input negatives and
  late-attachment derived case. Lower-layer/configured timing and native
  boundary fixtures remain required. Guest trace establishes no FIN/RST
  during65.060281 host seconds after a failed-login reply before client
  cleanup. A separate isolated35-second quiet case resets the failed
  session92.254ms after a new control SYN. Added primary OT predicate/close
  helper captures. Dispatcher scheduling, guard semantics across profiles and
  clock/configuration boundaries remain open; no hard30-second deadline is
  claimed. Added partial header/body/transaction silence then nativeFIN
  responses to client write-half-close. These are not timeout observations or
  mandatory deadlines; platform/scheduling/liveness requirements remain open.
  Native-login-extras-01 retains a90second waiting hypothesis: guest close
  at90.851866 reportseconds precedes host121send92.727286;121never
  reachesguest.20second configured-name change permits waiting121completion.
  This isnot a universal deadline orisolated options-save/timercause;
  scheduling/guard boundaries remain required. Deleted-account subjects show
  native first FIN but remain in two bounded observer snapshots; late 302
  messages follow the recorded receive prefix. No universal teardown deadline
  is inferred. Revision73 prepares a finite135second A/B/F/O liveness timeline
  with source-gated delayed107 and partial121. Fourteen offline controls
  validate generatedbytes, semanticnegativecases and reporttiming/terminal
  reconstruction. This is preparation only; a native case and pairedpacket
  publication remain required. Onlineidle>600 and broaderroom/transfercleanup
  are not covered. Revision74 accepts finite C93 liveness capture and C94
  portable replay: pre/post18 controls, seven coordinator flows, nine total
  lifetimes with exact paired applicationbytes/tails. A never-complete107
  locallyEOF65.116360; B selected107at45/partial121at50 locallyEOF110.017097;
  F failed107 locallyEOF35.138506. GuestRST becomesrelayEOF forA/B/F. OnlineO
  remainsopen through135secondwindow thenclientfirstFIN. SixO302 carryonly103,
  no301, T46rosteronlyO; UID-to-socket labels remainunproved.
  Nativeclock/uniquewakecause/configuration/onlineidle>600 and
  broaderroom/transfercleanup remainopen.
- **Evidence:** [Native transport
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json);
  [Captured boundaries and timers](session-transport-contracts.md);
  [Repeatable transport
  fixtures](native-capture-workflow.md#recorded-native-transport-fixtures);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Finite native liveness fixture
  preparation](native-liveness-preparation.md); [Finite native liveness
  witness](native-liveness-witness.md); [Paired liveness packet
  corpus](../mothra/evidence/gap-remediation/2026-11-14/native-liveness-01/manifest.json);
  [Selected-request and partial-input
  timing](session-transport-contracts.md#captured-selected-request-and-partial-input-timing)
- **Closure:** Not closed: the remaining unchanged acceptance requirements are
  explicitly retained above.

### GAP-007

#### Allowed operations by session state

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  43–87); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — Agreement Acceptance (Transaction 121) –
  Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 387–415); [protocol.md — Additional Observed Requests and
  Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps)
  (snapshot lines 1224–1271)
- **Question:** What can be sent before authentication, after login ACK, while
  agreement is pending, after early completion and during shutdown?
- **Implementation impact:** The guide has transaction descriptions but no
  complete dispatch/state contract for a server implementation.
- **Close when:** Publish a state/operation table including invalid
  transitions, replayed login/agreement requests and state-specific failures,
  backed by traces or dispatcher analysis.
- **Prior ledger entries:** V023, V026, V027
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Evidence:** [Native
  dispatcher](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c);
  [Unknown-operation
  error](../mothra/evidence/gap-remediation/2026-11-12/batch-03/queries/B03-D-10014640.c);
  [State/operation
  table](operation-contracts.md#session-eligibility-and-invalid-transitions);
  [Login visibility
  sequence](presence-messaging-contracts.md#settings-and-login-visibility)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published allowed operations, invalid pre-online closes,
  replayed online login/agreement errors, failure waiting and disconnected
  teardown states, backed by dispatcher analysis as allowed by the closure
  criterion. Removed the planned GAP-025 prerequisite because dispatch was
  established directly; full configured sequence captures remain GAP-025/084.

### GAP-008

#### Handshake failures and stream boundaries

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  43–87)
- **Question:** How are short, long, pipelined, wrong-magic, wrong-version or
  unsupported-sub-version handshakes consumed, replied to and closed?
- **Implementation impact:** The happy-path twelve/eight-byte layouts do not
  specify initial stream recovery or rejection.
- **Close when:** Record positive and negative handshake exchanges with exact
  byte consumption, response status, pipelining behaviour and closure order.
- **Prior ledger entries:** V003, V004, V005, V006
- **Investigation leads:**
  [10058650](../mothra/evidence/hotline-server-1.9/queries/D-10058650.c),
  [10058770](../mothra/evidence/hotline-server-1.9/queries/D-10058770.c),
  [100587f0](../mothra/evidence/hotline-server-1.9/queries/D-100587f0.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Boundary
  table](session-transport-contracts.md#captured-handshake-boundaries);
  [Native transport
  manifest](../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json);
  [Packet/stream semantic
  checks](../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-04/review.json)
- **Closure:** Recorded positive and negative primary handshake exchanges,
  exact12-byte/prefix preservation, five3-second split observations,
  short-input half-close, pipelined login and failure response/guest
  RST-versus-FIN order. Fourteen addressed final cases include13 completed
  plans and an explicitly failed alternate-control probe. The unchanged
  ordinary handshake criterion is met; alternate wrapping, matched HTXF
  streams, scheduling and identified peers remain GAP-009/010/005/055/080/084.

### GAP-009

#### Sub-version 3 and direct HTXF relationship

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 1 Session-initialization
  handshake](protocol.md#1-session-initialization-handshake) (snapshot lines
  43–87); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974)
- **Question:** When does the TRTP sub-version-3 path apply, on which
  endpoint, and how does it relate to a direct sixteen-byte HTXF header?
- **Implementation impact:** An implementer could perform the wrong handshake
  on a transfer socket despite knowing each observed magic.
- **Close when:** Trace the two entry paths and document complete
  endpoint-specific sequences, transitions and fixture bytes.
- **Prior ledger entries:** V004, V059, V060
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** No prerequisite recorded.
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured ordinary-file
  sequences](transfer-contracts.md#captured-ordinary-file-round-trips);
  [Completion and
  EOF](transfer-contracts.md#captured-completion-and-eof-behaviour); [Native
  fork
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/manifest.json);
  [Packet/fork/metadata
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-06/review.json)
- **Closure:** Both raw5501 and primarycontrol5500 TRTPv1sub3 entry paths have
  positive matched-reference upload/download sequences with exact host/guest
  packet reconciliation. The handover success is read before
  same-connectionHTXF. Earlier native-transport-01 retains unmatched ref0
  negatives through both entry paths. Completion boundaries are
  direction-specific: uploadEOF versus downloadadvertisedcount with open
  transport and explicit214 cleanup. Alternate5502/5503 wrapping
  remainsGAP-010, banner matching is covered by resolvedGAP-055 and full
  peersGAP-084.

### GAP-010

#### Listening endpoints and data-port arithmetic

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  733–747); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974)
- **Question:** How are control/data listeners selected and configured, and is
  the data port always the base port plus one in this build?
- **Implementation impact:** File-transfer connection setup cannot be derived
  from a tentative port convention.
- **Close when:** Trace listener creation and configuration; document endpoint
  mapping, exceptions and verified client connection examples.
- **Prior ledger entries:** V060
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Traced configured base port (default 5500), ordinary
  base/base+1 and alternative-wrapper base+2/base+3 binds. Constructor modes
  are kept separate from unproven TLS/HTTP labels. Runtime/overflow/client
  connection fixtures remain required. Native primary control5500 and data5501
  examples retained. Alternate5502/5503 accept TCP and acknowledge unwrapped
  input but return no application response within10 seconds; full wrapping and
  port-boundary/overflow configuration remain unverified. Revision68:
  reconcile the baseline with the traced default/configured four-listener map
  and complete ordinary control/data examples. Both alternate ports have
  bounded TCP/no-ordinary-response observations. Halfword narrowing and
  sub-version3 control-to-HTXF handover are explicit exceptions to a universal
  usable-base-plus-one rule. Independent headless callback descriptor reads
  are retained, including FUNCTION_NOT_FOUND for their unanalysed entries; no
  alternate-wrapper protocol is invented.
- **Evidence:** [Native transport
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-transport-01/manifest.json);
  [Captured boundaries and timers](session-transport-contracts.md);
  [Repeatable transport
  fixtures](native-capture-workflow.md#recorded-native-transport-fixtures);
  [Configured endpoints and
  exceptions](session-transport-contracts.md#configured-endpoints);
  [Independent criterion and formatter
  audits](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-04/decisions.json)
- **Closure:** Met for listener creation/configuration, endpoint mapping,
  documented exceptions and verified connection examples. Ordinary base/base+1
  and alternate-wrapper base+2/base+3 are traced; arbitrary high-base bind
  success and complete mode0 wire negotiation remain unverified. Do not infer
  TLS/HTTP or guarantee four usable adjacent ports.

### GAP-079

#### Request 500 purpose and scheduling

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 1224–1271)
- **Question:** Is 500 a liveness operation or something else, who sends it
  and when, and does its ACK affect idle deadlines?
- **Implementation impact:** Naming it a keepalive or scheduling it
  periodically would invent a contract from an empty-ACK handler.
- **Close when:** Identify client/server call sites or captures, document its
  purpose/timing/state eligibility, and explicitly scope support.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10018c00](../mothra/evidence/hotline-server-1.9/queries/D-10018c00.c)
- **Depends on:** [GAP-005](#gap-005)
- **Progress:** No500 definition/send site located in the inspected shx0.1.48
  source snapshot. This bounded negative does not identify its native purpose
  or later-client scheduling; peer-side evidence remains required. Latest
  captured session: The first Classic peer capture has four numbered client
  requests 107/121/300/212 and no 500. Its last numbered request to FIN
  interval is 144.395409 seconds (SYN to FIN 248.777271 seconds). The planned
  130-second local-only observation was stopped for automatic external HTTP
  traffic; finite measured absence does not establish purpose or universal
  scheduling. Root acceptance revision54: Identified native dispatcher/handler
  and matched empty ACK captures establish online eligibility and common
  activity refresh. Pinned modern client source names connectionKeepAlive,
  starts after login, checks every 15 seconds and sends after at least 180
  seconds traffic silence for reported server version >=185, otherwise 300; it
  cancels on disconnect and does not await the ACK. This is explicitly
  source-only and client-specific, with hashes, URLs, anchors and a
  reproducible source guard; no mandatory universal schedule is inferred.
- **Evidence:** [Error outcomes](error-outcomes.md); [Folder
  descriptor](transfer-contracts.md#folder-item-descriptor-bytes); [Identified
  client source](identified-client-source.md); [First Classic peer
  session](mac-peer-first-session.md); [Request 500 scoped
  contract](request-500-contract.md)
- **Closure:** Identified native dispatcher/handler and matched empty ACK
  captures establish online eligibility and common activity refresh. Pinned
  modern client source names connectionKeepAlive, starts after login, checks
  every 15 seconds and sends after at least 180 seconds traffic silence for
  reported server version >=185, otherwise 300; it cancels on disconnect and
  does not await the ACK. This is explicitly source-only and client-specific,
  with hashes, URLs, anchors and a reproducible source guard; no mandatory
  universal schedule is inferred.

## Framing and parsing

### GAP-011

#### Frame, transaction and buffering limits

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 185–214)
- **Question:** Is the image's 2 MiB value changed at runtime, does it bound a
  frame or aggregate transaction, and how are totals, fragments and concurrent
  buffers limited?
- **Implementation impact:** The existing image constant does not define safe
  or interoperable allocation and framing boundaries.
- **Close when:** Document native comparisons/configuration and explicit mxd
  limits with inclusive boundaries, overflow checks and boundary fixtures.
- **Prior ledger entries:** V009, V010, V021
- **Investigation leads:**
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c),
  [10058e80](../mothra/evidence/hotline-server-1.9/queries/D-10058e80.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Captured explicit startup assignment of 512 KiB to
  receive-limit global, superseding the image-only 2 MiB assumption for that
  path. Indirect future writes, configurability, aggregate bounds and boundary
  fixtures remain required. Native boundary cases confirm zero/above512KiB
  size words close, equality524288 passes and aggregate524290 can dispatch.
  mxd limits, configuration/write paths and global buffering bounds remain
  required. Frozen mxd base2e4c9c1 incorrectly reapplies its32KiB physical
  limit to normalized logical transactions. A private uncommitted correction
  passes44 focused production tests while retaining1MiB logical and32KiB
  physical limits. Two full test attempts failed while linking; the earlier
  interrupted run has no exit. Aggregate buffering/native later-write trace
  and release policy remain open. A twelve-call parity-gated trace pins the
  startup store at 10000b84-b8c of 0x80000 before config loading, alongside
  the 2 MiB image initializer and bounded data-reference results. No negative
  xref proves absence of later writes. Canonical mxd 48129491 now accepts
  logical reassembly above 32 KiB through configured 1 MiB while preserving 32
  KiB physical validation; focused/format/lint/full gates passed with explicit
  skips. Native later-write/configuration and aggregate buffering questions
  remain.
- **Evidence:** [Framing
  evidence](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Native framing
  contracts](session-transport-contracts.md#captured-framing-and-reassembly-boundaries);
  [TLV and scalar
  outcomes](native-wire-details.md#captured-tlv-and-scalar-boundaries);
  [Second delegated investigation](mxd-limit-contracts.md); [Second delegated
  investigation](receive-limit-origin.md); [Accepted mxd
  correction](../mothra/evidence/gap-remediation/2026-11-13/mxd-correction-01/manifest.json)
- **Closure:** Not closed: broader unchanged acceptance requirements remain as
  stated above.

### GAP-012

#### Fragment reassembly edge cases

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 185–214)
- **Question:** What happens when type/total changes, fragments interleave,
  lengths overrun or underfill, transactions are abandoned, or a partial frame
  ends in EOF?
- **Implementation impact:** A codec implementing only ordinary concatenation
  has no specified outcome for common malformed or interrupted input.
- **Close when:** Publish reassembly invariants and a test matrix covering
  keys, length consistency, overshoot, underflow, abandonment and partial TCP
  delivery.
- **Prior ledger entries:** V009, V010, V020
- **Investigation leads:**
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c),
  [10058e80](../mothra/evidence/hotline-server-1.9/queries/D-10058e80.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published the complete observed reassembly matrix across62
  prior framing cases and24 new ID/envelope/EOF cases. Keys, total/type
  replacement, overshoot, interleaving, abandonment/coexistence, partial TCP
  delivery and underfilled EOF now have paired native evidence. Four new
  half-close controls distinguish FIN response from timeout; destructor traces
  establish object removal. Broader timers/global buffering remain separately
  tracked.
- **Evidence:** [Native ID/reassembly
  contract](session-transport-contracts.md#transaction-ids-reassembly-and-correlation);
  [Native envelope
  acceptance/emission](session-transport-contracts.md#native-envelope-acceptance-and-emission);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Prior framing
  matrix](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-13/review.json)
- **Closure:** Resolved against the unchanged reassembly-invariant/test-matrix
  criterion. All named matrix classes have native fixtures and
  receiver/selector evidence; no universal assembly deadline, global
  allocation cap, retry policy or historical-peer tolerance is claimed.

### GAP-013

#### Accepted envelope values and reserved bytes

- **Tracking:** P0; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2 General transaction
  frame](protocol.md#2-general-transaction-frame) (snapshot lines 88–114);
  [protocol.md — 4 Reply semantics](protocol.md#4-reply-semantics) (snapshot
  lines 215–239)
- **Question:** How are nonzero flags, reply markers other than zero/one,
  nonzero request error words, unsupported types and nonzero reply types
  handled?
- **Implementation impact:** Writer conventions do not define the
  input-validation contract.
- **Close when:** Specify accepted and rejected header values for each
  direction and their failure outcomes, supported by receiver checks and
  negative fixtures.
- **Prior ledger entries:** V002, V007, V012, V022
- **Investigation leads:**
  [10058fd0](../mothra/evidence/hotline-server-1.9/queries/D-10058fd0.c),
  [100590e0](../mothra/evidence/hotline-server-1.9/queries/D-100590e0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published direction-specific native request/reply acceptance
  and emission for flags, marker, type, ID, error and size words. Added
  unsupported0/FFFF requests, flags1/80 with errorFFFFFFFF, late/unmatched
  marker1/2/255 typeFFFF replies and zero-size reply closes. Native
  outputflags0, directtype0/reply1/status and notification types/IDs are
  checked independently in24 paired sessions.
- **Evidence:** [Native ID/reassembly
  contract](session-transport-contracts.md#transaction-ids-reassembly-and-correlation);
  [Native envelope
  acceptance/emission](session-transport-contracts.md#native-envelope-acceptance-and-emission);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Prior framing
  matrix](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-13/review.json)
- **Closure:** Resolved against the unchanged native envelope criterion,
  including receiver checks and negative request/reply fixtures. This
  specifies the native server input/output contract; historical clients
  accepting extra/noncanonical output and mxd policy remain separate
  requirements.

### GAP-014

#### TLV structural validation

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — 3 Fragmentation
  rules](protocol.md#3-fragmentation-rules) (snapshot lines 185–214)
- **Question:** What happens with a missing count, count/length mismatch,
  truncated values, trailing bytes, zero field IDs, unknown fields or maximum
  field counts?
- **Implementation impact:** The record shape alone is insufficient for a
  deterministic parameter decoder.
- **Close when:** Define exact consumption, bounds, unknown-field and
  trailing-data rules; add byte fixtures at every boundary and mismatch class.
- **Prior ledger entries:** V013, V014, V020
- **Investigation leads:**
  [100566e0](../mothra/evidence/hotline-server-1.9/queries/D-100566e0.c),
  [100572d0](../mothra/evidence/hotline-server-1.9/queries/D-100572d0.c)
- **Depends on:** No prerequisite recorded.
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured TLV
  boundaries](native-wire-details.md#captured-tlv-and-scalar-boundaries);
  [Native framing
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Packet and outcome
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-05/review.json)
- **Closure:** Exact prefix consumption, record/header/value bounds,
  unknown/zero IDs and trailing-data rules are defined with retained helper
  code and native boundary/mismatch fixtures. Settings304 outcomes
  independently expose complete indexed values and defaults. Other handlers
  may reject those defaults; their transaction-specific acceptance remains
  separate.

### GAP-017

#### Repeated scalar fields and ordering

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — Chat Invitations (Transactions 112, 113, 114) –
  Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 634–655)
- **Question:** Beyond observed list/invitation cases, are duplicate scalars
  rejected, first-wins, last-wins or accumulated, and is order meaningful?
- **Implementation impact:** Preserving repetitions is necessary but does not
  determine how each schema resolves ambiguous duplicates.
- **Close when:** Define multiplicity and ordering by transaction/field and
  test repeated scalars, interleaved repeated records and reordered inputs.
- **Prior ledger entries:** V014, V040, V042, M006
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [100572d0](../mothra/evidence/hotline-server-1.9/queries/D-100572d0.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Established sorted binary-search scalar selection without a
  first/last guarantee and original-order indexed iteration. Duplicate/reorder
  fixtures remain required. Four duplicate icon orders emitted the last icon
  in those cases only. Interleaved repeated-record and transaction/field
  multiplicity coverage remain incomplete; no universal last-wins policy
  inferred. Outer IDs 0/65000/0 process in positional order: create, rename,
  then update the new identity. This does not settle all repeated scalar
  fields. Root acceptance revision58: Resolved against the unchanged
  criterion: transaction/field cardinality and ordering are consolidated;
  captured duplicate scalar orders, interleaved settings and repeated account
  records demonstrate the documented bounded outcomes. Native scalar duplicate
  selection remains unspecified beyond observed cases; no universal first/last
  rule is claimed. Root independently checked all 45 frozen handler hashes and
  recorded multiplicity-acceptance-01.
- **Evidence:** [Framing
  evidence](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Native framing
  contracts](session-transport-contracts.md#captured-framing-and-reassembly-boundaries);
  [TLV and scalar
  outcomes](native-wire-details.md#captured-tlv-and-scalar-boundaries);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Parameter multiplicity and ordering](parameter-multiplicity.md)
- **Closure:** Resolved against the unchanged criterion: transaction/field
  cardinality and ordering are consolidated; captured duplicate scalar orders,
  interleaved settings and repeated account records demonstrate the documented
  bounded outcomes. Native scalar duplicate selection remains unspecified
  beyond observed cases; no universal first/last rule is claimed. Root
  independently checked all 45 frozen handler hashes and recorded
  multiplicity-acceptance-01.

## Values and encoding

### GAP-015

#### Field-specific scalar types

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — User Account Management – Client Initiates (Admin)
  (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153); [protocol.md — Downloading a File (Transaction
  202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 761–788)
- **Question:** Which numeric fields permit one/two/four bytes, which are
  fixed-width or signed, and how are booleans, sentinel values and invalid
  widths interpreted?
- **Implementation impact:** The generic reader's three-byte-to-zero behaviour
  could be mistaken for a valid zero or applied to a fixed-width field.
- **Close when:** Give each core scalar an explicit wire type, allowed
  widths/range and invalid-width outcome, including references and privilege
  bitmaps.
- **Prior ledger entries:** V015, V029, V051, V069
- **Investigation leads:**
  [10056a90](../mothra/evidence/hotline-server-1.9/queries/D-10056a90.c),
  [10056b90](../mothra/evidence/hotline-server-1.9/queries/D-10056b90.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Core registry now supplies field-specific
  scalar/byte/bitmap/record schemas. Non-core types and malformed-width/range
  native fixtures remain required. Captured settings icon widths0..5, low16bit
  narrowing and301 signed-short promotion:8000 emitsffff8000; initial wrong
  hypothesis retained. Other core scalar/reference/bitmap malformed-width
  outcomes remain required. Captured file-info207 for the ordinary13-byte
  fixture is a two-byte scalar000d; directory206 omits207. New listing records
  have fldrtype/zero creator/value0; existing directory values26/3/1 match
  immediate counts. These are field-specific samples, not a universal scalar
  width.
  Nested321flavoursize65535isunsigned16bitffff,notthesign-extendinggenericouter-scalarcase.
  Bodygraphzero/smallIDfields331/332/335/336arepresenttwo-bytevalues.
  Otherfield-specifictypesremainrequired. Fourteen native 337 controls
  establish zero/nonzero semantics: three-byte width defaults zero; five-byte
  input uses leading four bytes. Body navigation explicitly emits two-byte
  zeros and small IDs. Other scalar fields remain active. Native 64
  walking-bit replacements and width controls establish field110 serialization
  and padding/truncation boundaries. Bit semantics and policy remain open.
  Revision61: Eight same-session 304 transitions add measured name/icon
  omission and empty resets on a naming-allowed admin, plus options 8/12
  controls; the all-core scalar requirements remain open.
- **Evidence:** [Framing
  evidence](../mothra/evidence/gap-remediation/2026-11-12/native-framing-01/manifest.json);
  [Native framing
  contracts](session-transport-contracts.md#captured-framing-and-reassembly-boundaries);
  [TLV and scalar
  outcomes](native-wire-details.md#captured-tlv-and-scalar-boundaries);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Second delegated investigation](bitmap-boundaries.md); [Native
  documentation evidence](native-settings-transition-witness.md)
- **Closure:** Not closed: broader unchanged acceptance requirements remain as
  stated above.

### GAP-016

#### Absent, empty and zero-valued fields

- **Tracking:** P0; Ambiguous; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 240–274);
  [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — Changing User Settings (Transaction 304) –
  Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575)
- **Question:** Which operations distinguish an omitted field, a zero-length
  TLV, an empty string and numeric zero, and what defaults are applied?
- **Implementation impact:** The native writer omits empty fields while
  documented readers sometimes reset state when fields are absent.
- **Close when:** Add per-field presence/default tables and fixtures for all
  four cases, especially credentials, settings and partial account updates.
- **Prior ledger entries:** V011, V018, V037, V068
- **Investigation leads:**
  [100568b0](../mothra/evidence/hotline-server-1.9/queries/D-100568b0.c),
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Account and session settings presence/default tables are
  published, including missing/empty/NUL password and comment distinctions.
  Other operations and full native fixture coverage remain required.
  Absent/empty105 chooseactualguest; NULonly105 isdistinct. Missingguest
  fails; configuredempty-password zero-privilege guest succeeds.
  Otherfield-specific default/zero contracts remain required. Native
  missing/empty/unreadableagreement emits109withzero fields, distinct
  from101emptyvalue; bit27always154=1. Fieldwriter omitszero lengths.
  Otherfield defaults remain required. Native205 distinguishes empty201 from
  one NUL byte: the latter creates an entry named00. Absent/empty201 can
  derive the last202component as leaf. Six root/name presence combinations
  fail against existingFiles root rather than idempotent success. Other fields
  retain their original requirements.
  Native207matrixcoversallnineadminabsent/empty/new-nameversusabsent/empty/new-commentcombinationsforfiles/folders.
  SingleNULclearsandinteriorNULpersists;zero-privilegeabsentupdatesnoop
  succeeds. Otherfieldpresencecriteriaremainactive. Eight owned account cases
  verify absent/empty 106 clearing, NUL preservation, literal-x replacement
  and sparse 353 clearing of name, 111 and access. Complete 734-byte records
  and 352 output omission/presence are retained. Other field/state defaults
  remain active. Batch replacement clears omitted name, bitmap and attribute.
  Old-name plus NUL password preserves credentials; creation without old-name
  stores encoded NUL and accepts plaintext FF. Other operation defaults remain
  active. Native bitmap controls distinguish absent/empty zero defaults and
  short/long values. This does not establish every permission effect.
  Revision61: Prior nonzero 102/104 and explicit 215 followed by
  omission/empty produce ***/0 and the exact default ASCII auto-response when
  enabled. These are 304 session observations, not all-field defaults.
- **Evidence:** [Error outcomes](error-outcomes.md); [Folder
  descriptor](transfer-contracts.md#folder-item-descriptor-bytes); [Identified
  client source](identified-client-source.md); [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Native rename/comment
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Second delegated investigation](bitmap-boundaries.md); [Native
  documentation evidence](native-settings-transition-witness.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-018

#### Text encoding and transformations

- **Tracking:** P0; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Binary Message Formats (Hotline Protocol
  1.9)](protocol.md#binary-message-formats-hotline-protocol-19) (snapshot
  lines 35–42); [internal-compatibility-matrix.md — Credential obfuscation and
  text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 112–139); [protocol.md — Receiving a Chat Message
  (Transaction 106) – Server
  Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates)
  (snapshot lines 590–599); [protocol.md — Listing Files in a Folder
  (Transaction 200) – Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 748–760)
- **Question:** Which charset, normalization, NUL handling and line-ending
  rules apply to credentials, names, paths, chat, news and error text?
- **Implementation impact:** A generic UTF-8 or XOR heuristic can change valid
  native text and fail to round-trip names or message content.
- **Close when:** Publish per-field byte/string rules with non-ASCII,
  embedded-NUL, CR/LF and complemented-credential fixtures from identified
  peers.
- **Prior ledger entries:** V016, V019, V048, M005
- **Investigation leads:**
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [10056cb0](../mothra/evidence/hotline-server-1.9/queries/D-10056cb0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Added native TEXT content-loader CRLF-to-CR conversion with
  captured literal bytes and replacement helper. This is separate from
  encoding and credential complement. Other text fields and identified-peer
  byte fixtures remain required. Native14-query table and positive
  storedaccount keys corroborate ASCIIcase/CR/80->8a; NUL cases
  distinctfromempty. This isnot Unicodefolding or universalpeerencoding
  evidence. TEXT34bytes normalizeonlyCRLF to32; loneLF/80/NUL survive.
  RecognizedBMP preservesall34rawbytes. BINAfixture retypedtoTEXT
  duringGUIsetup isretained separately; noUnicode/peerencoding guarantee.
  Native InfoName highbyte9a isidentical inPrefs and162; itisnot
  UTF8reencoded.31-byte configurationdestination and32-byte typingprefix
  arecaptured. Thisisfield-specific nativebyte evidence, not a
  universalMacRoman/UTF8policy orhistoricalpeerresult. Native-shx-01 adds
  full-process receive evidence: controlled105 and native106
  preserve80/9a/c3b6/ff testbytes through the real terminal peer stdout.bin.
  Localevariables are retained; no glyph rendering or universal encoding
  declaration inferred. Native-shx-02 adds actual configured162 byte9a
  consumed by the real peer while subsequent native chat succeeds.
  Preferences/ACK byte equality is checked, not glyph rendering or a universal
  decoder policy. Native205/202 preserves tested NUL/highbyte/CR/LF/slash
  filename bytes onOS9; colon becomeshyphen. Native wire names are independent
  of renderedTSKpath strings. No genericC-string/UTF8/normalization policy
  inferred. Controlled plaintext 87 with encoded 78 succeeds after literal-x
  replacement; complement is bytewise, not an ASCII-only transform. Actual
  historical-peer and broader encoding requirements remain active. ASCII-case
  duplicate creates fail without replacement. Lowercase and uppercase 352
  retrieve the same account but response 105 complements the supplied lookup
  spelling, while enumeration retains original case. Full native byte mapping
  and peer policy remain active. Topic and chat fixtures preserve NUL and
  non-ASCII bytes while chat CR prefix expansion leaves LF unchanged. Byte
  preservation is not a general decoding or peer policy.
- **Evidence:** [Login extras and
  content](presence-messaging-contracts.md#login-extras-and-configured-content);
  [Native
  loader](../mothra/evidence/gap-remediation/2026-11-12/batch-17/queries/B17-D-10003940.c);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Full historical peer
  sessions](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Native shx
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json);
  [Configured native names and controlled receiver
  matrix](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix);
  [Second full-peer
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-019

#### Semantic length limits and truncation

- **Tracking:** P0; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [protocol.md — Changing User Settings (Transaction 304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575); [protocol.md — Sending a Chat Message (Transaction
  105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589); [protocol.md — User Account Management – Client
  Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** What byte/character limits and truncation or rejection rules
  apply to every name, password, message, subject, comment and body?
- **Implementation impact:** The 65,535-byte TLV limit does not describe
  smaller buffers, truncation, multibyte strings or advertised transfer sizes.
- **Close when:** Record field-specific limits and units, max/max-plus-one
  behaviour and aggregate limits, preserving native versus mxd-policy
  distinctions.
- **Prior ledger entries:** V013, V016, V023, V037, V051
- **Investigation leads:**
  [10056c70](../mothra/evidence/hotline-server-1.9/queries/D-10056c70.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Added content loader file-type-dependent inclusive limits:
  TEXT65535 and other types262140, plus configuration server-name copy cap31.
  Complete field/aggregate limits and native max/max-plus-one fixtures remain
  required. Native31-byte account create/read/login succeeds;32-byte
  creation/read/login reportsbadfilename. Over32login namesclippedto32
  byhelper. Scopeisthisnativefilesystempath; no valid32-byte record
  orbackend-universalcap inferred. Positive native TEXT65535 emitsfull101;
  TEXT65536/BMP262141 hit65535/262140 loaderwarnings andomitfields. BMP65536
  loadsbutfieldwriter raises1/10 before109; early/delayedpartialstates differ.
  Otherfieldlimits andtruncation remain required. PositivePrefs and162agree
  on31-byte exactname andfirst31bytes of32-byte typingattempt. Emptyname
  omits162. Thisconfiguration/UI capisdistinct fromgeneric65535-byte TLV
  andaccountlookup32/session31caps. Otherfieldlimits remain required. 205
  reads up to255 Pascal content bytes, then preOSX normalization clips
  tested32/255/256/65535-byte names to31. A44-byte .txt name yields27-byte
  prefix plus extension. Static>=0a00 branch remains unexecuted; other
  semantic length requirements remain active.
  Native207/206boundarywrites0/1/198/199/200/201/254/255/256/300/65535show199maximumreadbackforbothfile/folderprofile.
  Setterwrapperclips255andlowerDesktopManagerhelperpassesatmost200;observedreadbackdoesnotproveportablecapacity/restartdurability.
  Otherlimitsremainactive.
  Native410submitted64-bytetitleclips31contentbytes;serializerstaticcaps63title/31poster/63flavourremainseparate.
  Body65535roundtripsand321usesunsignedffff. Otherlengthlimitsremainactive.
  Native child-chain append boundary: 101 children remain reachable; the 102nd
  append returns ACK but bypasses child 101 (public ID102). This is not a
  general 100-article category ceiling. Other semantic lengths remain active.
  Native network 350 stores 32-byte password and login 32 succeeds;353
  replacement 32 also succeeds. NUL preservation of an existing 32-byte
  password clips 31, after which 31 succeeds and old 32 fails. Submitted
  65-byte 111 clips 64. Other semantic length boundaries remain required.
  Batch nested records copy at most 512 bytes; complete known prefixes survive
  a 513-byte entry, while identity beyond an incomplete first field is
  unavailable. Other semantic caps remain active. Topic inputs of
  255/256/65535 bytes establish a 255-byte cap with exact outputs and
  repeated-join readback. Other semantic caps remain active. Native all-ones
  stored/login/readback evidence preserves raw bitmap identity; unknown-bit
  meanings remain open. Revision69 adds the source-derived1024-byte final303
  output cap and bounded63-byte request110 reason staging, including the
  inferred prefix-copy transformation; at-cap runtime clipping and nonempty
  stored-reason fixtures remain unobserved.
- **Evidence:** [Login extras and
  content](presence-messaging-contracts.md#login-extras-and-configured-content);
  [Native
  loader](../mothra/evidence/gap-remediation/2026-11-12/batch-17/queries/B17-D-10003940.c);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Native rename/comment
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Second delegated investigation](bitmap-boundaries.md); [Diagnostic
  formatter and emitted byte count](diagnostic-formatting-trace.md);
  [Reason-copy trace and its
  limits](native-ban-file-format.md#request-110-reason-copy-path)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-020

#### Date and timestamp semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 2.2 Date
  parameters](protocol.md#22-date-parameters) (snapshot lines 162–184);
  [protocol.md — Reading a News Article (Transaction 400) – Client
  Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates)
  (snapshot lines 1019–1047)
- **Question:** What epoch/units apply to the supplied filesystem value, how
  do nonzero milliseconds and other years work, and is news date 330
  equivalent?
- **Implementation impact:** The observed 1904/zero/value structure cannot yet
  be converted or compared reliably across all date fields.
- **Close when:** Trace each date producer/consumer and document epoch,
  timezone, units, range and conversion fixtures including rollover cases.
- **Prior ledger entries:** V017, V064
- **Investigation leads:**
  [10058070](../mothra/evidence/hotline-server-1.9/queries/D-10058070.c),
  [1002c910](../mothra/evidence/hotline-server-1.9/queries/D-1002c910.c),
  [10005ac0](../mothra/evidence/hotline-server-1.9/queries/D-10005ac0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Confirmed INFO upload restoration does not consume transmitted
  dates: it sets modification time from GetDateTime, incrementing if
  unchanged. News and file serializers retain fixed1904year date encoding;
  native timezone/rollover/date fixtures remain required.
  Native321and400copyidentical8bytedateswith0770year,zero
  millisecondsandsecondswordsacrossthreadedfixtures.
  Actualtimezone/rolloverboundariesremainuntested.
- **Evidence:** [Article
  navigation](news-contracts.md#reading-bodies-and-navigation); [Deletion
  rewrite](news-contracts.md#deletion-graph-rewrite); [INFO
  restoration](transfer-contracts.md#info-restoration-after-upload); [Captured
  native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Authentication and settings

### GAP-022

#### Native nonempty-password encoding

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 240–274);
  [protocol.md — User Account Management – Client Initiates (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153); [internal-compatibility-matrix.md — Credential
  obfuscation and text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 112–139)
- **Question:** What exact bytes does the 1.9 server expect for nonempty
  passwords in login and account mutation, independent of SynHX's helper?
- **Implementation impact:** The guide cannot yet supply a working
  nonempty-password authentication fixture.
- **Close when:** Trace account storage and comparisons, then capture
  successful and failed logins plus account changes using known nonempty
  credentials.
- **Prior ledger entries:** V019, V023, V068, V069, M005
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c),
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** No prerequisite recorded.
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Native core
  manifest](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json);
  [Semantic
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/verification.json);
  [Source and credential
  contracts](native-wire-details.md#credential-bytes-lookup-and-account-updates);
  [Enumeration
  grammar](operation-contracts.md#administrative-account-list-and-batch-mutation);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-03/review.json);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries)
- **Closure:** Native setter/storage/comparison tracing is now joined by
  successful login with a created known nonempty password, network password
  change, acceptance of the replacement, rejection of the old password and
  plaintext replacement bytes, and the matching734-byte stored account record.
  This satisfies the unchanged credential criterion. Length extremes, restart
  durability, encoding policy and transport close timing remain
  GAP-019/064/072/082/084.
- **Progress:**  Additional paired account fixtures verify bytewise password
  complement for non-ASCII plaintext 87, full 32-byte network
  replacement/login and 31-byte sentinel clipping. Original credential
  representation closure remains unchanged.

### GAP-023

#### Login-name lookup and guest fallback

- **Tracking:** P0; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** Are absent, empty, NUL-containing or differently cased logins
  equivalent; how are complemented bytes normalized and guest permissions
  chosen?
- **Implementation impact:** The guest-name path and account-name
  transformations are not a complete authentication lookup contract.
- **Close when:** Document transformation order, canonicalization and
  absent/empty/unknown account outcomes using lookup-helper evidence and
  fixtures.
- **Prior ledger entries:** V019, V023, V027
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published transformation order and actual guest-account
  selection with14 identity-checked oracle queries and33 accepted native
  reports. Missing/configured/restored guest phases, unknown names, mixedcase,
  CR, high-byte normalization, NUL and31/32-byte native path boundaries have
  fixtures. Independent native UserData keys/privileges corroborate lookup
  results; all temporary owned accounts are removed and read back as missing.
- **Evidence:** [Captured login lookup and guest
  phases](native-wire-details.md#captured-login-lookup-and-guest-phases);
  [Native authentication
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-13/closure-review-14/review.json);
  [Repeatable authentication
  workflow](native-capture-workflow.md#reproducing-native-authentication-and-visibility-fixtures)
- **Closure:** Resolved against the unchanged lookup/canonicalization
  criterion. Absent/empty select the configuredguest account, unknown/NUL do
  not become guest, and byte transformations/native boundary outcomes are
  documented. General textencoding, other backendlimits,
  fullagreementconfiguration anddurability remain separate requirements.

### GAP-024

#### Client-version and optional login inputs

- **Tracking:** P0; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — 2.1 Parameter list (payload
  block)](protocol.md#21-parameter-list-payload-block) (snapshot lines
  115–161); [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 35–62)
- **Question:** Are fields 160/102/104 mandatory, what defaults apply if
  omitted or malformed, and does saved version affect anything besides the
  named banner/news paths?
- **Implementation impact:** A field-read list can be mistaken for required
  input and can select the wrong login-completion path.
- **Close when:** Supply a login input-condition table covering presence,
  widths, zero, version boundaries and each dependent feature without using
  version as conclusive client identity.
- **Prior ledger entries:** V023, V024, V027, V062, M002
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10005710](../mothra/evidence/hotline-server-1.9/queries/D-10005710.c)
- **Depends on:** No prerequisite recorded.
- **Evidence:** [Login
  conditions](core-field-schemas.md#login-width-and-feature-condition-matrix);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-01/review.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published presence/width/default/narrowing conditions and each
  identified version-dependent banner/category branch without client-brand
  inference. This satisfies the unchanged input-condition-table criterion.
  Malformed-width native outcomes, full login sessions and peer identity
  remain GAP-015/025/065/080/084.

### GAP-025

#### Complete login/agreement state machine

- **Tracking:** P0; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [protocol.md — Server Agreement (Transaction 109) – Server
  Initiates](protocol.md#server-agreement-transaction-109--server-initiates)
  (snapshot lines 352–386); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 387–415)
- **Question:** What are the exact ACK, 109, 354, 122 and 301 ordering and
  state transitions for early completion, ordinary acceptance, no agreement,
  repeated 121 and delayed acceptance?
- **Implementation impact:** Two observed completion paths do not yet define a
  deterministic interoperable session sequence.
- **Close when:** Provide state/sequence tables and captured fixtures for each
  configured path, including duplicate/out-of-state requests and visibility
  timing.
- **Prior ledger entries:** V025, V026, V027, V029, V035
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c)
- **Depends on:** [GAP-022](#gap-022), [GAP-024](#gap-024)
- **Progress:** Native-agreement-01 supplies42 accepted cases across11
  configurations/partial-failure phases,28setup/control reports,12separate
  exploratory reports,16read-only oracle queries and independently verified
  native agreement paths/types/forks. Missing/empty/unreadable, typed text,
  bypass, early/delayed visibility, online replay, replacement and
  oversized-field partial states are documented. Original245-byte TEXT is
  restored,242 wire bytes rechecked and the owned bypass account removed/read
  back missing. Prior native-auth-01 supplies naming/icon and
  preauth/waiting-state controls.
- **Evidence:** [Agreement condition and partial-failure
  matrix](native-wire-details.md#captured-agreement-configurations-and-partial-login-failures);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-13/closure-review-15/review.json);
  [Repeatable agreement
  workflow](native-capture-workflow.md#reproducing-agreement-configuration-and-partial-failure-fixtures);
  [Prior authentication
  controls](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json)
- **Closure:** Resolved against the unchanged configuration/state criterion.
  Cross-connection total order, universal failure/cleanup deadlines, arbitrary
  field schemas, restart durability and identified-peer or mxd acceptance
  remain separate requirements.

### GAP-026

#### Meaning and lifetime of login extras

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351); [internal-compatibility-matrix.md — Login reply and banner
  policy](internal-compatibility-matrix.md#login-reply-and-banner-policy)
  (snapshot lines 63–111)
- **Question:** What are field 161's value semantics, widths and invalidation
  rules, and field 162's encoding/limits; how do they relate to banner 122 and
  download 212?
- **Implementation impact:** An implementation can send the right IDs with
  incompatible values or stale banner identity.
- **Close when:** Define the value schemas, configuration sources and
  change/lifetime rules with sample configured/no-banner replies.
- **Prior ledger entries:** V023, V024, V025, M003, M004
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Native-login-extras-01 provides34 accepted cases:
  absent/0/150/151/190 versions onbothreadinesspaths,
  native31-byte/prefix/highbyte162 controls, empty-nameomission,20second
  namechange acrossonline/waiting/freshsessions, Local/URL/none modes
  andtwoactual212references. Existing ACKsretainA;
  freshloginseesB;121/500sendno161/162refresh intheboundedtrial. Prefs
  version5 sources/General100/10/5 andfullrecorded175-byte restoration
  arechecked.161stays twozero bytes inthesesamples anddiffers
  fromnonzero212references. ExpandedD-form store-width discovery+Ghidra
  confirms onlyconstructor directstore andloginload,
  butdoesnotcoverindexed/derived/aliasedwrites. Field161purpose
  andexhaustivechange/lifetimesemantics remain unresolved; do notreplacewith a
  constant-zero/community/bannerlabel claim. A controlled full shx process
  tolerates omitted 161 and value 0001 as well as native 0000. This
  establishes receiver tolerance for one identified build, not field 161
  meaning or lifetime. Latest captured session: The first hash-identified
  Classic client completed the delayed agreement/roster path after receiving
  native fields 160 = 190 and 161 = 0000. This one successful exchange is not
  a semantic interpretation of field 161 or evidence for other values; field
  162 was absent in this server configuration. Revision64: the identified
  Classic client accepted absent, one-zero-byte and four-zero-byte 161 through
  121/300/212 and 58-byte banner data. These are finite tolerance
  observations; they establish neither the meaning of 161, nonzero semantics
  nor configured 162 tolerance. Revision66: one proxy-appended ASCII 162 value
  was tolerated by the identified Classic client through 121/300/212 and
  58-byte banner data; 161 remained 0000. This adds no meaning or lifetime
  rule for 161 and no general codec for 162.
- **Evidence:** [Configured login-extra byte and refresh
  evidence](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Repeatable configuration
  workflow](native-capture-workflow.md#reproducing-login-extra-configuration-and-refresh-fixtures);
  [Expanded direct-store
  discovery](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/all-direct-store-candidates.json);
  [Controlled peer tolerance matrix](peer-tolerance-matrix.md); [Peer
  tolerance
  corpus](../mothra/evidence/gap-remediation/2026-11-13/delegated-peer-01/manifest.json);
  [First Classic peer session](mac-peer-first-session.md);
  [Classic161matrix](classic-field161-matrix.md); [Classic ASCII server-name
  witness](classic-server-name-162.md)
- **Closure:** Not closed: field162 representation/configuration and
  boundedrefresh have native evidence; field161 purpose and
  completechange/lifetime semantics stillfail the unchangedcriterion.
  Fullpeer/restart/timer requirements remain separate.

### GAP-027

#### Agreement absence, bypass and text rules

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Server Agreement (Transaction 109) – Server
  Initiates](protocol.md#server-agreement-transaction-109--server-initiates)
  (snapshot lines 352–386); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 387–415)
- **Question:** When is 154 emitted, how do absent/empty/unreadable agreement
  text and account bypass privileges behave, and must a client send 121 after
  early completion?
- **Implementation impact:** Agreement omission or bypass may produce a
  different readiness flow than the prose implies.
- **Close when:** Document the configuration/account condition matrix and its
  wire/state outcomes; include absent, empty and configured agreement
  fixtures.
- **Prior ledger entries:** V025, V027, V028
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Native-agreement-01 supplies42 accepted cases across11
  configurations/partial-failure phases,28setup/control reports,12separate
  exploratory reports,16read-only oracle queries and independently verified
  native agreement paths/types/forks. Missing/empty/unreadable, typed text,
  bypass, early/delayed visibility, online replay, replacement and
  oversized-field partial states are documented. Original245-byte TEXT is
  restored,242 wire bytes rechecked and the owned bypass account removed/read
  back missing. Prior native-auth-01 supplies naming/icon and
  preauth/waiting-state controls.
- **Evidence:** [Agreement condition and partial-failure
  matrix](native-wire-details.md#captured-agreement-configurations-and-partial-login-failures);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-13/closure-review-15/review.json);
  [Repeatable agreement
  workflow](native-capture-workflow.md#reproducing-agreement-configuration-and-partial-failure-fixtures);
  [Prior authentication
  controls](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json)
- **Closure:** Resolved against the unchanged configuration/state criterion.
  Cross-connection total order, universal failure/cleanup deadlines, arbitrary
  field schemas, restart durability and identified-peer or mxd acceptance
  remain separate requirements.

### GAP-028

#### Banner metadata variants and lifecycle

- **Tracking:** P1; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Banner Metadata (Transaction 122) – Server
  Initiates](protocol.md#banner-metadata-transaction-122--server-initiates)
  (snapshot lines 416–430); [protocol.md — Banner Download (Transaction 212) –
  Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 937–954)
- **Question:** Which four-byte type tags and field-153 representations are
  valid, when are they required, and how does an early-completed session
  obtain metadata without a later 121?
- **Implementation impact:** The URL and image paths are described
  conditionally without a full schema or availability sequence.
- **Close when:** Enumerate supported type/field combinations, conditions and
  ordering, including no-banner, URL, image and metadata changes.
- **Prior ledger entries:** V025, V027, V058
- **Investigation leads:**
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c)
- **Depends on:** [GAP-025](#gap-025), [GAP-026](#gap-026)
- **Evidence:** [Banner
  conditions](presence-messaging-contracts.md#agreement-and-banner-condition-tables);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-01/review.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published URL/image/native-type fallback, field153 presence and
  version/buffer gates, including no-banner and early-completion absence
  of122. Current-value reload and send-time behaviour are explicit. This
  satisfies the unchanged type/field/ordering criterion; decoding and
  delivered change/transfer fixtures remain GAP-063/080/084.

### GAP-029

#### Settings update defaults and persistence

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Changing User Settings (Transaction 304) –
  Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575); [protocol.md — Agreement Acceptance (Transaction
  121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 387–415)
- **Question:** Which omitted/empty 102/104/113/215 values reset, preserve or
  derive state, and what changes are session-only or durable?
- **Implementation impact:** The warning against patch semantics still leaves
  callers unable to construct a safe partial update.
- **Close when:** Document field-by-field update/default/persistence rules and
  before/after state plus emitted-301 fixtures.
- **Prior ledger entries:** V028, V037, V038
- **Investigation leads:**
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c),
  [10016ad0](../mothra/evidence/hotline-server-1.9/queries/D-10016ad0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Documented per-field session settings defaults/clearing and
  named byte caps, plus native 301 fan-out. Restart persistence and
  before/after native fixtures remain required. Revision61: Eight same-session
  304 transitions now have paired 301 and 104 outcomes between exact full A7
  baselines; 121 and persistence clauses remain open. Revision62: client-only
  delayed 121 default-text plans and immediate semantic gates are prepared
  against the existing agreement/account state; no new 121 default-response
  result is claimed. Revision65 imports the unrun two-phase persistence
  preparation. Its runner holds two controlled sockets through native app Quit
  and explicitly refuses to claim persistence before orderly OS shutdown and
  stopped-image account/Prefs comparisons. No persistence run is accepted
  here. Revision67: field-by-field 102/104/113/215 update/default/persistence
  rules now consolidate native 304 transitions, delayed 121 defaults, emitted
  301 and PM fixtures, and the same-image A46/A48 restart witness. Complete
  named UserData and Prefs forks remain unchanged. The 121 session-state rule
  is inferred from its shared helper and account-read path; a separate 121
  restart experiment was not performed.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native documentation evidence](native-settings-transition-witness.md);
  [Delayed 121 default-text preparation](native-121-default-preparation.md);
  [Unrun settings persistence
  preparation](native-settings-persistence-preparation.md); [Settings
  persistence
  boundary](presence-messaging-contracts.md#settings-persistence-boundary);
  [Two-phase settings witness](native-settings-persistence-witness.md);
  [Original-criterion
  acceptance](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-03/decisions.json)
- **Closure:** Met for the documented native session-settings paths. Fresh 107
  alone does not prove persistence; static session writes and unchanged named
  forks provide the additional basis. Retain the legacy 64+2 capture mismatch,
  operator-observed lifecycle/FD evidence limits and A48 missing oracle.lock
  as explicit deviations. No power-loss or all-storage guarantee follows.

### GAP-030

#### Settings option edge cases and automatic-response defaults

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Agreement Acceptance (Transaction 121) – Client
  Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates)
  (snapshot lines 387–415); [protocol.md — Changing User Settings (Transaction
  304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575); [protocol.md — Sending an Instant Message
  (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 667–699)
- **Question:** How are unknown 113 bits, auto-response enable/disable
  transitions, missing 215 and default-response text handled across 121 and
  304?
- **Implementation impact:** The three known bits do not define all
  transitions or distinguish stored text from active automatic response.
- **Close when:** Specify bit acceptance and transition tables, default
  text/encoding, and enable/disable/update fixtures without conflating PM
  enumerants.
- **Prior ledger entries:** V028, V037, V043, V045
- **Investigation leads:**
  [10004d50](../mothra/evidence/hotline-server-1.9/queries/D-10004d50.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-029](#gap-029)
- **Progress:** Shared helper 10004d50 serves 121 and 304 and assigns the
  three setting flags from bits 0–2. Ten field-113 cases and eight
  same-session 304 stages establish the documented defaults and
  enable/disable/update outcomes, including values 8 and 12. Two delayed-121
  absent/empty 215 cases emit the same exact 52-byte ASCII default; paired
  streams and all 27 gates pass. PM 108/104 enumerants remain a separate
  grammar. Independent and parent review accept the unchanged criterion.
  Durability remains GAP-029; general supplied-text encoding remains GAP-018.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native documentation evidence](native-settings-transition-witness.md);
  [Delayed 121 default-text preparation](native-121-default-preparation.md);
  [Same-session settings transitions](native-settings-transition-witness.md);
  [Delayed121 defaults](native-121-default-witness.md); [Parent
  acceptance](../mothra/evidence/gap-remediation/2026-11-14/settings-default-acceptance-01/decision.json);
  [Settings defaults acceptance](native-121-default-witness.md)
- **Closure:** Resolved against the unchanged criterion: shared-helper bit
  assignments, measured121/304 default bytes and304 transitions, and separate
  PM enumerant fixtures meet the required tables and fixtures. General
  encoding and durable persistence remain separately tracked.

## Presence and permissions

### GAP-031

#### Complete privilege bitmap registry

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Access Privilege Bits (Field
  110)](protocol.md#access-privilege-bits-field-110) (snapshot lines 440–478)
- **Question:** What do all unlisted bits, including 18/19 and 41-63, mean,
  and which bits are reserved, ignored or preserved?
- **Implementation impact:** The corrected observed subset cannot support full
  account editing or a complete permission model.
- **Close when:** Publish a 64-bit MSB-first registry with per-bit evidence,
  unknown/reserved distinctions and serialization/enforcement fixtures.
- **Prior ledger entries:** V029, V030, V031, V073
- **Investigation leads:**
  [10008a90](../mothra/evidence/hotline-server-1.9/queries/D-10008a90.c),
  [100053e0](../mothra/evidence/hotline-server-1.9/queries/D-100053e0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Published a registry covering bits0–63 with37 observed uses
  and explicit unknown ranges12–13,18–19,41–63. Reconciled40 direct accessor
  calls in25 functions; inline account/status/settings tests reviewed
  separately. Native serialization/enforcement and unknown-bit fixtures remain
  required.
  Threeownedtemporaryaccountbitmapcontrols0000000c00000000comment-only,1100000000000000rename-onlyandzero
  verify207file/foldercommentbits28/29andrenamebits3/7withactualeffects.
  Fullbitmapregistryremainsrequired.
  Native208and204admin/zerobitmapcontrolsconfirmpermissiondenialsforbothfile/folderclasses;freshhandlerqueriesretainbit4/8moveand0/6deletechecks.
  Thisisnotanisolatedsingle-bitprooforfullregistryclosure. Owned create-only,
  delete-only, update-only and zero-role fixtures establish admission,
  immediate per-item checks, subset denial and create exemption bit 27. Wider
  bitmap meanings remain active. Bit 23 alone rejects administrator
  request-110 kick but permits administrator account deletion. Bits 15/23
  permit protected self-deletion. This confirms operation-specific protection
  rather than a blanket administrator override. Receive bit 9, send bit 10 and
  create bit 11 have independent native contrasts. Zero-role uninvited join,
  invite and topic update succeed; ordinary room notifications bypass
  receive-chat gating. Thirteen reports and14 paired lifetimes establish
  MSB-first bitmap serialization and exact width handling. Roundtrip is not
  proof that unknown bits are reserved or ignored. Revision73 fresh
  independent Classicclient import preserves exact7f286e/PPCBE32/3564
  identity. Three defined-string queries find CMyAdminEditUserWin at1014fef8
  but no defined privilege labels. Negative listing is not absence from
  loadedmemory; no label-to-bit map or field111meaning is inferred.
  CompressedPEF fileoffsets cannot be treated as loadedaddresses.
- **Evidence:** [Privilege registry](privilege-contracts.md); [Native caller
  review](../mothra/evidence/gap-remediation/2026-11-12/batch-15/privilege-callsite-review.json);
  [Native rename/comment
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Second delegated investigation](bitmap-boundaries.md); [Classic privilege
  discovery bounds](classic-privilege-discovery.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-032

#### Privilege composition and inheritance

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Access Privilege Bits (Field
  110)](protocol.md#access-privilege-bits-field-110) (snapshot lines 440–478);
  [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  733–747); [protocol.md — Managing News Structure (Transactions 380, 381,
  382) – Client Initiates
  (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods)
  (snapshot lines 1087–1103)
- **Question:** How do general, folder and news helpers combine account
  rights, path-specific rules, inheritance and administrator overrides?
- **Implementation impact:** Knowing a bit number does not establish which
  request on which object is authorized.
- **Close when:** Document decision tables for the three helper domains,
  including inherited/overridden rights and forbidden operations.
- **Prior ledger entries:** V030, V053, V055, V056, V065, V073
- **Investigation leads:**
  [10008a90](../mothra/evidence/hotline-server-1.9/queries/D-10008a90.c),
  [10008ab0](../mothra/evidence/hotline-server-1.9/queries/D-10008ab0.c),
  [10008ad0](../mothra/evidence/hotline-server-1.9/queries/D-10008ad0.c)
- **Depends on:** [GAP-031](#gap-031)
- **Evidence:** [Privilege
  composition](privilege-contracts.md#operation-specific-composition);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-01/review.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published decision tables for identical direct-session
  general/file/news accessors, base/additional/target/grant checks and absence
  of accessor-level inheritance/admin override. This satisfies the unchanged
  decision-table criterion; permission/alias/runtime evidence remains
  GAP-031/047/054/072/084.

### GAP-033

#### User, room, article and reference identifier lifetimes

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 479–511); [protocol.md — Chat Invitations (Transactions 112,
  113, 114) – Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 634–655); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974)
- **Question:** What are each ID's wire width, allocation scope, sentinel
  values, wrap/reuse rules and persistence across reconnects or restart?
- **Implementation impact:** A shared numeric value can be misinterpreted
  across object/session lifetimes or truncated using the wrong width.
- **Close when:** Provide a domain-specific identifier registry with
  allocation/reuse rules and stale-ID/wrap fixtures.
- **Prior ledger entries:** V032, V042, V051, V061, V064
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Recovered 16-bit user counter zero-skipping without collision
  scan and separate random/counter room allocator with live-room collision
  scan. Transfer/transaction domains remain separately documented;
  stale/reuse/wrap fixtures still required. Added bounded owner-departure,
  after-close reuse and duplicate banner attachment: second transport receives
  no repeat bytes and owner cleanup closes it while first remains
  quiet3seconds. No general collision/wrap or permanent-orphan lifetime is
  inferred.
  IndependentnativecategorieseachusepublicID1;325categorypathqualifiesthearticleID.
  SixmaincategoryIDsandbodygrapharecaptured,butbroaderuser/room/referenceallocation/reuseandwraplifetimesremainopen.
  Public article ID102 remains indexed/readable despite omission from 371
  after the 102nd child append. Absence from traversal is not ID invalidation.
  Other domains/reuse/wrap remain active. Captured room IDs are four-byte
  nonzero values from random/counter generation; room lookup uses the full
  value. No room/UID is reused from an earlier session. Wider identifier
  wrap/reuse lifetimes remain active.
- **Evidence:** [Session transport contracts](session-transport-contracts.md);
  [Core schemas](core-field-schemas.md); [Batch
  07](../mothra/evidence/gap-remediation/2026-11-12/batch-07/manifest.json);
  [Native HTXF header/reference
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-034

#### Colour/status bitmap semantics

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 479–511); [protocol.md — User Appearance and Updates
  (Transaction 301 & 302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 512–530)
- **Question:** What does each field-112/packed-roster status bit represent
  and when does it change relative to settings, privileges or away state?
- **Implementation impact:** Clients can decode record lengths yet display or
  propagate incompatible presence state.
- **Close when:** Trace status construction and publish a separate status-bit
  registry plus state-transition examples.
- **Prior ledger entries:** V032, V035
- **Investigation leads:**
  [10005000](../mothra/evidence/hotline-server-1.9/queries/D-10005000.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c)
- **Depends on:** [GAP-018](#gap-018)
- **Evidence:** [Status registry and
  examples](presence-messaging-contracts.md#status-word-separate-from-the-privilege-bitmap);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-01/review.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Traced six status masks and exact aggregate predicate to native
  assembly, with explicit calculated state-transition examples. This satisfies
  the unchanged registry/example criterion, without claiming captures.
  Delivered settings/roster/account transitions remain GAP-029/035/073/084.

### GAP-035

#### Roster and update ordering

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Retrieving the User List (Transaction 300) –
  Client
  Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates)
  (snapshot lines 479–511); [protocol.md — User Appearance and Updates
  (Transaction 301 & 302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 512–530); [protocol.md — Login (Transaction 107) – Client
  Initiates](protocol.md#login-transaction-107--client-initiates) (snapshot
  lines 300–351)
- **Question:** Does 301 include the subject user, when is a session visible
  in 300, and how are snapshots ordered against concurrent changes and 354?
- **Implementation impact:** A client can miss or double-apply a user when
  initial roster and updates overlap.
- **Close when:** Document eligibility, recipient and ordering rules, with
  initial login, rename and snapshot-race event traces.
- **Prior ledger entries:** V032, V034, V035, V037
- **Investigation leads:**
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** [GAP-025](#gap-025), [GAP-033](#gap-033),
  [GAP-034](#gap-034)
- **Progress:** Traced online/ready fan-out including online self, and initial
  login 301 before new-session online flag. Snapshot concurrency and delivered
  ordering fixtures remain required. Observerrosters exclude authenticated
  delayedsubject until121 and include earlysubject before121. Repeated107
  post-close3second snapshot stilllists subject, thenliteralunread302 arrives;
  noatomic snapshot/subscription oruniversalcleanup deadline claimed.
  40configuredmatrixcases independentlyshowearly301/visibility before121
  anddelayedvisibility after121. Overflowearlyremainsvisiblewithout109;
  delayedneverlisted. Noatomic300subscription/crossconnectiontotalorder claim.
  Two matching sessions receive their new zero-mask 354 before their own 301;
  peer rename messages can precede that recipient's 354. Caller ACK precedes
  its two rename notifications and requested snapshot. Password/attribute-only
  edits emit no extra 354/301 in the observed windows. Broader snapshot races
  remain required. Revision70 prepares a bounded two-session300/304 overlap
  collector with old/new name-icon pair checks, same-socket500barriers,
  stable300 andretainedtails. Five socketpair tests exercise bothACK/301orders
  and malformed/truncated/correlation/torn/extra-row cases; this is
  offlinepreparation, not the required native overlap trace or
  universalatomicity proof. Revision72 accepts the native C87 overlap trace
  and C89 portable replay: two owned sessions, A300ID11 old Bname/icon,
  B304ID20 change, A/B301+500barriers, finalA300ID13 new pair, sameBUID0003.
  Four paired TCP lifetimes include controlpre/post18; old/new
  snapshot/schedule/tail provenance faultcontrols pass. Combined
  priorinitial107/121 visibility and353live-rename per-socket examples
  meetoriginalcriterion. Localarrival_ns isframecompletion, notserver
  execution/wirearrival; no
  globaltotalorder/universalsnapshotatomicity/race-freesubscription guarantee.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Roster-overlap preparation](native-roster-overlap-preparation.md); [Roster
  snapshots and concurrent
  updates](presence-messaging-contracts.md#roster-snapshots-and-concurrent-updates);
  [Native roster overlap witness](native-roster-overlap-witness.md); [Portable
  roster packet
  evidence](../mothra/evidence/gap-remediation/2026-11-14/native-roster-overlap-01/manifest.json);
  [Original-criterion
  decision](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-06/decision.json)
- **Closure:** Met for documented eligibility/recipient rules and
  initial-login, rename and one snapshot-race event trace. Initial joiner301
  is broadcast before joineronline/354; an already-online settings sender can
  receive its own301. The finite overlap returned old then new state after
  recorded same-socket handler barriers. Untested interleavings and stronger
  atomic snapshot/subscription promises remain unproved. No full A7 health,
  orderlyOSshutdown or observed runner/proc namespace receipt is claimed; unit
  namespace configuration, executed guard and paired TCP separately bound
  placement.

### GAP-036

#### Disconnect notification and cleanup

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Appearance and Updates (Transaction 301 &
  302) – Server
  Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates)
  (snapshot lines 512–530); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 612–621); [protocol.md — Disconnecting a User (Transaction
  110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 1154–1199)
- **Question:** Which teardown paths emit 302, which fields/recipients are
  used, and when are rooms, queued transfers and IDs cleaned up?
- **Implementation impact:** The known explicit-leave path does not specify
  global disconnect consistency.
- **Close when:** Trace normal EOF, timeout, kick and failure teardown, then
  document and fixture 302 and associated room/transfer cleanup ordering.
- **Prior ledger entries:** V035, V041, V072
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c),
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-033](#gap-033), [GAP-035](#gap-035)
- **Progress:** Identified native 302 producer with UID 103 after per-room 118
  and empty-room removal. Departing session is removed before fan-out;
  transfers clean via owner checks later. EOF/kick/timeout native traces
  remain required. Observerreceives302 for failed/premature sessions
  neverpresent inrosters andwithno301. Repeated107 case hasdelayed302
  afterpostclose snapshot; literal28-byte tail pinned inbothviews.
  Broaderroomcleanup andtiming requirements remain. Overflowdelayed
  emits302withoutprevious301/listing; overflowearlycleanup removesvisibleUID.
  Fullroomcleanup/scheduling/lifetime remain required. Account deletion
  delivers exact data-only 104 notice and guest-first FIN to two subjects. Two
  subsequent observer snapshots still contain them; two exact 28-byte 302
  messages lie beyond the observer's recorded read prefix in both packet
  views. Broader room/transfer, timeout/kick and close scheduling criteria
  remain active. Two new owned deletion cases have guest-first FIN and stale
  snapshots after a measured three-second pause. Exact 28-byte target-specific
  302 tails are retained in both packet views; an earlier unrelated 302 is
  distinguished. Wider teardown cases remain active. Client closes generate
  additional room 118 and roster 302 tails. Recorded prefixes agree at
  host/guest boundaries, but late guest output can exceed host output after
  closure. Each view and target/room identity is retained separately; general
  teardown remains active. Revision73 prepares a finite135second A/B/F/O
  liveness timeline with source-gated delayed107 and partial121. Fourteen
  offline controls validate generatedbytes, semanticnegativecases and
  reporttiming/terminal reconstruction. This is preparation only; a native
  case and pairedpacket publication remain required. Onlineidle>600 and
  broaderroom/transfercleanup are not covered. Revision74 accepts finite C93
  liveness capture and C94 portable replay: pre/post18 controls, seven
  coordinator flows, nine total lifetimes with exact paired
  applicationbytes/tails. A never-complete107 locallyEOF65.116360; B
  selected107at45/partial121at50 locallyEOF110.017097; F failed107
  locallyEOF35.138506. GuestRST becomesrelayEOF forA/B/F. OnlineO remainsopen
  through135secondwindow thenclientfirstFIN. SixO302 carryonly103, no301,
  T46rosteronlyO; UID-to-socket labels remainunproved.
  Nativeclock/uniquewakecause/configuration/onlineidle>600 and
  broaderroom/transfercleanup remainopen.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Finite native liveness fixture
  preparation](native-liveness-preparation.md); [Finite native liveness
  witness](native-liveness-witness.md); [Paired liveness packet
  corpus](../mothra/evidence/gap-remediation/2026-11-14/native-liveness-01/manifest.json);
  [Selected-request and partial-input
  timing](session-transport-contracts.md#captured-selected-request-and-partial-input-timing)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-037

#### Diagnostic-text output contract

- **Tracking:** P2; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Viewing User Info (Transaction 303) – Client
  Initiates](protocol.md#viewing-user-info-transaction-303--client-initiates)
  (snapshot lines 531–541)
- **Question:** Are the 303 text labels, line endings, address representation
  and transfer summaries stable protocol content or
  build/configuration-dependent presentation?
- **Implementation impact:** An implementation may promise exact native text
  or parse it as a stable structure without evidence.
- **Close when:** Define mandatory versus descriptive content, encoding/limits
  and representative replies; explicitly state whether exact textual parity is
  required.
- **Prior ledger entries:** V036, V048
- **Investigation leads:**
  [10016150](../mothra/evidence/hotline-server-1.9/queries/D-10016150.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Documented diagnostic fields, generated
  session/account/address/transfer content and final 1024-byte formatting cap.
  Exact-text parity is an unchosen release policy; representative native
  outputs/encoding fixtures remain required. Five native diagnostic reports
  and six paired lifetimes verify allowed 299/303-byte text, raw8e
  preservation, denied/missing families, stale UID negative control and
  one-row same-connection self targeting. Account baseline restored. Active
  transfer/queue and near-boundary examples plus exact-text release policy
  remain open. The bounded transfer-state attempt stopped at a failed owned
  upload before active/queued or near-boundary 303 states existed. Three
  captures retain preflight, exact failed seed and guarded cleanup; settings
  were never changed. Those requested diagnostic examples and exact-text
  policy remain open. Latest A8 phase 1: A8 phase 1 now supplies an actual
  one-active/one-waiting 303 with 350 field-101 bytes. Active row has
  percent/size; waiting row has (File). The first verifier rejected this
  distinct grammar and its failure is retained beside a corrected result. Both
  saved references were cancelled, original 100/10/IP5 settings
  restored/reopened, and exact account/41-file/metadata/idle baselines
  verified. Density at 8/8, near-1024 formatting and the exact-text release
  decision remain unmet. Revision68: consolidate the mandatory 303
  request/privilege/reply envelope and descriptive text boundary with idle,
  active/queued, density and 995-byte positive partial observations.
  Independent Ghidra formatter/wrapper/handler/field-writer traces show a
  final cap of1024 bytes, no reserved or appended NUL, and the returned byte
  count as TLV101 length. The old void decompiler wrapper signature is
  corrected by instruction evidence. For the baseline, generated labels/prose
  are descriptive and exact wording is not required; any mxd byte-for-byte
  presentation release promise remains separate and on hold.
- **Evidence:** [Filesystem and board
  contracts](filesystem-and-board-contracts.md); [Source
  lineage](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits);
  [Portability procedure](evidence-portability.md); [Batch
  08](../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json);
  [Native diagnostic replies](diagnostic-replies.md); [Native diagnostic
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/manifest.json);
  [Second delegated investigation](diagnostic-transfer-boundaries.md); [Active
  and queued native diagnostic](native-diagnostic-existing-witness.md);
  [Diagnostic contract](diagnostic-replies.md); [Formatter-to-field
  trace](diagnostic-formatting-trace.md); [Independent criterion and formatter
  audits](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-04/decisions.json)
- **Closure:** Met for mandatory versus descriptive content, raw-byte encoding
  observations, source-derived limits and representative replies. The995-byte
  reply is inside an overall failed capture; no at-cap native clipping
  fixture, general codec, every intermediate buffer safety or all-client
  parsing claim is made.

## Chat and messaging

### GAP-038

#### Room access and main-chat membership

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589); [protocol.md — Joining a Chat Room (Transaction
  115) – Client
  Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates)
  (snapshot lines 600–611); [protocol.md — Chat Invitations (Transactions 112,
  113, 114) – Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 634–655); [protocol.md — Additional Admin Privileges
  Note](protocol.md#additional-admin-privileges-note) (snapshot lines
  1215–1223)
- **Question:** Is the main room implicit, and what authorizes join, send,
  invite, topic edit or administrative access to a private room?
- **Implementation impact:** The presence of a room ID and bit-11 check does
  not specify all membership/permission requirements.
- **Close when:** Publish room-state and permission tables with
  member/non-member, owner/admin, missing-room and main-chat cases.
- **Prior ledger entries:** V039, V040, V041, V042, V073
- **Investigation leads:**
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c),
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-032](#gap-032),
  [GAP-033](#gap-033)
- **Progress:** Documented actual room handler checks: join and subject do not
  enforce invitation/owner/membership privilege in these handlers; main-chat
  routing is separate. Missing/member/nonmember native fixtures remain
  required. Published native permission/state table covers creator/admin,
  member/non-member, zero/read/send roles, missing-room and implicit main
  chat. Eight scenarios prove uninvited join, outsider invite/topic/send,
  receive gating and independent create denial.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Closure review
  24](../mothra/evidence/gap-remediation/2026-11-13/closure-review-24/review.json)
- **Closure:** Closed against the unchanged original criterion using the
  published native room contract, eight complete scenarios and closure review
  24. Two failed recorder expectations remain failed. Local send/recipient
  order is not a universal cross-socket receipt guarantee; decoding policy,
  general teardown/flood/identifier lifetimes, historical clients and mxd
  remain separate active requirements.

### GAP-039

#### Invitation lifecycle and partial failures

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Chat Invitations (Transactions 112, 113, 114) –
  Private
  Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats)
  (snapshot lines 634–655)
- **Question:** How are duplicate target UIDs, declined/expired invitations,
  repeated joins, disconnected invitees and mixed valid/invalid target lists
  handled?
- **Implementation impact:** Repeated UID support alone does not define
  whether a request partially succeeds or how invitation state expires.
- **Close when:** Document 112/113/114 lifecycle, recipient outcomes,
  atomicity and retries; include mixed-target and disconnect/reject fixtures.
- **Prior ledger entries:** V042, V041
- **Investigation leads:**
  [10017f30](../mothra/evidence/hotline-server-1.9/queries/D-10017f30.c),
  [100188e0](../mothra/evidence/hotline-server-1.9/queries/D-100188e0.c),
  [10018340](../mothra/evidence/hotline-server-1.9/queries/D-10018340.c)
- **Depends on:** [GAP-038](#gap-038)
- **Progress:** Documented notification-only invitation behaviour, target
  filtering, repeated-target iteration, refusal/automatic feedback and
  rejection routed as room chat 106. Lifecycle, partial-target and disconnect
  native fixtures remain required. Mixed-target creates/invites retain valid
  duplicate notifications, skip missing/disconnected/self/member targets and
  can repeat delivery on retry. Repeated rejection yields exact system chat
  but does not block join. Refusal/automatic codes 3/4 and sender feedback
  suppression are captured; join has no invitation-expiry/capability state.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Closure review
  24](../mothra/evidence/gap-remediation/2026-11-13/closure-review-24/review.json)
- **Closure:** Closed against the unchanged original criterion using the
  published native room contract, eight complete scenarios and closure review
  24. Two failed recorder expectations remain failed. Local send/recipient
  order is not a universal cross-socket receipt guarantee; decoding policy,
  general teardown/flood/identifier lifetimes, historical clients and mxd
  remain separate active requirements.

### GAP-040

#### Room snapshot and notification ordering

- **Tracking:** P1; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Joining a Chat Room (Transaction 115) – Client
  Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates)
  (snapshot lines 600–611); [protocol.md — Leaving a Chat Room (Transaction
  116) – Client
  Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates)
  (snapshot lines 612–621); [protocol.md — Chat Room Notifications
  (Transactions 117 & 118) – Server
  Initiates](protocol.md#chat-room-notifications-transactions-117--118--server-initiates)
  (snapshot lines 622–633)
- **Question:** When is subject 115 omitted versus empty, does the joining
  user appear in the returned roster, and how do 117/118 interleave with
  join/leave replies?
- **Implementation impact:** Two peers can construct different room membership
  from the same partially specified sequence.
- **Close when:** Specify subject presence, roster inclusion and event
  ordering, including repeated join, last-member leave and concurrent
  membership changes.
- **Prior ledger entries:** V040, V041
- **Investigation leads:**
  [100183c0](../mothra/evidence/hotline-server-1.9/queries/D-100183c0.c),
  [10018620](../mothra/evidence/hotline-server-1.9/queries/D-10018620.c)
- **Depends on:** [GAP-034](#gap-034), [GAP-038](#gap-038)
- **Progress:** Documented 117 before add, post-add roster ACK, repeated-join
  no duplicate push, nonempty leave 118 and last-member deletion. Concurrent
  native fixtures remain required. Native subject omission, self-including
  post-add rosters, repeated join, non-member leave and last-member deletion
  are published. Two outstanding joins return coherent 2/3 snapshots; paired
  leaves preserve departure cuts. Static local enqueue order and per-recipient
  order are distinguished from cross-socket receipt order.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Closure review
  24](../mothra/evidence/gap-remediation/2026-11-13/closure-review-24/review.json)
- **Closure:** Closed against the unchanged original criterion using the
  published native room contract, eight complete scenarios and closure review
  24. Two failed recorder expectations remain failed. Local send/recipient
  order is not a universal cross-socket receipt guarantee; decoding policy,
  general teardown/flood/identifier lifetimes, historical clients and mxd
  remain separate active requirements.

### GAP-041

#### Subject update validation

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Chat Subject Management (Transactions 119 &
  120)](protocol.md#chat-subject-management-transactions-119--120) (snapshot
  lines 656–664)
- **Question:** Who may change a topic, what are the maximum length/encoding
  rules, and do absent and empty 115 both clear it?
- **Implementation impact:** The current description establishes a setter/send
  site without a complete authorized update contract.
- **Close when:** Document topic permissions and input/default rules with
  denied, empty, omitted, boundary-length and successful notifications.
- **Prior ledger entries:** V041, V073
- **Investigation leads:**
  [10018760](../mothra/evidence/hotline-server-1.9/queries/D-10018760.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-019](#gap-019),
  [GAP-038](#gap-038)
- **Progress:** Documented subject requester unused, no membership/privilege
  check in this handler, 255-byte cap, missing/empty clearing and omitted
  empty 115 in notification. Denied/missing/boundary native fixtures remain
  required. Zero-privilege outsider topic changes succeed; missing room is
  silent. Omitted/empty clears and omits 115; binary/NUL/CR/LF survive, and
  255/256/65535 inputs produce the exact 255-byte boundary and later join
  readback. No invented membership-denied topic branch.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Closure review
  24](../mothra/evidence/gap-remediation/2026-11-13/closure-review-24/review.json)
- **Closure:** Closed against the unchanged original criterion using the
  published native room contract, eight complete scenarios and closure review
  24. Two failed recorder expectations remain failed. Local send/recipient
  order is not a universal cross-socket receipt guarantee; decoding policy,
  general teardown/flood/identifier lifetimes, historical clients and mxd
  remain separate active requirements.

### GAP-042

#### Chat formatting and option 109

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589); [protocol.md — Receiving a Chat Message
  (Transaction 106) – Server
  Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates)
  (snapshot lines 590–599)
- **Question:** What are option-109 values/defaults, exact server formatting,
  newline/NUL handling and recipient rules for main versus room chat?
- **Implementation impact:** The delivered text cannot be reproduced from raw
  client input using the current guide.
- **Close when:** Trace formatting and fan-out helpers and record
  ordinary/action/system, multiline and permission-denied examples with
  byte-level text rules.
- **Prior ledger entries:** V039, V048
- **Investigation leads:**
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-019](#gap-019)
- **Progress:** Documented action option exactly 1, ordinary fallback for
  other values, actual recipient helper predicates and lack of sender
  membership check in room chat handler. Exact multiline/non-ASCII formatting
  fixtures remain required. Ordinary/action/system and denied-send fixtures
  establish exact prefix, 13-byte ordinary name clipping and width padding,
  non-1 fallback, CR expansion, LF/CRLF/NUL/non-ASCII preservation and
  main/private recipient rules. Short-name prefix is right-justified; decoding
  policy remains separate.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Closure review
  24](../mothra/evidence/gap-remediation/2026-11-13/closure-review-24/review.json)
- **Closure:** Closed against the unchanged original criterion using the
  published native room contract, eight complete scenarios and closure review
  24. Two failed recorder expectations remain failed. Local send/recipient
  order is not a universal cross-socket receipt guarantee; decoding policy,
  general teardown/flood/identifier lifetimes, historical clients and mxd
  remain separate active requirements.

### GAP-043

#### Private-message routing truth table

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending an Instant Message (Transaction 108) –
  Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 667–699)
- **Question:** How do options 1-4, both peers' refusal/automatic-response
  flags, empty text and quoted field 214 combine, including post-ACK rejection
  or automatic-response loops?
- **Implementation impact:** The guide lists enumerants but does not fully
  specify who receives what in each state.
- **Close when:** Publish a sender/recipient/options decision table with ACKs
  and emitted 104 fields for each supported case.
- **Prior ledger entries:** V043, V044, V045
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-030](#gap-030)
- **Evidence:** [PM routing
  table](presence-messaging-contracts.md#private-message-routing); [Unchanged
  criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-01/review.json)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Published sender/recipient/options decisions, pre-routing ACK,
  feedback and original-message identity/field rules for supported cases. This
  satisfies the unchanged routing-table criterion. Text/quote limits, other104
  producers, spam and native delivered cases remain GAP-019/044/045/084.

### GAP-044

#### Type-104 variant schemas

- **Tracking:** P1; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Receiving a Private Message (Transaction 104) –
  Server
  Initiates](protocol.md#receiving-a-private-message-transaction-104--server-initiates)
  (snapshot lines 700–717); [protocol.md — Disconnecting a User (Transaction
  110 & 111) – Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 1154–1199); [protocol.md — Sending a Chat Message
  (Transaction 105) – Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589)
- **Question:** Which fields identify user messages, server/admin notices,
  refusals and kick notices; are sender UID/name/options mandatory in each
  variant?
- **Implementation impact:** A single parser cannot reliably distinguish
  notice origin or field requirements from a description of related messages.
- **Close when:** Define discriminators and per-variant required/optional
  fields, with fixtures for each known producer.
- **Prior ledger entries:** V043, V045, V046, V048, V072
- **Investigation leads:**
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-003](#gap-003), [GAP-043](#gap-043)
- **Progress:** Separated routed user/feedback 104 schemas from data-only
  console/kick notices and chat-denial forms. All known producers and
  byte-level native variant fixtures still need completion. Existing-login
  create collision emits exact 104 fields 101 text and 109 marker 0001,
  followed by final successful batch reply. Other 104 variants remain active.
  Revision60: second disposable lab failed the mandatory full A7 download
  after 98,304 of 1,049,073 bytes, before any option-two request.
  Guest/namespace/recorder prefixes match; all observed payload was ACKed with
  positive receive windows. Producer stall cause remains unknown; this is a
  retained failure, not ban acceptance. Revision62: the third disposable lab
  also failed its mandatory 29-action A7 at the same 98,304-byte prefix,
  before any account seed or option-two request. Independent reassembly
  confirms C32 completed 1,049,073 bytes in both views; C35/C45 stopped at the
  identical prefix. Recorded source images, binaries and preferences match,
  but live worker/GUI state is missing and the cause remains unknown.
  Revision64 consolidates known 104 producer schemas and explicitly
  overlapping data-only and 109=1 variants. Ordinary PM/feedback, invitation
  feedback, denied chat, batch collision, account deletion, console and
  temporary ban have captured witnesses. Permanent ban and configured
  address-ban application still need accepted native fixtures. No universal
  origin discriminator is asserted. Revision65 accepts the C56 control-only
  option-two notice: data-only104/101 exact42 ASCII bytes, target EOF,
  requester ACK/302 and same-admin readback. Six complete paired TCP lifetimes
  and stopped49-byte Banned data are retained. Configured-address-ban
  application104 producer10006590 still lacks a fixture; no universal origin
  discriminator or complete closure follows. Revision66: an independent
  PowerPC32 fresh no-analysis Ghidra import and 160-byte raw read pin the
  configured-ban helper 101 to the same 42-byte ASCII permanent-ban notice.
  The original wrong automatic-language import was rejected before content
  access. Function count zero is explicit; this is raw/static evidence, not a
  new wire fixture. The pinned resource fork identifies Options but contains
  no mapped ban-list editor. Actual Options control/address mapping and the
  configured-application notification remain open. Revision67: the
  notification inventory specifies identity-bearing, denial/collision and
  data-only variants with required/optional fields and positive fixtures for
  every listed known producer. Configured address-ban application now has a
  paired native one-Save fixture: both held clients receive sole field 101
  with the exact permanent-ban text and EOF; no request 110 was sent. The
  deletion helper is reached from 351 and qualifying nested 349 deletion; 353
  and 349 live updates use a different helper.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Failed disposable-lab baseline and packet
  replay](native-transfer-stall.md); [Repeated baseline failure and successful
  control](native-transfer-stall.md#repeated-baseline-and-a-successful-comparison);
  [Control-onlybanpreparation](native-ban-control-preparation.md);
  [104producerinventory](notification-104-variants.md); [Permanent-ban control
  witness](native-ban-control-witness.md); [Configured-ban static bytes and UI
  gate](native-configured-ban-static.md); [Options resource mapping
  limit](native-configured-ban-ui-resources.md); [Type-104 variants and
  ambiguity](notification-104-variants.md); [Configured-ban native
  witness](native-configured-ban-witness.md); [Original-criterion
  acceptance](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-03/decisions.json)
- **Closure:** Met at known-producer scope. UID/name/113 are not universal.
  Shared 109 and data-only shapes cannot uniquely identify their producer, and
  operator text can equal generated text. No exhaustive absence of further
  producers, universal origin discriminator, expiry/protection or general
  codec guarantee is claimed.

### GAP-045

#### Flood, spam and throttling outcomes

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Sending a Chat Message (Transaction 105) –
  Client
  Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates)
  (snapshot lines 578–589); [protocol.md — Sending an Instant Message
  (Transaction 108) – Client
  Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates)
  (snapshot lines 667–699); [protocol.md — Broadcasting a Message (Transaction
  355) – Admin/Server
  Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated)
  (snapshot lines 1200–1214); [protocol.md — Changing User Settings
  (Transaction 304) – Client
  Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates)
  (snapshot lines 542–575)
- **Question:** What counters, windows, limits and reset conditions cause
  rejection, delayed handling, ACK-then-close or disconnection for each
  operation?
- **Implementation impact:** Ordinary traffic and retry policies can trigger
  undocumented native rate behaviour.
- **Close when:** Trace per-operation limits/configuration and publish bounded
  timing/rate fixtures plus explicit mxd policy where parity is intentionally
  different.
- **Prior ledger entries:** V038, V039, V044, V046
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [1000fc20](../mothra/evidence/hotline-server-1.9/queries/D-1000fc20.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c),
  [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Separated per-session request counter from server-wide
  last-address connection burst. Documented preincrement >120 test, >60 reset,
  repeat >10 with <30 age and non-sliding same-address timestamp.
  Counter-boundary/interleaved-address/expiry native fixtures remain required.
  Initial seed receives 121 ACKs including login within 17.74 seconds, then
  EOF before request 219; fresh login explicitly reports a temporary ban and
  GUI says Autobanned for flooding. Dispatcher trace has
  count/60-second/1800-second branches. Recovery is a new process, not natural
  expiry evidence; broader rate/timing criteria remain active.
- **Evidence:** [Activity
  clocks](session-transport-contracts.md#activity-clocks-and-incomplete-input);
  [Flood
  counters](session-transport-contracts.md#flood-and-connection-burst-counters);
  [Transfer timer
  resets](transfer-contracts.md#transfer-timer-origins-and-resets); [Captured
  article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-046

#### Legacy-board data and update contract

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Legacy Message Board (Transactions 101, 102,
  103)](protocol.md#legacy-message-board-transactions-101-102-103) (snapshot
  lines 718–732)
- **Question:** What are the aggregate 101 format, append/replace rules for
  103, post size limits, persistence and 102 update ordering/recipients?
- **Implementation impact:** Keeping the old board in scope does not yet
  provide an interoperable read/post/update implementation.
- **Close when:** Document board serialization and mutation semantics with
  multi-post, empty, boundary-size and update-recipient fixtures.
- **Prior ledger entries:** V047
- **Investigation leads:**
  [1000f130](../mothra/evidence/hotline-server-1.9/queries/D-1000f130.c),
  [1000f260](../mothra/evidence/hotline-server-1.9/queries/D-1000f260.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Traced newest-segment prepending, native date/name header and
  separator, whole-board file write before ACK, retrieval clipping65535, post
  length8192 and post-ACK spam suppression before 102 fan-out.
  Multi-post/empty/boundary and recipient native fixtures remain required.
  Revision74 six parity-gated readonlyGhidra memoryqueries pin Pascal16
  MessageBoard.txt, formatliteral and separatorPascal3c→CR+58underscores+CR.
  ImmutablebaseTSK11191 positivelyprovesallocatedemptyDATA/RSRC
  atHotline19/MessageBoard.txt. No nativeboardpost or liveempty101 reply is
  inferred; planned multi-post/boundary/recipient fixtures remainrequired.
  Revision75 retains the aborted firstboard lab: receipt-property-shape
  mismatch and missingcorrection-script127 bothbeforefirstprotocolsocket;
  host/namespacePCAPs24B, guestbootDHCP/ARPonly, no18readiness andno
  boardcase. Five stoppednamedforks unchanged, boardDATA/RSRCremainzero.
  B79/B80offlineboardmatrix passes11tests inclrealmalformedtailcleanup;
  thisdoesnotfulfilnativeboardacceptance. Exactreceiptbuilder has7faulttests,
  independentreview andrealmanagedlease/passivecapturefunctionrehearsal;
  fullnewMac/runtimeCLIreadiness remainsseparate.
  Freshstoppedboard02preparationdoesnotimplyliveauthority.
  Prioracceptednativefixturesremainvalid; no mxdvalidationresumes.
- **Evidence:** [Filesystem and board
  contracts](filesystem-and-board-contracts.md); [Source
  lineage](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits);
  [Portability procedure](evidence-portability.md); [Batch
  08](../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json);
  [Legacy board static format](legacy-board-format.md); [Native board fixture
  preparation](native-board-preparation.md); [Aborted pre-contact board
  lab](native-board-readiness-failure.md); [Receipt-builder workflow and
  limits](../mothra/docs/native-capture-receipt.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Files and paths

### GAP-047

#### Structured path format

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing Files in a Folder (Transaction 200) –
  Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 748–760); [protocol.md — Moving Files/Folders (Transaction
  208) – Client
  Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates)
  (snapshot lines 874–886); [protocol.md — Listing News Categories
  (Transaction 370) – Client
  Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates)
  (snapshot lines 986–1003)
- **Question:** What are the counts, component records, reserved bytes, root
  representation, limits and normalization rules for fields 202/212/325, and
  do those fields share a grammar?
- **Implementation impact:** Control transactions cannot address filesystem or
  news objects from unspecified opaque bytes.
- **Close when:** Trace path encoders/resolvers and provide separate field
  grammars and root/nested/non-ASCII/invalid-component fixtures; prove any
  claimed equivalence.
- **Prior ledger entries:** V049, V050, V062
- **Investigation leads:**
  [1002b0e0](../mothra/evidence/hotline-server-1.9/queries/D-1002b0e0.c),
  [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c),
  [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** News structure paths share the resolver with explicit
  mode/type/root checks. Documented sanitizer transformations and long-name
  fallback, retaining platform and alias containment uncertainties. Native
  malformed-path, alias/root and name/collision fixtures remain required.
  Folder descriptors and field202 before-state queries now exercise
  root-relative/nested ASCII components with zero words and exact native
  paths. Invalid/non-ASCII/limit/normalization outcomes remain required; no
  universal grammar equivalence inferred. Native-mkdir-01 supplies
  root/nested/nonASCII/NUL/dot/dotdot/colon traversal,
  short/malformed/prefix/count/word/trailing202 controls with exact
  before/after locations. Short values can selectFiles root; invalidsuffixes
  can stop at validprefix. No field212/325 equivalence or alias containment is
  inferred, so those original requirements remain open.
  Native209absent/empty201 acceptscomplete202source and212destinationleaf;
  nonempty201keepsbasename. Alias202/210transfersresolvebothfile/folderchains.
  Broader212/325grammar andcontainment requirements remain active. A
  livealiasinsideFilescontinues206resolutionafteritstargetmovesoutsideFilesintoTrash;positivecatalogueidentifiesthetargetthere.
  Thisshowsboundedmetadatacontainmentbehaviour,notallpathgrammarsoroutside-share-downloadrules.
- **Evidence:** [Native folder
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json);
  [Folder state/clock
  contracts](transfer-contracts.md#captured-folder-timing-and-filesystem-observations);
  [Repeatable capture/snapshot
  workflow](native-capture-workflow.md#recorded-native-folder-fixtures);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Native alias and metadata
  matrix](filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix);
  [Alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json)
- **Closure:** Not closed: broader unchanged acceptance requirements remain as
  stated above.

### GAP-048

#### File-list record layout

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing Files in a Folder (Transaction 200) –
  Client
  Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates)
  (snapshot lines 748–760)
- **Question:** What are the exact field-200 offsets, metadata/tag meanings,
  size widths, entry kinds, sort order and empty-list representation?
- **Implementation impact:** A client cannot render or navigate file listings
  from the current field ID alone.
- **Close when:** Specify the nested record grammar and listing order with
  file/folder/alias/non-ASCII/empty/multiple-entry fixtures.
- **Prior ledger entries:** V049
- **Investigation leads:**
  [100100a0](../mothra/evidence/hotline-server-1.9/queries/D-100100a0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-047](#gap-047)
- **Progress:** Nativealias01 supplies exact listing grammar/order and
  target-kind/field-presence metadata evidence, including
  ordinaryfile/folder,livealiases/chains,cyclicunattachedalias,zero/unknown/emptyvalues
  andnonASCII/multiple/emptylistingcontrols.
  All44completedreportsplusinitialfailedEOF are
  independentlyreconciledacross66sockets.
  14freshoraclequeriesandpositivephysicalforksseparatealiasobjectsfromresolvedwiremetadata.
- **Evidence:** [Native listing grammar and
  order](native-wire-details.md#captured-listing-kinds-and-enumeration-order);
  [Captured metadata
  matrix](filesystem-and-board-contracts.md#file-info-presence-and-values);
  [Native alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-alias-and-metadata-fixtures);
  [Closure
  review18](../mothra/evidence/gap-remediation/2026-11-13/closure-review-18/review.json)
- **Closure:** Closed against unchanged
  nestedrecordgrammar/order/representativekindfixture
  ormetadatafield-presence/type/empty/unknown criterion.
  Noportablecomparator,allfiltermodes,genuinedeletedtarget
  orcompletepersistenceclaim.

### GAP-049

#### File-info variant matrix

- **Tracking:** P1; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Getting File/Folder Info (Transaction 206) –
  Client
  Initiates](protocol.md#getting-filefolder-info-transaction-206--client-initiates)
  (snapshot lines 837–854)
- **Question:** Which fields and widths occur for files, folders, aliases and
  special items, including descriptive 205/206, raw 213 and size/date
  omissions?
- **Implementation impact:** Removing the universal four-character assumption
  still leaves multiple incompatible response schemas.
- **Close when:** Publish a target-kind/field-presence/type matrix with
  representative metadata and empty/unknown-value cases.
- **Prior ledger entries:** V017, V054
- **Investigation leads:**
  [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c)
- **Depends on:** [GAP-020](#gap-020)
- **Progress:** Nativealias01 supplies exact listing grammar/order and
  target-kind/field-presence metadata evidence, including
  ordinaryfile/folder,livealiases/chains,cyclicunattachedalias,zero/unknown/emptyvalues
  andnonASCII/multiple/emptylistingcontrols.
  All44completedreportsplusinitialfailedEOF are
  independentlyreconciledacross66sockets.
  14freshoraclequeriesandpositivephysicalforksseparatealiasobjectsfromresolvedwiremetadata.
- **Evidence:** [Native listing grammar and
  order](native-wire-details.md#captured-listing-kinds-and-enumeration-order);
  [Captured metadata
  matrix](filesystem-and-board-contracts.md#file-info-presence-and-values);
  [Native alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-alias-and-metadata-fixtures);
  [Closure
  review18](../mothra/evidence/gap-remediation/2026-11-13/closure-review-18/review.json)
- **Closure:** Closed against unchanged
  nestedrecordgrammar/order/representativekindfixture
  ormetadatafield-presence/type/empty/unknown criterion.
  Noportablecomparator,allfiltermodes,genuinedeletedtarget
  orcompletepersistenceclaim.

### GAP-050

#### Delete semantics and failures

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Deleting a File (Transaction 204) – Client
  Initiates](protocol.md#deleting-a-file-transaction-204--client-initiates)
  (snapshot lines 804–818)
- **Question:** Can 204 remove nonempty folders, which errors apply to
  missing/root/protected targets, and what state/notifications follow a
  partial filesystem failure?
- **Implementation impact:** A successful ACK is not a complete
  destructive-operation contract.
- **Close when:** Trace deletion helpers and define permission, recursion,
  failure/atomicity and refresh outcomes with controlled fixtures.
- **Prior ledger entries:** V053
- **Investigation leads:**
  [100140e0](../mothra/evidence/hotline-server-1.9/queries/D-100140e0.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047)
- **Progress:** Traced delete helper to native Trash lookup and catalog move
  with collision handling; no recursive erase or automatic list refresh
  implied. Permission, conflict, protected-object and failure native fixtures
  remain required. Cleanup204 movesall44owned catalogue objects into
  nativeTrash. All36 pre-move subtree identities/paths and ordinarychild DATA
  survive; initialFileslisting is restored exactly. This proves a bounded
  positive nonrecursiveerase result, not
  conflict/permission/protected-object/failure coverage.
  Native-move01addsordinaryfile/nonemptyfolder,path-onlydirectory,missing-source,zero-privilegedenialsandtwoequalTrashbasenames.
  Sixsuccesses/threeerrorshavebefore/afterviewsandpositiveidentity/forkcontrols;Trashcollisionretainsm-del22-dupeandm-del22-dupe1.
  Protected/rootandforcedinterruptedfailurebranchesremainrequired;quietwindowsdonotproveallnotifications.
- **Evidence:** [Filesystem and board
  contracts](filesystem-and-board-contracts.md); [Source
  lineage](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits);
  [Portability procedure](evidence-portability.md); [Batch
  08](../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-051

#### Folder creation semantics

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Creating a New Folder (Transaction 205) – Client
  Initiates](protocol.md#creating-a-new-folder-transaction-205--client-initiates)
  (snapshot lines 819–836)
- **Question:** How are name/path defaults, existing names, invalid names,
  missing parents and per-folder privilege checks handled by 205?
- **Implementation impact:** An encoder can issue a valid TLV request but
  cannot predict creation or error outcomes.
- **Close when:** Document input conditions, conflicts, permission and
  success/error responses for 205 with exact fixtures.
- **Prior ledger entries:** V053, V050
- **Investigation leads:**
  [100143f0](../mothra/evidence/hotline-server-1.9/queries/D-100143f0.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047)
- **Progress:** Native205 now has47 creation/path fixtures plus sixroot/name
  absence-empty combinations: root/nested names, field presence,
  NUL/control/highbytes,31/32/255/256/65535 lengths and extension
  preservation, valid/missing/file parents, existing file/folder/case
  conflicts andzero-privilege denial. ExactACK/error text, before/after
  records, liveness and one-second quiet windows are checked.
  Ghidrahandler/normalizer/resolver/CreateDir paths have
  tenidentitycheckedqueries. Native204cleanup moves44owned objects toTrash
  andrestoresFiles listing; no account/config/restart/debugger change.
- **Evidence:** [Captured create inputs and
  outcomes](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Native directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-directory-creation-and-path-fixtures);
  [Closure
  review17](../mothra/evidence/gap-remediation/2026-11-13/closure-review-17/review.json)
- **Closure:** Closed against the unchanged205
  input/conflict/permission/success/error fixture criterion for the
  nativeOS9oracle. Field212/325equivalence, alias containment, broader name
  policies and204failure cases remain separate original requirements.

### GAP-052

#### Rename/comment partial updates

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Setting File/Folder Info (Transaction 207) –
  Client
  Initiates](protocol.md#setting-filefolder-info-transaction-207--client-initiates)
  (snapshot lines 855–873)
- **Question:** Do omitted/empty 210 and 211 preserve, clear or reject values,
  and what happens when one permitted sub-operation succeeds and another
  fails?
- **Implementation impact:** The guide allows both fields without defining
  partial success, atomicity or comment/rename permission combinations.
- **Close when:** Publish the field-presence/permission/conflict matrix and
  before/after outcomes for rename-only, comment-only and combined requests.
- **Prior ledger entries:** V053, V054
- **Investigation leads:**
  [100170c0](../mothra/evidence/hotline-server-1.9/queries/D-100170c0.c)
- **Depends on:** [GAP-016](#gap-016), [GAP-032](#gap-032),
  [GAP-047](#gap-047)
- **Progress:**
  Native207file/folderpresence,permissionandconflictmatrixsupplies36maincasesplussixcombined-emptycases,22boundarywritesandindependentadministratorfinalviews.
  Comment-firstpartialsuccesssurvivesrenamepermission/collisionerror;commentdenialpreventsrename.
  All49reports/72socketsarepairedverifiedwith13freshoraclequeriesand13newregressions.
  Initialaccountcleanupmistakeandcorrectedrecoveryremainexplicit.
- **Evidence:** [Captured presence/permission/conflict
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Native metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-rename-and-comment-fixtures);
  [Closure
  review19](../mothra/evidence/gap-remediation/2026-11-13/closure-review-19/review.json)
- **Closure:** Closed
  againstunchanged207field-presence/permission/conflict/before-aftercriterion.
  Measuredquietwindowsdonotprovealllaterrefreshes;noatomicrollback,universalcommentcapacityorrestartdurabilityclaim.

### GAP-053

#### Move collision and metadata behaviour

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Moving Files/Folders (Transaction 208) – Client
  Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates)
  (snapshot lines 874–886)
- **Question:** How do destination conflicts, aliases, cross-volume moves and
  interrupted filesystem operations affect 208 and its ACK/error result?
- **Implementation impact:** The operation name does not establish overwrite,
  rollback or metadata preservation rules.
- **Close when:** Document resolver and move outcomes, including
  same-location, collision and partial-failure fixtures; bound any
  platform-specific semantics.
- **Prior ledger entries:** V053, V050
- **Investigation leads:**
  [100177d0](../mothra/evidence/hotline-server-1.9/queries/D-100177d0.c)
- **Depends on:** [GAP-047](#gap-047)
- **Progress:** Traced move to same-volume check, destination-directory
  validation and FSpCatMove; no cross-volume copy/delete fallback or explicit
  overwrite policy. Same-place/conflict/metadata/failure native fixtures
  remain required. Native-move01adds26cases:12successesincludingtwo
  same-parentnoops,and14expectederrors. File/foldercollisionsdo
  notoverwrite;missingendpoints/zero-privilege/self/descendantattemptsleaveviewsunchanged.
  Rootdefaultsandaliassource/destinationresolve;all72seededcatalogueidentitiesandordinaryforksarepreservedbeforecleanup.
  ActualothervolumeandinterruptedI/O/partial-failureacceptanceremainunexecuted.
- **Evidence:** [Filesystem and board
  contracts](filesystem-and-board-contracts.md); [Source
  lineage](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits);
  [Portability procedure](evidence-portability.md); [Batch
  08](../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-054

#### Alias creation and resolution

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Creating an Alias (Shortcut) (Transaction 209) –
  Client
  Initiates](protocol.md#creating-an-alias-shortcut-transaction-209--client-initiates)
  (snapshot lines 887–900)
- **Question:** What alias object is created, how is its name chosen, and when
  do listing/info/download resolve its target rather than expose the alias
  itself?
- **Implementation impact:** Portable symlink assumptions can produce
  different list, metadata and transfer results.
- **Close when:** Trace alias creation/resolution and document
  source/destination/default-name rules with live, missing-target and
  alias-to-alias cases.
- **Prior ledger entries:** V053, V054
- **Investigation leads:**
  [10017c10](../mothra/evidence/hotline-server-1.9/queries/D-10017c10.c),
  [10016ba0](../mothra/evidence/hotline-server-1.9/queries/D-10016ba0.c),
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-049](#gap-049)
- **Progress:** Traced same-source-name alias target construction, native
  NewAlias/resource file/alis resource/Finder flags and partial-file cleanup.
  Alias-to-alias/missing-target/conflict/transfer fixtures remain required.
  Native-alias-01 verifies19creation cases, livefile/folder resolution,
  aliaschains, deriveddestinationnames, ignored211,
  missing/empty/zero212rootdefaults, ordinaryfilecollision success,
  existingdirectory/alias collisionerrors, selfcycleunattachedclassification
  andresolved202/210forks. Originalgenuinedeletedtarget criterion remains
  unmet; selfcycle andmissingsource do not satisfy it.
  Aliaswhoseoriginaltargetmoves
  toTrashremainslivein206,withtargetsize332/commentandpositiveoutside-sharetargetcatalogue.
  Resourcebyteschangebyfinalsnapshot;thisdoesnotprovideagenuinemissingtarget.
  Originalmissing-targetcriterionremainsactive.
- **Evidence:** [Filesystem and board
  contracts](filesystem-and-board-contracts.md); [Source
  lineage](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits);
  [Portability procedure](evidence-portability.md); [Batch
  08](../mothra/evidence/gap-remediation/2026-11-12/batch-08/manifest.json);
  [Native alias and metadata
  matrix](filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix);
  [Alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Transfer protocol

### GAP-055

#### Sixteen-byte HTXF header and reference matching

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974); [protocol.md — Banner Download (Transaction 212) – Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 937–954)
- **Question:** What are every offset/width, type value, reserved field and
  reference-matching rule, and how do unknown, expired or other-session
  references fail?
- **Implementation impact:** No interoperable transfer handshake can be
  encoded from the current partial description.
- **Close when:** Publish the complete header plus upload/download/banner
  matching and failure rules with valid/invalid reference and type fixtures.
- **Prior ledger entries:** V058, V059, V060
- **Investigation leads:**
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-009](#gap-009), [GAP-010](#gap-010),
  [GAP-033](#gap-033)
- **Progress:** Published complete16-byte header and parity/selector dispatch
  with static full-reference lookups. Retained valid ordinary/folder/banner
  streams, invalid/unknown/zero/aged references and wrong selectors. Added17
  HTXF cases plus preflight: arbitrary size/trailing words, split15+1, bad
  magic, ordinary-upload size replacement, concurrent low-privilege observer,
  owner-gone rejection, after-close reuse and bounded duplicate pointer
  replacement. Every new stream reconciles exactly across host and guest, with
  positive native upload forks.
- **Evidence:** [Captured HTXF header/reference
  contract](transfer-contracts.md#captured-htxf-field-and-reference-cases);
  [Native HTXF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-12/review.json);
  [Repeatable HTXF
  workflow](native-capture-workflow.md#reproducing-htxf-header-and-reference-fixtures)
- **Closure:** Resolved against the unchanged criterion. Full
  header/matching/failure rules have valid/invalid native fixtures.
  Alternate-listener wrapping, general identifier collision/lifetime,
  arbitrary source-IP admission, client interoperability and full-operation
  persistence remain separate unchanged requirements.

### GAP-056

#### Flattened file and fork stream

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974); [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 761–788); [protocol.md — Uploading a File (Transaction 203)
  – Client
  Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates)
  (snapshot lines 789–803)
- **Question:** What are stream headers, metadata/fork records, lengths,
  padding, order and termination for ordinary Mac files versus raw/preview
  transfers?
- **Implementation impact:** The control ACK does not specify actual file
  contents or preserve resource forks.
- **Close when:** Trace transfer workers and publish byte grammars plus
  data/resource-fork, empty-file and metadata round-trip fixtures.
- **Prior ledger entries:** V051, V052, V059
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-055](#gap-055)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured ordinary-file
  sequences](transfer-contracts.md#captured-ordinary-file-round-trips);
  [Completion and
  EOF](transfer-contracts.md#captured-completion-and-eof-behaviour); [Native
  fork
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/manifest.json);
  [Packet/fork/metadata
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-forks-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-06/review.json)
- **Closure:** Retained worker/serializer/restoration code plus byte grammar
  and two successfuluploads/eightrevieweddownloads demonstrate
  data/resourcefork bytes, emptyforks,
  INFOtype/creator/name/comment/flags/dateeffects. Read-only native HFS+ fork
  extraction independently matches nonempty bytes; empty resource-attribute
  absence is labelled and zeroMACR captured. Selected metadata roundtrips
  satisfy the criterion; interruption/restartdurability and
  broadermetadata/datecases remainGAP-020/064.

### GAP-057

#### Download and preview response conditions

- **Tracking:** P1; Ambiguous; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 761–788)
- **Question:** Which 204 values/defaults choose each mode, how are 108/207
  calculated and when are 107/116 omitted or mandatory?
- **Implementation impact:** A successful zero-size response or differing
  sizes cannot yet be interpreted consistently.
- **Close when:** Document mode and response-presence/size calculation tables
  with zero-size, preview, ordinary and queued fixtures.
- **Prior ledger entries:** V051
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c)
- **Depends on:** [GAP-055](#gap-055)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Controlled queue modes and
  ordering](transfer-contracts.md#captured-controlled-queues); [Bounded
  pending-reference
  timeout](transfer-contracts.md#captured-pending-reference-timeout); [Native
  queue
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/manifest.json);
  [Packet/mode/position
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-08/review.json)
- **Closure:** Traced request-202 branches and size helpers are paired with
  native mode/response tables and delivered bytes for absent/0/1/3/65535
  ordinary modes, numeric-2 preview, zero-size ordinary and empty-preview
  paths. Controlled queues retain four-byte references and advertised/logical
  sizes, add field 116 only when waiting, and deliver each expected FILP/raw
  stream after admission. Empty preview returns field 108 = zero without
  107/207/116 and allocates no queue entry. Resume calculations remain
  independently established by GAP-058.

### GAP-058

#### Resume-data format and offset negotiation

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Uploading a File (Transaction 203) – Client
  Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates)
  (snapshot lines 789–803); [protocol.md — Downloading a File (Transaction
  202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 761–788)
- **Question:** What is the nested field-203 grammar, which forks/offsets it
  covers, and how are mismatch, completed and missing partial files handled?
- **Implementation impact:** Neither upload nor download resume can be
  implemented from a field label and mode value.
- **Close when:** Trace both directions and publish offset/fork validation and
  continuation fixtures, including fresh/resumed/completed and inconsistent
  state.
- **Prior ledger entries:** V051, V052
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c)
- **Depends on:** [GAP-055](#gap-055), [GAP-056](#gap-056)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured RFLT download
  boundaries](transfer-contracts.md#captured-rflt-download-boundaries);
  [Captured upload
  continuation](transfer-contracts.md#captured-upload-continuation-and-inconsistent-state);
  [Native resume
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-resume-01/manifest.json);
  [Packet/fork
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-resume-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-07/review.json)
- **Closure:** Retained RFLT consumer/builder and upload handler/parser code,
  explicit byte grammar and validation limits, and 23 final native cases
  establish fresh, zero, inside, EOF, beyond-EOF and all-ones offsets;
  unknown/repeated fork entries; malformed magic/version/minimum-length
  no-reply windows; interrupted 13/5 partial state; negotiated offsets; exact
  continuation; missing/completed-file errors; and inconsistent-client
  appends. Paired host/guest packets and before/after HFS+ forks independently
  agree. Unchecked entry-count bounds are documented, not certified safe.
  Folder resume, disk-full, large-file and restart-durability requirements
  remain GAP-059/060/064.

### GAP-059

#### Folder-download stream state machine

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading an Entire Folder (Transaction 210) –
  Client
  Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates)
  (snapshot lines 901–918)
- **Question:** What are entry/path records, actions, traversal order,
  aggregate counts/sizes, skips and resume transitions for 210?
- **Implementation impact:** The known initiation fields do not describe a
  recursive transfer implementation.
- **Close when:** Provide a direction-specific state machine and complete
  small nested-folder stream fixtures, including empty, skipped and resumed
  entries.
- **Prior ledger entries:** V055, V057
- **Investigation leads:**
  [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-055](#gap-055),
  [GAP-056](#gap-056)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured
  downloads](transfer-contracts.md#captured-folder-downloads); [Captured
  uploads](transfer-contracts.md#captured-folder-uploads); [Timing and
  filesystem
  observations](transfer-contracts.md#captured-folder-timing-and-filesystem-observations);
  [Native folder
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json);
  [Direction/state/fork
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-10/review.json)
- **Closure:** Retained traversal/worker code and direction-specific native
  streams establish five root-excluded descendants, HFS+ fixture order,
  aggregate 652 versus 1,148 fresh FILP bytes, empty/directory-only outcomes
  and exact full/skip/resume/mixed transitions. Control 0 preserves the
  recorded states through three-second windows. A delayed file choice remains
  usable after 130 seconds of measured pauses and completes the full stream.
  Exact host/guest reconciliation and positive native catalogue/fork
  observations support the fixtures. The unchanged criterion is met; arbitrary
  path/descriptor validation, mixed-folder queues and broader timing/failure
  guarantees remain unclaimed.

### GAP-060

#### Folder-upload stream state machine

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Uploading an Entire Folder (Transaction 213) –
  Client
  Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates)
  (snapshot lines 919–936)
- **Question:** How are directories/files framed, acknowledged, counted,
  resumed or rolled back in 213, and how do empty transfers complete?
- **Implementation impact:** Assuming the inverse of download would invent
  unverified control and persistence semantics.
- **Close when:** Provide the upload-specific state machine with nested,
  empty, partial and resumed transfer fixtures, including metadata and
  conflict handling.
- **Prior ledger entries:** V056, V057
- **Investigation leads:**
  [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c)
- **Depends on:** [GAP-047](#gap-047), [GAP-055](#gap-055),
  [GAP-056](#gap-056)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Captured
  downloads](transfer-contracts.md#captured-folder-downloads); [Captured
  uploads](transfer-contracts.md#captured-folder-uploads); [Timing and
  filesystem
  observations](transfer-contracts.md#captured-folder-timing-and-filesystem-observations);
  [Native folder
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/manifest.json);
  [Direction/state/fork
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-folder-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-10/review.json)
- **Closure:** Retained request-213/upload-worker code and native nested,
  zero-item, directory-final, interrupted, resumed, completed-skip and
  directory/file conflict cases establish the upload state machine, item
  counting and selected metadata effects. Before/after direct HFS+ forks show
  completed alpha retained, partial DATA 13 / MACR 5 under HTft/HTLC, then
  correct 13/317 under TEXT/MOTH after RFLT continuation. Final directory/skip
  sends control 3 before EOF; final file does not. Late attachment after 125
  seconds closes without readiness; descriptor-only progress does not reset a
  full interval, with close 35.018523 host seconds after the directory reply.
  These meet the unchanged criterion. Malformed-path/descriptor, overshoot,
  large-size and durable failure requirements remain GAP-047/064; no
  safe-parser or exact-deadline claim.

### GAP-061

#### Queue notification 211 and scheduling

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Downloading a File (Transaction 202) – Client
  Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates)
  (snapshot lines 761–788); [protocol.md — Downloading an Entire Folder
  (Transaction 210) – Client
  Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates)
  (snapshot lines 901–918); [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  733–747)
- **Question:** What fields/type/ordering does 211 use, how do queue positions
  and slots change, and when should the client connect, wait or retry?
- **Implementation impact:** Queued transfers cannot make reliable progress
  using only an initial waiting-count field.
- **Close when:** Trace queue workers and capture admission, advancement,
  notification, timeout and fairness/order behaviour under a small controlled
  queue.
- **Prior ledger entries:** V051, V055, V060
- **Investigation leads:**
  [100121a0](../mothra/evidence/hotline-server-1.9/queries/D-100121a0.c),
  [10012850](../mothra/evidence/hotline-server-1.9/queries/D-10012850.c)
- **Depends on:** [GAP-055](#gap-055)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Controlled queue modes and
  ordering](transfer-contracts.md#captured-controlled-queues); [Bounded
  pending-reference
  timeout](transfer-contracts.md#captured-pending-reference-timeout); [Native
  queue
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/manifest.json);
  [Packet/mode/position
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-queue-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-08/review.json)
- **Closure:** Retained queue-worker code and four controlled native cases at
  saved limits of two globally and one per session establish initial
  positions, 211/zero admission, position advancement, finite
  unchanged-position silence, owner eligibility and early attached
  connections. Later eligible owner B advances before owner A waiters blocked
  by their own cap; no universal FIFO claim is made. Twelve measured 45-second
  pauses precede old-reference rejection and successful waiter delivery. The
  complete 211/zero frame is observed 542.973851 host seconds after the first
  ACK; this does not locate internal expiry/admission or establish an exact
  500-second deadline. Universal starvation bounds and mixed-folder operation
  details remain unclaimed.

### GAP-062

#### Reference cleanup 214 semantics

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974)
- **Question:** Does 214 cancel queued/active/completed transfers, who owns
  the reference, and how are zero, unknown, duplicate or racing requests
  acknowledged?
- **Implementation impact:** A provisional cancellation label does not specify
  safe client retry or resource lifecycle behaviour.
- **Close when:** Trace the cleanup helper and publish reference-state/outcome
  tables and cancellation/completion race fixtures.
- **Prior ledger entries:** V061
- **Investigation leads:**
  [10013040](../mothra/evidence/hotline-server-1.9/queries/D-10013040.c)
- **Depends on:** [GAP-033](#gap-033), [GAP-055](#gap-055),
  [GAP-061](#gap-061)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Reference-state/outcome
  table](transfer-contracts.md#reference-allocation-and-request-214);
  [Cancellation/completion
  races](transfer-contracts.md#captured-cancellation-and-completion-races);
  [Buffer and packet
  ordering](transfer-contracts.md#buffered-receipt-and-packet-ordering);
  [Native cleanup
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-cleanup-01/manifest.json);
  [Packet/prefix/native-file
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-cleanup-01/verification.json);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-09/review.json)
- **Closure:** Retained handler 10013040 and cleanup-helper 1000e760 code, a
  reference-state/outcome table, the earlier
  queued/pending/absent/zero/unknown/nonowner cases and ten new native cases
  satisfy the unchanged criterion. A complete multi-chunk baseline, three
  immediate and three partial-read cancellations establish exact delivered
  prefixes and observed incoming-request/data overlap. Packet timing is
  separated from buffered application reads after ACK. Nonowner cleanup allows
  continued full delivery; owner/duplicate cleanup ACKs and removed-reference
  rejection are verified. A pending upload survives 214, consistent with the
  helper collection search. Native HFS+ DATA/MACR bytes match seeds after all
  cases. Finite races do not establish universal delivery counts, deadlines,
  rollback or folder/banner stream conformance.

### GAP-063

#### Banner data stream and absence

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Banner Download (Transaction 212) – Client
  Initiates](protocol.md#banner-download-transaction-212--client-initiates)
  (snapshot lines 937–954); [protocol.md — Banner Metadata (Transaction 122) –
  Server
  Initiates](protocol.md#banner-metadata-transaction-122--server-initiates)
  (snapshot lines 416–430)
- **Question:** Is banner content raw or flattened, what exact bytes/size are
  transferred, and what happens if a configured banner changes or disappears
  after metadata delivery?
- **Implementation impact:** Metadata type and an HTXF branch are insufficient
  to fetch a displayable banner reliably.
- **Close when:** Specify the banner stream, reference/size lifetime and
  missing/changed-banner errors for supported metadata types.
- **Prior ledger entries:** V025, V058, V059
- **Investigation leads:**
  [10012f40](../mothra/evidence/hotline-server-1.9/queries/D-10012f40.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c)
- **Depends on:** [GAP-028](#gap-028), [GAP-055](#gap-055)
- **Progress:** Retained GIF/URL controls plus eight native format/empty
  cases, phase-checked absent/restored recovery, current-buffer replacement,
  pending-reference expiry, null/zero allocation traces and concurrent reset
  observations. Published raw versus TEXT-normalized bytes, reference size
  lifetime and missing/changed/empty outcomes, with reproducible assets,
  plans, native fork observations and exact paired final streams. Native
  client rendering, general reset policy and other-reference ownership remain
  separate requirements. Both completion paths now have accepted recovery
  cases: the delayed owner receives122 before212, Remote-empty removes its
  loaded image, and the old connection delivers58 restored bytes; the early
  control uses a failed file load. Nine additional setup observations preserve
  rejected GUI phases rather than certifying their runner completion.
- **Evidence:** [Banner stream/type/recovery
  contract](transfer-contracts.md#captured-banner-formats-and-recovery);
  [First banner
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-01/manifest.json);
  [Format/recovery
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json);
  [Unchanged-criterion closure
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-11/review.json)
- **Closure:** Resolved against the unchanged criterion: raw and normalized
  streams, size/reference lifetime, missing/replaced/restored buffers and
  present-empty failure are specified for the supported metadata types.
  Observations retain their timing and implementation limits; no general
  client-rendering or reset-threshold claim is made.

### GAP-064

#### Transfer completion, failure and persistence

- **Tracking:** P1; Missing; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — File Services (Files and
  Folders)](protocol.md#file-services-files-and-folders) (snapshot lines
  733–747); [protocol.md — Transfer Connection and Reference
  Cleanup](protocol.md#transfer-connection-and-reference-cleanup) (snapshot
  lines 955–974); [protocol.md — Uploading an Entire Folder (Transaction 213)
  – Client
  Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates)
  (snapshot lines 919–936)
- **Question:** Which byte counts or markers prove completion, and what
  survives EOF, timeout, reconnect, disk-full, oversized files or an
  interrupted upload?
- **Implementation impact:** A transfer can appear complete while lacking data
  or leave incompatible resumable state after failure.
- **Close when:** Define completion and interruption outcomes per direction,
  including large-size representation and partial-file retention, with
  controlled failure fixtures.
- **Prior ledger entries:** V051, V052, V057, V059, V061
- **Investigation leads:**
  [1000bd20](../mothra/evidence/hotline-server-1.9/queries/D-1000bd20.c),
  [100130f0](../mothra/evidence/hotline-server-1.9/queries/D-100130f0.c),
  [10013930](../mothra/evidence/hotline-server-1.9/queries/D-10013930.c)
- **Depends on:** [GAP-055](#gap-055), [GAP-056](#gap-056)
- **Progress:** Added age-check-before-drain and late-first-attachment derived
  upload case, retaining separate500-second pending versus120-second connected
  comparisons. Native completion/interruption/durability fixtures remain
  required. Uploads receive nativeEOF after advertised consumption without
  extraACK. Downloads deliver advertised count and remainopen
  through3secondquiet; initial30secondEOF timeouts preserved. LiveHFS+
  selectedfork/metadata observations are not restartdurability.
  Interruption/diskfull/large-size/partialretention remain required.
  Interrupted197of509byte upload retains13DATA/5MACR underHTft/HTLC;
  successfulcontinuation restores13/317. Inconsistent fullfork replay
  appends26/322 and finalizesTEXT/MOTH. Paired nativeforkreadback/extractions
  establish observed state, not restartdurability. Unsignedmax resume
  advertises180 but closes datawithoutbytes.
  Diskfull/large-size/reconnect/otherinterruption requirements remain open.
  Ten new cleanup cases retain a1MiB DATA baseline, native fork extractions
  and exact cancellation prefixes. Buffered application reads can follow
  ownerACK even though native DATA/close precede thatACK in these six races;
  no rollback is inferred. Pending upload survives214. Larger-than32bit
  representation, diskfull, restartdurability and remaining interruption
  states remain required. Folder count-three interruption retains a complete
  first file and partial second file; resumed continuation restores selected
  forks. Zero counts create a root withouttransferref; directory/file
  conflicts can share control3/EOF wire result. Late and descriptor-delay
  upload closes and long connected download choice are bounded observations.
  Unsafe/tiny/truncated descriptors, invalid paths, byte-count overshoot,
  diskfull/large-size/restartdurability remain unclosed. Present empty-banner
  attachment triggers a service reset in the retained fixture; ordinary
  upload/download/folder interruption, large sizes, disk-full and persistence
  remain separate unchanged requirements. An initial post-reset500 host write
  is explicitly not guest-consumed. Added three exact native uploadDATA
  controls, including ordinary HTXF byte count37 below request203
  advertisement. Positive live forks establish storage at observation, not
  restart durability or general size/failure handling. Failed 1 MiB seed
  records host 193,913 and guest 74,295-byte prefixes of a 1,049,088-byte
  local send, host proxy-server RST and guest client-to-server RST, then
  positively identified Incomplete File metadata. One guarded 204 restored all
  41 file records and two accounts. This establishes an interrupted
  artifact/cleanup example, not rejection of a fully received 1 MiB upload or
  a native-server-initiated reset. Latest A8 phase 1: An existing verified
  file supplied a 65,536-byte flattened-stream cancellation witness with exact
  recorder/host/guest bytes and no unread payload tail in this case. Guest RST
  payload No TCP is excluded from application data; host FIN and guest RST
  views remain distinct. This is partial-transfer cancellation and live
  restoration, not a successful full transfer or restart-persistence proof.
  Revision60: second disposable lab failed the mandatory full A7 download
  after 98,304 of 1,049,073 bytes, before any option-two request.
  Guest/namespace/recorder prefixes match; all observed payload was ACKed with
  positive receive windows. Producer stall cause remains unknown; this is a
  retained failure, not ban acceptance. Revision61: Frozen worker/helper
  queries establish the inspected OpenTransport pending-send count, OTSnd
  queue and callback conditions. The alternate mode, scheduler and historical
  98,304-byte stall cause remain unproved. Revision62: the third disposable
  lab also failed its mandatory 29-action A7 at the same 98,304-byte prefix,
  before any account seed or option-two request. Independent reassembly
  confirms C32 completed 1,049,073 bytes in both views; C35/C45 stopped at the
  identical prefix. Recorded source images, binaries and preferences match,
  but live worker/GUI state is missing and the cause remains unknown.
  Revision63: one delivered focus event did not resume the exact dual
  98,304-byte prefix, and the stock full A7 failed. This falsifies that one
  event-resume claim only; no account or ban request ran.
- **Evidence:** [Native format/recovery/reset
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json);
  [Banner type/recovery
  contract](transfer-contracts.md#captured-banner-formats-and-recovery);
  [Repeatable format/recovery
  workflow](native-capture-workflow.md#reproducing-banner-format-and-recovery-fixtures);
  [Native HTXF header/reference
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json);
  [Second delegated investigation](diagnostic-transfer-boundaries.md); [Active
  and queued native diagnostic](native-diagnostic-existing-witness.md);
  [Failed disposable-lab baseline and packet
  replay](native-transfer-stall.md); [Native documentation
  evidence](native-download-send-path.md); [Repeated baseline failure and
  successful
  control](native-transfer-stall.md#repeated-baseline-and-a-successful-comparison);
  [Verified focus-event negative](native-ui-focus-witness.md)
- **Closure:** Not closed: broader unchanged acceptance requirements remain as
  stated above.

## News

### GAP-065

#### Category records and version threshold

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing News Categories (Transaction 370) –
  Client
  Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates)
  (snapshot lines 986–1003); [protocol.md — News
  Hierarchy](protocol.md#news-hierarchy) (snapshot lines 977–985)
- **Question:** What are nested 320/323 record layouts and kind/count fields,
  and what peers actually send version values around literal threshold 15?
- **Implementation impact:** A known top-level field switch does not permit
  decoding or justify a displayed-version mapping.
- **Close when:** Provide both record grammars with boundary-version and mixed
  folder/category fixtures; identify peer evidence separately.
- **Prior ledger entries:** V062, M002
- **Investigation leads:**
  [10005710](../mothra/evidence/hotline-server-1.9/queries/D-10005710.c),
  [100102c0](../mothra/evidence/hotline-server-1.9/queries/D-100102c0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-047](#gap-047)
- **Progress:**
  Native-news01providescontrolled107versionboundary0/1/14/15/16/149/150/190/ffffandmixedfolder/category370fixtures;exact320/323grammars,nonzeroopaquetailsandHLNZheader/countcopiesareverified.
  Empty/multiple/threaded321,rawword/date/parent/flavourfields,65535bodylengthand395/10/73bytestoredcachesarecheckedacross43reports/45pairedsocketsand29freshqueries.
  Identifiedshx0.1.48omits160;controlledboundarycasesarenotattributedtoahistoricalrelease.
  A separate native child-boundary corpus positively demonstrates category aux
  count103 while cached article-list count is102; parsers must respect each
  independently framed grammar. Existing category grammar closure unchanged.
- **Evidence:** [Captured category versions and
  metadata](news-contracts.md#captured-category-versions-and-header-metadata);
  [Captured threaded
  lists](news-contracts.md#captured-threaded-article-lists-and-partial-posts);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-category-and-threaded-news-fixtures);
  [Separate actual peer
  evidence](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Closure
  review20](../mothra/evidence/gap-remediation/2026-11-13/closure-review-20/review.json);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary)
- **Closure:**
  Closedagainstunchanged065grammar/version/mixedfixture/separatepeer-evidenceor066serializer/empty-multiple-threadedcriterion.
  No15-to-human-release
  mapping,identifiedmodernhistoricalpeer,allnavigation/flavour/siblinglimits,recursivearticledeletion,interruptedstorageorrestartdurabilityclaim.

### GAP-066

#### Serialized article-list format

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Listing News Articles (Transaction 371) – Client
  Initiates](protocol.md#listing-news-articles-transaction-371--client-initiates)
  (snapshot lines 1004–1018)
- **Question:** What are field-321 headers, article records, counts, flags,
  dates, flavour records, ordering and size limits?
- **Implementation impact:** The correction to one containing field still
  leaves the article list impossible to decode.
- **Close when:** Trace the serializer and document nested offsets,
  cardinalities and empty/multiple/threaded article-list fixtures.
- **Prior ledger entries:** V063
- **Investigation leads:**
  [100059e0](../mothra/evidence/hotline-server-1.9/queries/D-100059e0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-020](#gap-020)
- **Progress:**
  Native-news01providescontrolled107versionboundary0/1/14/15/16/149/150/190/ffffandmixedfolder/category370fixtures;exact320/323grammars,nonzeroopaquetailsandHLNZheader/countcopiesareverified.
  Empty/multiple/threaded321,rawword/date/parent/flavourfields,65535bodylengthand395/10/73bytestoredcachesarecheckedacross43reports/45pairedsocketsand29freshqueries.
  Identifiedshx0.1.48omits160;controlledboundarycasesarenotattributedtoahistoricalrelease.
  Serialized traversal follows the mutated sibling chain and bypasses indexed
  ID102 after child append102. Its count102 and exact6229-byte cache differ
  from header/index count103; original serializer criterion remains closed
  without claiming index completeness.
- **Evidence:** [Captured category versions and
  metadata](news-contracts.md#captured-category-versions-and-header-metadata);
  [Captured threaded
  lists](news-contracts.md#captured-threaded-article-lists-and-partial-posts);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#reproducing-category-and-threaded-news-fixtures);
  [Separate actual peer
  evidence](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Closure
  review20](../mothra/evidence/gap-remediation/2026-11-13/closure-review-20/review.json);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary)
- **Closure:**
  Closedagainstunchanged065grammar/version/mixedfixture/separatepeer-evidenceor066serializer/empty-multiple-threadedcriterion.
  No15-to-human-release
  mapping,identifiedmodernhistoricalpeer,allnavigation/flavour/siblinglimits,recursivearticledeletion,interruptedstorageorrestartdurabilityclaim.

### GAP-067

#### Article navigation, flavour and date semantics

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Reading a News Article (Transaction 400) –
  Client
  Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates)
  (snapshot lines 1019–1047)
- **Question:** What precisely do 331/332/335/336 identify, what are
  sentinel/end conditions, which flavours work and how is 330 constructed?
- **Implementation impact:** A client cannot traverse threads or interpret all
  article data from field names alone.
- **Close when:** Document navigation graphs, flavour selection/errors and
  news-date conversion using branching-thread, absent-body and boundary
  fixtures.
- **Prior ledger entries:** V064, V017
- **Investigation leads:**
  [10005ac0](../mothra/evidence/hotline-server-1.9/queries/D-10005ac0.c),
  [10011580](../mothra/evidence/hotline-server-1.9/queries/D-10011580.c)
- **Depends on:** [GAP-020](#gap-020), [GAP-066](#gap-066)
- **Progress:** Assembly identifies331/332 as previous/next sibling IDs,335
  parent,336 firstchild, with zero for absent links. Append search reads at
  most100 links; native navigation and boundary fixtures remain required.
  Native-news01addsbranchingparent/sibling/firstchildbodygraph,case-sensitiveflavourfailures,unknownIDandzero-flavourerrors,exact65535bodyanddatecopycontrols.
  Broader100sibling/30flavour/dateboundaryandothernavigationcriteriaremainactive.
  Twenty-five independent article trees verify before/after sibling, parent
  and first-child graphs, surviving dates/bodies/flavours and removed-ID
  errors. Broader date/flavour/navigation boundaries remain active.
  Native99/100/101/102-child fixtures establish the 100-link helper
  consequence: public ID102 is bypassed when103 is attached after101. Six
  direct body graphs and all103 physical/indexed records preserve the
  asymmetric links. Date conversion/rollover and flavour-chain boundaries
  remain required.
- **Evidence:** [Article
  navigation](news-contracts.md#reading-bodies-and-navigation); [Deletion
  rewrite](news-contracts.md#deletion-graph-rewrite); [INFO
  restoration](transfer-contracts.md#info-restoration-after-upload); [Captured
  native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-068

#### Posting and new-article discovery

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Posting a News Article (Transaction 410) –
  Client
  Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates)
  (snapshot lines 1048–1069)
- **Question:** How do omitted/zero 326, flags 334, supported flavours and
  body limits affect creation, and how is the resulting ID or update
  discovered after ACK?
- **Implementation impact:** Posting can succeed without any specified way to
  locate the new article or distinguish parent relationships.
- **Close when:** Publish post field/default and flag tables plus
  discovery/notification/persistence behaviour for new threads, replies and
  invalid requests.
- **Prior ledger entries:** V064, V065, V066
- **Investigation leads:**
  [10010470](../mothra/evidence/hotline-server-1.9/queries/D-10010470.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-067](#gap-067)
- **Progress:** Confirmed create parent/root insertion and raw334 storage;
  success remains empty ACK after metadata-first mutation. Child-tail search
  capped100 links warrants boundary testing. Native limits/discovery/failure
  fixtures remain required.
  Native-news01showsnewrootandreplycreationwithrawflags11223344,emptyACKsandpoll-discoveredIDs.
  Missingbodyerrorleaveszero-flavourID3andcount3beforelaterbranches.
  Onequietsecondisnotallpush/discovery/persistenceevidence;flagmeaningandotherpartialfailuresremainrequired.
  Interrupted seed is inventoried and resumed only from verified
  ID/title/parent prefixes. Broader post flags, discovery and partial failure
  requirements remain active. Paced new-child posts all ACK successfully
  through102, but polling no longer exposes every allocated ID: ID102 remains
  directly readable and indexed while371 omits it. Native count/index/cache
  mismatch is retained. Broader post defaults/flags, discovery peers,
  persistence and invalid requests remain active.
- **Evidence:** [Article
  navigation](news-contracts.md#reading-bodies-and-navigation); [Deletion
  rewrite](news-contracts.md#deletion-graph-rewrite); [INFO
  restoration](transfer-contracts.md#info-restoration-after-upload); [Captured
  native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-069

#### Recursive article deletion

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Deleting a News Article (Transaction 411) –
  Client
  Initiates](protocol.md#deleting-a-news-article-transaction-411--client-initiates)
  (snapshot lines 1070–1086)
- **Question:** What values/widths does 337 accept, and how are descendants,
  orphans, navigation IDs and notifications updated on success or partial
  failure?
- **Implementation impact:** The guide intentionally removed guessed deletion
  semantics but provides no replacement contract.
- **Close when:** Trace deletion/index helpers and document
  nonrecursive/recursive outcomes with parent, leaf and failure fixtures.
- **Prior ledger entries:** V065, V066
- **Investigation leads:**
  [100108a0](../mothra/evidence/hotline-server-1.9/queries/D-100108a0.c)
- **Depends on:** [GAP-067](#gap-067)
- **Progress:** Native parent/internal/leaf/root endpoint fixtures establish
  recursive descendant removal and nonrecursive first-child promotion with
  reparenting. Fourteen 337 controls, missing/omitted/repeated ID, absent
  category and zero-privilege failures are verified, including exact
  before/after body links, surviving dates/bodies, unchanged rejected lists
  and native HLNZ counts/caches. All 58 reports and 60 paired connections
  retain both failed initial attempts and separate managed recovery
  provenance.
- **Evidence:** [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Closure review
  21](../mothra/evidence/gap-remediation/2026-11-13/closure-review-21/review.json)
- **Closure:** Closed against the unchanged deletion/index-helper and
  parent/leaf/failure-fixture criterion. No forced interrupted-storage
  atomicity, restart durability, natural ban expiry or historical-client
  claim; cross-cutting and other news requirements remain active.

### GAP-070

#### News hierarchy and structure mutations

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — News Hierarchy](protocol.md#news-hierarchy)
  (snapshot lines 977–985); [protocol.md — Managing News Structure
  (Transactions 380, 381, 382) – Client Initiates
  (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods)
  (snapshot lines 1087–1103)
- **Question:** What nesting/type/depth rules apply, how are paths and name
  fields interpreted, and what happens on create/delete conflicts or subtree
  failures?
- **Implementation impact:** A fixed four-tier assumption was withdrawn
  without a validated structural model for mxd.
- **Close when:** Publish object/path grammars and 380/381/382
  permission/conflict/recursive-effect tables with nested and failure
  fixtures.
- **Prior ledger entries:** V050, V065, V066
- **Investigation leads:**
  [10010b70](../mothra/evidence/hotline-server-1.9/queries/D-10010b70.c),
  [10010ee0](../mothra/evidence/hotline-server-1.9/queries/D-10010ee0.c),
  [10011110](../mothra/evidence/hotline-server-1.9/queries/D-10011110.c)
- **Depends on:** [GAP-032](#gap-032), [GAP-047](#gap-047),
  [GAP-065](#gap-065)
- **Progress:** Published380/381/382 field, permission, root/conflict and
  normal-effect table. Deletion moves to native Trash; category creation
  writes HLNZv2. Resolver alias kinds are outside explicit2/3 permission
  branches; no blanket alias guarantee is inferred.
  Nested/alias/conflict/partial-write native fixtures remain required.
  Nested381/382ownedhierarchyand14conflict/missing/wrong-parent/zero-privilege/root-protectionerrorsarecaptured.
  380cleanupmoveswholeownedsubtreewithpositivecatalogue/forkcontrolsafterindependentuploadflush.
  Alias/rootvariantsandinterrupted/partialcategorywriteacceptanceremainactive.
  Owned cleanup positively publishes all 27 original objects in Trash with
  preserved catalogue IDs, paths and forks/caches. Alias and interrupted
  hierarchy writes remain unproved.
- **Evidence:** [Structure
  effects](news-contracts.md#structure-operation-effects-and-conflicts);
  [Internal errors](error-outcomes.md#internal-exceptions-and-text-resources);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Administration

### GAP-071

#### Account field 111

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** What is field 111's wire type, presence/default rule, stored
  meaning and effect on 350/353?
- **Implementation impact:** The documented account schema explicitly contains
  a field mxd cannot yet interpret or preserve correctly.
- **Close when:** Trace reads/storage/use of 111 and add an account field
  schema with absent, empty and representative-value fixtures.
- **Prior ledger entries:** V069
- **Investigation leads:**
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Account111 remains stored opaque data, absent from
  inspected352/348 outputs. Inspected UI range was ban editing, and pinned shx
  account constants do not name111. No human label or no-use-anywhere claim is
  inferred; native representative fixtures remain required. Captured
  absent/empty/value111 updates with native734-byte UserData: lengths0/0/8 and
  opaque-c content;352 omits111 in all three. Human meaning and later
  reads/use remain unresolved. Native account-update 01 stores 65-byte 111 as
  length 64 with exact 64 X bytes, and sparse 353 clears its length/content.
  All 352 outputs still omit 111. Full stored-record evidence advances
  width/default rules but does not identify human meaning or all later
  consumers. Attribute-only live update with password NUL sentinel leaves
  effective identity/access unchanged and emits no extra 354/301 during
  measured windows. This is a bounded propagation result, not an
  account-attribute meaning or no-consumer-anywhere claim. Batch field 111 is
  copied and default-cleared; opaque bytes alone do not establish its meaning.
  Reader100073c0 has ten traced direct callers; local administrator password
  path10007780 preserves the whole734-byte record without a direct field111
  dereference. Stored slot boundaries and prior native controls are linked.
  Human meaning and indirect/resource consumers remain unresolved. Revision61:
  A separate hashed Classic client trace proves that 350/353 append
  105/106/102/110 and 349 builds nested fields 101/105/106/102/110. The
  inspected constructors omit 111 and immediate 0x6f candidates are error
  codes; no whole-client absence or semantic meaning is inferred. Revision68
  independent consumer audit traces full-record reading and local
  administrator password-update rewriting, which preserves opaque111 bytes.
  This is a whole-record preservation consumer, not a field-specific semantic
  read; stored meaning remains unresolved. Revision73 fresh independent
  Classicclient import preserves exact7f286e/PPCBE32/3564 identity. Three
  defined-string queries find CMyAdminEditUserWin at1014fef8 but no defined
  privilege labels. Negative listing is not absence from loadedmemory; no
  label-to-bit map or field111meaning is inferred. CompressedPEF fileoffsets
  cannot be treated as loadedaddresses.
- **Evidence:** [Native core
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#recorded-native-core-fixtures);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Second delegated investigation](account-attribute-trace.md); [Native
  documentation evidence](classic-account-constructors.md); [Field111 consumer
  audit](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-04/a53-account111-consumer-audit.md.txt);
  [Classic privilege discovery bounds](classic-privilege-discovery.md)
- **Closure:** Not closed: remaining unchanged acceptance requirements are
  explicitly retained above.

### GAP-072

#### Account update, placeholder and identity rules

- **Tracking:** P1; Unanswered; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153)
- **Question:** How are target login, rename, absent/empty password, literal
  x, duplicate names, protected-account deletion and partial updates handled?
- **Implementation impact:** Treating the 352 placeholder as an
  unchanged-password token could overwrite credentials or target the wrong
  account.
- **Close when:** Define 350-353 mutation/default/atomicity rules with
  existing-password preservation, literal-x, rename/conflict and
  protected-delete fixtures.
- **Prior ledger entries:** V067, V068, V069, V070
- **Investigation leads:**
  [100146f0](../mothra/evidence/hotline-server-1.9/queries/D-100146f0.c),
  [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c),
  [10014bc0](../mothra/evidence/hotline-server-1.9/queries/D-10014bc0.c),
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c)
- **Depends on:** [GAP-016](#gap-016), [GAP-022](#gap-022),
  [GAP-071](#gap-071)
- **Progress:** Documented350 create grant subset check with bit27
  exemption,353 update bit17 without the equivalent handler subset
  comparison,352/348 read bit16 and351 delete bit15. Delete helper moves
  account file to Trash; protected/self/conflict/persistence native fixtures
  remain required. Captured create/change, wrong/complement/plaintext password
  controls and352 asymmetry: request lookup uses uncomplemented105,
  unlike350/351/353; reply105 is complemented. Sentinel, sparse/default,
  collision, rename and live-session boundary cases remain. Eight
  replacement/default/sentinel/width cases, nine positive and eight negative
  logins, exact 352 placeholder/omission rules and complete native records are
  verified across 31 reports/34 pairedconnections. Enumeration and Files
  baselines restored. Rename/conflict, protected/self deletion and forced
  storage failures remain required. Owned account replacement and deletion
  persist across a normal native server application restart, with unchanged
  application/Prefs identities and full stored records.
  Protected/self-deletion, rename/conflict and forced write failures remain
  required. Successful rename preserves catalogue identity. Distinct-password
  collision leaves source intact but overwrites destination with source
  credentials, then continues later creation despite final error.
  Protected/self-delete and remaining forced storage failures remain active.
  Exact/ASCII-case duplicate 350 preserve original account/password; 352
  echoes complemented lookup spelling. Owned bit-23 account deletion and
  bit-15/23 self-deletion succeed despite prior kick denial; account read and
  reconnect then fail. Original admin/fixture-low and Files enumeration
  restored. Built-in identities and forced storage/atomicity failures remain
  untested; no native Trash-fork claim. Revision71 stoppedHFS evidence
  corroborates351 movingownedfolders/UserData intoallocatedTrash;
  native352missingand348originaltwo proveactiveaccountremoval,
  notphysicalerasure. Originalnamedforks unchanged
  afterappQuit/forcedemulatorretirement. This isnot a353failed-writeratomicity
  fixture or allstorage guarantee. Revision72 independent Ghidra writer trace
  confirms353opensUserData, separatelySetEOF734, onePBWriteSync734 andclose
  beforeACK/liveupdate. OSerror invokesSError; actualwritecount
  returnedbylowlevelhelper isignoredbywriter. No localrollback/temp/swap
  appearsindirectchain, butouterrecovery/failed-writebytes/OScrashatomicity
  remainunmeasured. FinderLockedmayrejectbeforewrite,
  whichwouldnotprovewrite-phaseatomicity.
- **Evidence:** [Native core
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json);
  [Repeatable
  workflow](native-capture-workflow.md#recorded-native-core-fixtures);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Allocated Trash records after account
  deletion](operation-contracts.md#account-deletion-and-allocated-trash-records);
  [Direct account write ordering and limits](account-write-ordering.md)
- **Closure:** Not closed: remaining unchanged acceptance requirements are
  explicitly retained above.

### GAP-073

#### Account changes and active sessions

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — User Account Management – Client Initiates
  (Admin) (Tx
  350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353)
  (snapshot lines 1106–1153); [protocol.md — User Access Privileges
  (Transaction 354) – Server
  Initiates](protocol.md#user-access-privileges-transaction-354--server-initiates)
  (snapshot lines 431–439); [protocol.md — Additional Admin Privileges
  Note](protocol.md#additional-admin-privileges-note) (snapshot lines
  1215–1223)
- **Question:** When do edited privileges, names or passwords affect current
  sessions, does deletion disconnect them, and what 354/301 notifications
  occur?
- **Implementation impact:** Stored account state and live authorization may
  diverge in ways clients and tests cannot predict.
- **Close when:** Trace account/session propagation and record
  live-edit/delete event sequences and persistence across reconnect/restart.
- **Prior ledger entries:** V029, V035, V070
- **Investigation leads:**
  [10014df0](../mothra/evidence/hotline-server-1.9/queries/D-10014df0.c),
  [100149e0](../mothra/evidence/hotline-server-1.9/queries/D-100149e0.c),
  [10004f30](../mothra/evidence/hotline-server-1.9/queries/D-10004f30.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-072](#gap-072)
- **Progress:** Traced351 order: account deletion and ACK precede
  matching-login session notification/disconnect scan. Distinguished live354
  privilege propagation from deletion. Native self/delete/multiple-session
  delivery and reconnect fixtures remain required. Password/access/default
  replacements are visible on fresh connections and in stored records; these
  are not live-edit or restart fixtures. Fresh 10005d30/10005f90 queries
  retain propagation/deletion paths without a new runtime claim for active
  subjects. Native two-session edits establish new privileges/name propagation
  and continued existing-session liveness after password changes. Two-session
  deletion establishes data-only104, guest-firstFIN, stale snapshots and
  explicit late302 tails. Old/intermediate/deleted reconnects fail and final
  credentials succeed before/after a normal application restart; complete
  account records, five owned objects, app forks and Prefs remain identical.
  Host exit143 is retained with independent confirmation.
- **Evidence:** [Privilege registry](privilege-contracts.md); [Native caller
  review](../mothra/evidence/gap-remediation/2026-11-12/batch-15/privilege-callsite-review.json);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Closure review
  22](../mothra/evidence/gap-remediation/2026-11-13/closure-review-22/review.json)
- **Closure:** Closed against unchanged account/session propagation,
  live-edit/delete sequences and reconnect/normal-server-restart persistence
  criterion. No OS/power-loss or forced-I/O durability,
  protected/self-deletion, rename/conflict or universal room/transfer teardown
  claim. Other original gaps remain active.

### GAP-074

#### Kick/ban option branches

- **Tracking:** P1; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Disconnecting a User (Transaction 110 & 111) –
  Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 1154–1199)
- **Question:** What exactly do options 1 and 2 do, including identity
  matching, ranges/duration, optional data 101, reconnection and protected
  users?
- **Implementation impact:** Enumerated branches were observed but
  account-ban/IP-ban semantics remain guesses.
- **Close when:** Trace both ban helpers and publish
  option/outcome/expiry/protection rules with kick-only and both branch
  fixtures.
- **Prior ledger entries:** V071, V072, V073
- **Investigation leads:**
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c)
- **Depends on:** [GAP-031](#gap-031), [GAP-036](#gap-036)
- **Progress:** Traced option 1 timed 1800-second address ban and option 2
  persisted version-2 address-ban list; plain kick, missing target and
  protection branches documented. Expiry/restart/protected native fixtures
  remain required. Two bit-23 subjects reject administrator kicking and remain
  live before account deletion. Plain kick, both ban options, expiry/restart
  and broader protection fixtures remain active. Revision60: second disposable
  lab failed the mandatory full A7 download after 98,304 of 1,049,073 bytes,
  before any option-two request. Guest/namespace/recorder prefixes match; all
  observed payload was ACKed with positive receive windows. Producer stall
  cause remains unknown; this is a retained failure, not ban acceptance.
  Revision62: the third disposable lab also failed its mandatory 29-action A7
  at the same 98,304-byte prefix, before any account seed or option-two
  request. Independent reassembly confirms C32 completed 1,049,073 bytes in
  both views; C35/C45 stopped at the identical prefix. Recorded source images,
  binaries and preferences match, but live worker/GUI state is missing and the
  cause remains unknown. Revision63: one delivered focus event did not resume
  the exact dual 98,304-byte prefix, and the stock full A7 failed. This
  falsifies that one event-resume claim only; no account or ban request ran.
  Revision64 imports the gated control-only permanent-ban preparation with
  root controller identity checks. C53 was retired without frontend contact.
  No permanent-ban case is accepted by this checkpoint; expiry, reload and
  protection requirements remain open. Revision65 accepts one option-two
  control-only ban with target identity/zero-access/current-roster gates, no
  reason101, successful same-admin postreadback and fresh TRTP+Login107
  status1/100 permanent notice. The stopped49-byte Banned data fork is
  preserved. Temporary expiry, permanent reload and full protection fixtures
  remain open. Revision68 documents three stopped49-byte Banned v2 files with
  exact offsets and writer/reader trace: version/count, flag, twoIPv4
  endpoints,33-byte display area and zero-length reason. In-memory expiry+4 is
  not serialized. The11-byte display remainder stays opaque; C56/C62 reload is
  one case, C68 has no reload. Temporary expiry, kick-only and protection
  fixtures remain required. Revision69 supplies static instruction evidence
  for the request110 option2 optional-reason copy: bounded TLV payload lengthL
  is staged before its bytes; constructor raw-copies from the unadjusted
  length-byte pointer, predicting length byte plus firstL-1 content bytes
  forL1..63. This is not a nonempty runtime fixture or Options UI rule. The
  new expiry fixture is preparation only: first18baseline, deliberate35second
  connection-burst settling, kick0/protected/option1 plans, and separate
  pre/post first-lookup probes with current process/namespace/mutex/deadline
  gates. Eight focused tests and all438native tests pass; no
  kick/protection/expiry acceptance follows before live evidence. Revision70
  accepts C77 first-epoch packet evidence:13 paired control lifetimes,9 cases
  including option0 EOF/no104 then fresh107success, protected error then
  target500/one-secondquiet, option1notice/EOF/ACK and
  immediatevalid107temporaryerror. C76wrongnamespacefailure0actions is
  retained; frozenB68source andmetadata-only generic replay adaptation
  remainexplicit. Host/nsrecorders andmutex stopped; sameVM
  retainedsocket-free forlater probes. No expiryresult yet. Later runner guard
  checks itsOWN namespace beforecapture/socket work; staged cleanup permits
  guardonlyafteracceptedpost-probe
  anddeleteonlyafterownedaccountidentity/access proof. Revision71 accepts the
  complete later-epoch portable replay: sameVM/image, post-login success
  at2032.227663hostseconds, four paired laterflows, unchanged
  originalaccount/Prefs/appforks and controlledcleanup. C80pre-window
  remainedmissed with zero socketactions; source-derived1800seconddeadline
  andlazylookup cleanup are separate from observed immediate
  rejection/lateracceptance. Read-onlyguestclocks show ordinary progression
  withhostbrackets; not calibration ofGetDateTime. Both ownedfolders remain
  allocated inTrash despite352missing/348originaltwo. Retirement
  forcedemulatortermination afternativeappQuit, not orderlyOSshutdown.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Failed disposable-lab baseline and packet
  replay](native-transfer-stall.md); [Repeated baseline failure and successful
  control](native-transfer-stall.md#repeated-baseline-and-a-successful-comparison);
  [Verified focus-event negative](native-ui-focus-witness.md);
  [Control-onlybanpreparation](native-ban-control-preparation.md);
  [Permanent-ban control witness](native-ban-control-witness.md); [Observed
  Banned v2 layout](native-ban-file-format.md); [Request110 reason-copy source
  trace](native-ban-file-format.md#request-110-reason-copy-path); [Bounded
  temporary-ban fixture preparation](native-ban-expiry-preparation.md);
  [Stopped assets and pre-live
  reviews](../mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-preparation-01/manifest.json);
  [Paired first-epoch witness](native-ban-expiry-first-witness.md);
  [First-epoch portable packet
  evidence](../mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01/manifest.json);
  [Staged post-probe cleanup](native-ban-expiry-cleanup.md); [Runner namespace
  failure
  regression](../mothra/evidence/gap-remediation/2026-11-14/native-runner-namespace-guard-01/manifest.json);
  [Later expiry observation and cleanup](native-ban-expiry-later-witness.md);
  [Later portable
  evidence](../mothra/evidence/gap-remediation/2026-11-14/native-ban-expiry-later-01/manifest.json);
  [Original-criterion
  decision](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-05/decision.json)
- **Closure:** Met at the original native 1.9 option/outcome/expiry/protection
  scope: both helper traces, kick-only and both ban-branch fixtures, protected
  target, immediate rejection and later acceptance, and the permanent
  reload/configured-apply cases are documented. The pre1700-second control was
  missed and is not treated as evidence. Exact1800-second cutoff, rollover/all
  clock adjustments, arbitrary ranges and nonempty reason bytes remain
  unmeasured; the optional reason transformation is explicitly source-derived.
  No universal purge mechanism, physical erasure or full-transfer guarantee
  follows.

### GAP-075

#### Standalone transaction 111

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Disconnecting a User (Transaction 110 & 111) –
  Admin/Server
  Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use)
  (snapshot lines 1154–1199); [protocol.md — Additional Observed Requests and
  Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps)
  (snapshot lines 1224–1271)
- **Question:** Does any native producer actually emit 111, under which
  conditions, with what fields and delivery/closure ordering?
- **Implementation impact:** A retained catalogue entry cannot yet be
  implemented or declared absent with confidence.
- **Close when:** Locate a producer and capture its schema/sequence, or
  document a bounded negative-search result and an explicit support decision.
- **Prior ledger entries:** V072, V074
- **Investigation leads:**
  [10015e70](../mothra/evidence/hotline-server-1.9/queries/D-10015e70.c),
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c)
- **Depends on:** No prerequisite recorded.
- **Evidence:** [Shutdown producer
  10001bf0](../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10001bf0.c);
  [Online fan-out
  10005510](../mothra/evidence/gap-remediation/2026-11-12/batch-06/queries/B06-D-10005510.c);
  [Published schema and
  sequence](presence-messaging-contracts.md#kick-options-and-native-console-messages)
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Closure:** Located and captured a positive standalone-111 producer,
  field-101 schema and conditional shutdown sequence. This satisfies this
  entry’s producer/schema criterion. Delivered native packet fixtures remain
  GAP-084; no mandatory-kick interpretation is asserted.

### GAP-076

#### Server-originated broadcast and eligibility

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Broadcasting a Message (Transaction 355) –
  Admin/Server
  Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated)
  (snapshot lines 1200–1214)
- **Question:** Does a console-generated broadcast use the same 355 schema,
  and which connected/logged-in/refusing users receive each origin's
  broadcast?
- **Implementation impact:** The validated client-request path does not
  establish all advertised admin/server initiation cases.
- **Close when:** Trace console and fan-out paths and publish
  origin/recipient/field tables with self-recipient and session-state
  fixtures.
- **Prior ledger entries:** V046, V048
- **Investigation leads:**
  [1000f990](../mothra/evidence/hotline-server-1.9/queries/D-1000f990.c)
- **Depends on:** [GAP-044](#gap-044)
- **Progress:** Identified console message 104/data-only versus client
  broadcast355 and documented online/ready recipient helper. Native
  self/state/message fixtures remain required. Root acceptance revision56:
  Traced console104/data-only and client355 identity/data fan-out are now
  paired with four-state native fixtures, sender exclusion, online
  refusal-option recipient and waiting121 activation. Guest streams are
  complete; three host views are complete and the first host handshake loss is
  explicit. Full A7 postflight restores the baseline. The original
  origin/recipient/field/self/session-state criterion is met; other104
  variants remain GAP044.
- **Evidence:** [Presence, messaging and
  administration](presence-messaging-contracts.md); [Batch
  06](../mothra/evidence/gap-remediation/2026-11-12/batch-06/manifest.json);
  [Native console and client broadcast
  recipients](native-console-broadcast.md)
- **Closure:** Traced console104/data-only and client355 identity/data fan-out
  are now paired with four-state native fixtures, sender exclusion, online
  refusal-option recipient and waiting121 activation. Guest streams are
  complete; three host views are complete and the first host handshake loss is
  explicit. Full A7 postflight restores the baseline. The original
  origin/recipient/field/self/session-state criterion is met; other104
  variants remain GAP044.

### GAP-077

#### Request 348 schema and purpose

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 1224–1271)
- **Question:** What does 348 do, what fields and privileges apply, and how
  are its potentially nested account records serialized?
- **Implementation impact:** An observed dispatcher entry cannot be advertised
  as a supported account operation from its number alone.
- **Close when:** Trace handler/helper paths and provide operation semantics,
  request/reply grammar and representative success/error fixtures.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10015160](../mothra/evidence/hotline-server-1.9/queries/D-10015160.c)
- **Depends on:** No prerequisite recorded.
- **Binary sha256:**
  ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b
- **Evidence:** [Native core
  manifest](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/manifest.json);
  [Semantic
  verification](../mothra/evidence/gap-remediation/2026-11-12/native-core-01/verification.json);
  [Source and credential
  contracts](native-wire-details.md#credential-bytes-lookup-and-account-updates);
  [Enumeration
  grammar](operation-contracts.md#administrative-account-list-and-batch-mutation);
  [Unchanged criterion
  review](../mothra/evidence/gap-remediation/2026-11-12/closure-review-03/review.json)
- **Closure:** Traced348 enumeration and its account reader/serializer;
  published no directly read request fields and repeated outer101
  nested102/105/106/110 grammar. Native admin success and zero-privilege
  denial are retained, and the executable verifier checks nested records,
  password placeholders and exact fixture membership. This satisfies the
  unchanged representative-fixture criterion; no historical client identity or
  atomic snapshot guarantee is inferred.

### GAP-078

#### Request 349 schema and batch outcomes

- **Tracking:** P2; Unanswered; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — Additional Observed Requests and Scope
  Gaps](protocol.md#additional-observed-requests-and-scope-gaps) (snapshot
  lines 1224–1271)
- **Question:** What indexed/transitive fields does 349 consume, how are batch
  entries delimited, and are failures atomic or per-entry?
- **Implementation impact:** Implementing guessed batch semantics can mutate
  only part of a request with no specified result.
- **Close when:** Trace the handler and publish batch framing,
  permission/default/partial-error rules and mixed-success fixtures.
- **Prior ledger entries:** V074
- **Investigation leads:**
  [10015500](../mothra/evidence/hotline-server-1.9/queries/D-10015500.c)
- **Depends on:** [GAP-071](#gap-071), [GAP-072](#gap-072)
- **Progress:** Batch349 admits any of bits14/15/17 but enforces per-item
  delete/create/update gates, including create bitmap subset with bit27
  exemption. Earlier mutations can survive later failure.
  Mixed-result/rename/conflict native fixtures remain required. Captured
  framing, 512-byte copy boundaries, per-item permissions, defaults, NUL
  password qualification and mixed success/error effects. Distinct-password
  rename collision proves destination overwrite and later-item continuation.
  Seventy complete reports, 75 paired connections, full native records and
  positive cleanup support the published matrix.
- **Evidence:** [Privilege registry](privilege-contracts.md); [Native caller
  review](../mothra/evidence/gap-remediation/2026-11-12/batch-15/privilege-callsite-review.json);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Closure review
  23](../mothra/evidence/gap-remediation/2026-11-13/closure-review-23/review.json)
- **Closure:** Closed against the unchanged batch framing,
  permission/default/partial-error and mixed-success fixture criterion. Opaque
  attribute meaning, protected/self-delete, general exception translation and
  forced I/O remain separate active requirements. No mxd defect-parity claim.

## Compatibility and evidence

### GAP-080

#### Identified peer corpus and fallback classifier

- **Tracking:** P1; Evidence; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 35–62); [internal-compatibility-matrix.md — Open compatibility gaps
  and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 324–360)
- **Question:** Which client builds are acceptance targets, what stable
  evidence distinguishes them after removing sub-version 2, and what is the
  unknown-peer fallback?
- **Implementation impact:** Correcting a bad discriminator does not supply a
  replacement compatibility policy.
- **Close when:** Create a hashed client/capture corpus and evidence-based
  profile/fallback rules; retain reported version values separately from
  proven identities.
- **Prior ledger entries:** M001, M002, M003, M004, M007
- **Investigation leads:**
  [1000acf0](../mothra/evidence/hotline-server-1.9/queries/D-1000acf0.c),
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c)
- **Depends on:** No prerequisite recorded.
- **Progress:** Added hashed shx0.1.48 source at
  adb1bf8c8cb12f7eb2fa2c01673295a6312f262b. Source profile is identified;
  compiled-client/runtime corpus and fallback policy remain open.
  Native-shx-01 identifies one complete modern Linux shx0.1.48 build at
  sourceadb1bf8c8cb1 and executable8fbbe56cef43. Five accepted sessions cover
  login/chat/list/forks/negativepassword/ambiguousbytes with paired packet
  evidence. Acceptance-target selection and unknown-peer fallback remain open;
  reported160 is absent in this peer request and is not used as identity.
  Eight actual native full-peer sessions across native-shx-01/02 andfour
  labelled receiver fixtures identify one modern configured shx build.
  Acceptance-target selection and unknown-peer fallback still require a
  separate policy; no field160/sub-version peer identity is inferred. Five
  full-process controlled sessions pin the same identified shx build and
  source; reported sub-version2 stays separate from identity.
  Omitted/varied161, unknown login TLV and earlier122 preserve continuation.
  Target/fallback decisions and other selected profiles remain open. An
  acquired Mac client archive is hashed and statically identified with
  APPL/HTLC PPC PEF forks. Archive/application labels say 1.9.2 while both
  embedded vers strings say 1.9.1.0. Keep these observations distinct from
  opaque binary identity and vendor authenticity. At that acquisition
  checkpoint, no client replay or additional profile/fallback decision had
  occurred. Latest captured session: B13 executed the prelaunch
  fork-hash-identified Classic candidate once against native 1.9. Three
  independent control views reconcile 150 client/514 server bytes; both guest
  data views reconcile 16/58 bytes for its automatic banner fetch. One
  login/agreement/roster session succeeded, then automatic external
  advertising HTTP caused a safety stop. Archive 1.9.2 versus resource 1.9.1.0
  identity conflict remains explicit. Neither vendor identity, universal
  profile classification nor fallback policy is inferred. User
  instruction13November2026: further mxd validation/fixes are on hold;
  consolidate completed evidence in mxd-validation.md. Canonical sourcecb907
  has accepted framing/directACK/loginextras corrections. Actual Classic
  authenticates with fully transmitted24-byte fixture secret but waits for
  missing agreement handoff; no121/300/212 follows. This is partial startup,
  not release or complete compatibility evidence. Revision63: the pinned
  Classic client completed the unchanged 161=0000 baseline through 121/300 and
  a 16-byte HTXF request/58-byte banner transfer. All five views match. Banner
  rendering is unproved. B52 width probes remain a separate pending
  publication; no broader profile or field-162 policy is inferred. Revision64
  accepts the published B52 three-case Classic 161 matrix with five-view
  complete TCP lifetimes and exact A7 preflight/postflight. Build identities
  remain separate from archive/version labels. No universal classifier or
  release-target decision follows. Revision65 root acceptance:
  peer-profile-rules.md publishes two exact evaluated build identities, finite
  measured/untested cells and the native1.9 unknown-peer producer rule.
  Independent A43/A44 criterion audits support closure against the original
  criterion. Missing build provenance stays unknown; shared
  sub-version2/reported160 never classify. Classic archive/app1.9.2 versus
  vers1.9.1.0 remains explicit. No universal compatibility or mxd
  release/policy decision follows. Revision66 updates the evaluated-build
  registry with the accepted finite Classic ASCII 162 cell; identity/fallback
  closure remains unchanged.
- **Evidence:** [Error outcomes](error-outcomes.md); [Folder
  descriptor](transfer-contracts.md#folder-item-descriptor-bytes); [Identified
  client source](identified-client-source.md); [Full historical peer
  sessions](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Native shx
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json);
  [Configured native names and controlled receiver
  matrix](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix);
  [Second full-peer
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/manifest.json);
  [Controlled peer tolerance matrix](peer-tolerance-matrix.md); [Peer
  tolerance
  corpus](../mothra/evidence/gap-remediation/2026-11-13/delegated-peer-01/manifest.json);
  [Acquired Mac candidate
  identity](../mothra/docs/delegation/mac-peer-candidate.md); [First Classic
  peer session](mac-peer-first-session.md); [mxd validation findings and
  hold](mxd-validation.md); [Classic native
  baseline](classic-native-baseline.md);
  [Classic161matrix](classic-field161-matrix.md); [Evaluated profiles and
  unknown-peer rule](peer-profile-rules.md); [Root peer-profile
  acceptance](../mothra/evidence/gap-remediation/2026-11-14/peer-profile-acceptance-01/decision.json);
  [Classic ASCII server-name witness](classic-server-name-162.md)
- **Closure:** Resolved against the unchanged criterion: two hashed
  executable/capture profiles, explicit evaluated-build targets, separate
  reported-version observations, and native1.9 unknown-peer rules are
  published. Per-field tolerance and release/mxd decisions remain separate.

### GAP-081

#### Client tolerance of extra fields

- **Tracking:** P2; Evidence; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Login reply and banner
  policy](internal-compatibility-matrix.md#login-reply-and-banner-policy)
  (snapshot lines 63–111); [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 35–62)
- **Question:** Which identified clients accept 161/162, 122, native roster
  output and the SynHX subject addition, and when is an omission policy
  necessary?
- **Implementation impact:** The matrix cannot justify compatibility-specific
  reply changes from another server's output alone.
- **Close when:** Run a peer-by-field acceptance matrix and record actual
  failures/tolerance before selecting omission/default policies.
- **Prior ledger entries:** M003, M004, M007, V024, V033
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [10011ee0](../mothra/evidence/hotline-server-1.9/queries/D-10011ee0.c),
  [10011870](../mothra/evidence/hotline-server-1.9/queries/D-10011870.c)
- **Depends on:** [GAP-080](#gap-080)
- **Progress:** Executed seven host-built cases of the unchanged basic-login
  callback/macros, including ignored160/161/162 and unknown fields with
  UID/status controls. Full historical peer-by-field sessions and other
  configured profiles remain required. Full shx terminal sessions consume
  native160=00be/161=0000, automatic native roster records and repeated
  file-list records, then chat/download successfully. Empty configuredname
  omits162 and no122is emitted; configured162,122,subjectaddition and
  otherpeer/profile cases remain required before omission/default policy.
  Native-shx-02 adds actual ASCII/highbyte162 success andemptyname
  restoration. Controlled fullprocess matrix delivers exact native122
  andsource-derived115 separately/together withnative roster controls:122is
  reportedunknown anddumpedexactly while reload/chat continue;115isdisplayed.
  No bannerUI, liveSynHXserver, optional-profile or universal
  omission/fallback policy claimed. Controlled full-process matrix adds
  omitted 161, changed 161, unknown login field32767 and native122 before
  automatic roster. Exact socket/packet/terminal bytes and continuation pass;
  three checksum-refreshed semantic mutations are rejected. Other selected
  profiles and omission/default policy remain open. Latest captured session:
  The first actual Classic candidate consumed native login fields 160/161,
  agreement 109, bitmap 354, banner 122 and a roster reply, and automatically
  fetched the 58-byte banner. This is a finite positive witness for those
  bytes/build only. There was no controlled extra-field perturbation matrix,
  configured field 162 case or universal tolerance proof; the planned
  local-only idle test was stopped. User instruction13November2026: further
  mxd validation/fixes are on hold; consolidate completed evidence in
  mxd-validation.md. Canonical sourcecb907 has accepted
  framing/directACK/loginextras corrections. Actual Classic authenticates with
  fully transmitted24-byte fixture secret but waits for missing agreement
  handoff; no121/300/212 follows. This is partial startup, not release or
  complete compatibility evidence. Revision63: the pinned Classic client
  completed the unchanged 161=0000 baseline through 121/300 and a 16-byte HTXF
  request/58-byte banner transfer. All five views match. Banner rendering is
  unproved. B52 width probes remain a separate pending publication; no broader
  profile or field-162 policy is inferred. Revision64: the B52 Classic
  omission, one-byte and four-byte zero-valued 161 cases all reached
  121/300/212 and banner data. The controlled shx matrix remains separately
  identified. The historical proxy/parser are frozen as run, so new 162
  preparation cannot change their source identity. The field-162 case is
  preparation only; no omission/default policy is selected. Revision66 accepts
  B57: the raw 34-byte native ACK becomes 52 bytes by adding only
  162=fixture-native. Five complete TCP views, control IDs/flags, data
  reference and 16/58-byte exchange, full A7 preflight/postflight, and managed
  zero-drop recorder/cleanup receipts agree. B56 FileExistsError remains a
  zero-contact setup failure with its own full A7 readbacks. SynHX-shaped
  subject 115 remains untested on this Classic build; no universal
  omission/default policy follows. Revision67: the consolidated peer-by-field
  matrix covers native roster, 161 variation/omission, nonempty 162, 122, and
  the SynHX-shaped 115 addition for the two exact identified builds. The new
  Classic first-roster subject capture has paired native/modified streams and
  a subsequent displayed Online Users row. The shx 122 unknown-header
  diagnostic with continued operation is recorded as partial support.
- **Evidence:** [Error outcomes](error-outcomes.md); [Folder
  descriptor](transfer-contracts.md#folder-item-descriptor-bytes); [Identified
  client source](identified-client-source.md); [Full historical peer
  sessions](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Native shx
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json);
  [Configured native names and controlled receiver
  matrix](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix);
  [Second full-peer
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/manifest.json);
  [Controlled peer tolerance matrix](peer-tolerance-matrix.md); [Peer
  tolerance
  corpus](../mothra/evidence/gap-remediation/2026-11-13/delegated-peer-01/manifest.json);
  [First Classic peer session](mac-peer-first-session.md); [mxd validation
  findings and hold](mxd-validation.md); [Classic native
  baseline](classic-native-baseline.md);
  [Classic161matrix](classic-field161-matrix.md); [Evaluated profiles and
  unknown-peer rule](peer-profile-rules.md); [Classic ASCII server-name
  witness](classic-server-name-162.md); [Cross-peer acceptance and omission
  rules](peer-tolerance-matrix.md#cross-peer-acceptance-and-omission-rules);
  [Classic subject-field witness](classic-roster-subject-115.md);
  [Original-criterion
  acceptance](../mothra/evidence/gap-remediation/2026-11-14/criterion-acceptance-03/decisions.json)
- **Closure:** Met for the two pinned builds and finite recorded bytes. No
  measured rejection requires a family-wide omission rule. Unknown builds and
  values remain unknown; Classic subject/banner rendering and general
  malformed-TLV tolerance are unproved. Screenshot mtime is a receipt bound
  and earlier request 212 is not proof of roster processing. Native
  producer/default rules are separate from mxd release policy; mxd validation
  remains on hold.

### GAP-082

#### Heuristic text-decoding policy

- **Tracking:** P1; Decision; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Credential obfuscation and
  text
  compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility)
  (snapshot lines 112–139); [protocol.md — Binary Message Formats (Hotline
  Protocol 1.9)](protocol.md#binary-message-formats-hotline-protocol-19)
  (snapshot lines 35–42)
- **Question:** Will mxd retain text XOR heuristics, on which fields/states,
  and how does it handle valid non-UTF-8 or ambiguous plaintext without
  irreversible mode changes?
- **Implementation impact:** Credential complementing does not decide a
  general message/news decoder and heuristics may not identify peers.
- **Close when:** Document the policy decision and exact state/field rules
  with an ambiguity corpus; validate interoperability independently of named
  heuristic tests.
- **Prior ledger entries:** M005, V016, V043, V045
- **Investigation leads:**
  [10011960](../mothra/evidence/hotline-server-1.9/queries/D-10011960.c),
  [1000f4e0](../mothra/evidence/hotline-server-1.9/queries/D-1000f4e0.c)
- **Depends on:** [GAP-018](#gap-018), [GAP-080](#gap-080)
- **Progress:** Pinned shx basic source uses credential complement separately
  from ordinary text copying; no universal UTF8-triggered text mode is
  inferred. Existing mxd heuristic remains a distinct policy requiring
  ambiguity corpus and full interoperability evidence. Full historical-source
  peer receives a controlled80/9a/c3b6/ff chat suffix unchanged at native106
  and rawPTYoutput, independent of mxd heuristic tests. This one-profile
  ambiguity sample does not decide mxd field/state rules or unknown-peer
  fallback. Peer tolerance is measured independently of heuristic decoder
  tests, but five controlled variants do not select mxd state/field decoding
  rules or unknown-peer policy.
- **Evidence:** [Error outcomes](error-outcomes.md); [Folder
  descriptor](transfer-contracts.md#folder-item-descriptor-bytes); [Identified
  client source](identified-client-source.md); [Full historical peer
  sessions](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Native shx
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json);
  [Controlled peer tolerance matrix](peer-tolerance-matrix.md); [Peer
  tolerance
  corpus](../mothra/evidence/gap-remediation/2026-11-13/delegated-peer-01/manifest.json)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-083

#### Historical SynHX source identity and applicability

- **Tracking:** P2; Evidence; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Compatibility
  matrix](internal-compatibility-matrix.md#compatibility-matrix) (snapshot
  lines 35–62); [protocol.md — References and Correction
  Traceability](protocol.md#references-and-correction-traceability) (snapshot
  lines 1272–1313)
- **Question:** Which release/client/server configurations do the selected RCS
  trunk snapshots represent, and how do the default vendor branch and build
  options differ?
- **Implementation impact:** A useful historical comparison could otherwise be
  generalized to all SynHX profiles or mixed build variants.
- **Close when:** Record archive lineage, selected/default revision
  relationship, relevant build flags and the exact peers to which each source
  observation applies.
- **Prior ledger entries:** M001, M005, M007, M008
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** No prerequisite recorded.
- **Progress:** Supplementary six server metadata/configuration archives plus
  earlier14protocolarchives now establish selected/default relationship,
  declaredserver source0.1.48.1 versusclient0.1.48,
  configure/effectivefallback distinctions andexactobservation applicability.
  The testedclient8fbbe56 hasfullflags/config/compiler/library/patch
  provenance; originaldistributed/deployedserver identity isnot asserted.
- **Evidence:** [Source identities and
  applicability](identified-client-source.md#source-package-identities-and-configuration-applicability);
  [Server profile
  record](../mothra/evidence/gap-remediation/2026-11-13/synhx-profile-01/manifest.json);
  [Full build
  record](../mothra/evidence/gap-remediation/2026-11-13/shx-build-01/build/manifest.json);
  [Closure review
  16](../mothra/evidence/gap-remediation/2026-11-13/closure-review-16/review.json)
- **Closure:** Closed against the unchanged source
  lineage/revision/flags/applicability criterion. GAP080/081 retain broader
  acceptance-target/fallback/peer-tolerance requirements; no universal
  deployed-binary claim is made.

### GAP-084

#### Native conformance fixtures beyond one illustrative frame

- **Tracking:** P0; Evidence; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — 5 Worked example
  (Login)](protocol.md#5-worked-example-login) (snapshot lines 240–274);
  [protocol.md — 6 Implementation
  checklist](protocol.md#6-implementation-checklist) (snapshot lines 275–289);
  [internal-compatibility-matrix.md — Open compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 324–360)
- **Question:** Where are executable positive/negative fixtures for core
  handshake, authenticated login, both completion paths, errors and
  repeated-field handling?
- **Implementation impact:** Static paths and a hand-counted example do not
  establish end-to-end interoperability or a regression oracle.
- **Close when:** Retain identified-peer/core-session captures and expected
  decoded/events results, with a reproducible fixture runner and packet
  provenance.
- **Prior ledger entries:** V003, V007, V018, V019, V025, V027, M008
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-022](#gap-022), [GAP-025](#gap-025)
- **Progress:**  Added a14-test capture runner and the first positive
  native12/8-byte handshake. The guest later crashed; exact guest component
  versions and running executable hash were not retained.
  Negative/pipelined/login/data/identified-peer fixtures and complete
  provenance remain required. Added16 native transcripts from hashed patched
  emulator/ROM/base/native application forks, host-loopback packet capture,
  account records and a semantic verifier. Fourteen plans completed; two EOF
  observations timed out and remain failed. No identified historical peer or
  full native corpus completion is claimed. Added14 addressed final handshake
  cases with paired host/guest packet reconciliation,39 total retained
  transcripts including explorations, a hashed clean prelaunch checkpoint and
  reset-aware analysis. Split windows are3 seconds; observed native FIN/RST
  distinctions are preserved even when the host proxy exposes EOF. Full
  operation/identified-peer corpus remains required. Added62 reviewed
  framing/TLV sessions plus preserved disproven initial icon-width hypothesis,
  exact host/guest packet reconciliation scoped to UTC/SYN lifetimes, and
  independent missing-close/quiet-window controls. Full operations and
  identified peers remain required. Added two successfulordinaryuploads and
  eightrevieweddownload modes plus eight initialprobes. Exact pairedpackets
  and nativeHFS+ forks validated; oneunread59byte301 controlsuffix explicitly
  pinned in bothviews rather than addedtooriginalreport.
  Fulloperation/identifiedpeer corpus remains required. Added23 final resume
  observations and7 initialattempts with3 retainedfailures. Everytranscript
  reconciles exact pairedpackets, with2 pinnedinitialunread301suffixes.
  Before/after nativeHFS+ forks validate correct/inconsistent continuation.
  Boundedreplymatching preserves asynchronousnotifications. Full operations
  andidentifiedpeers remain required. Added four controlled queue cases with
  paired exact streams, full reply inventories, mode/fork sizes,
  owner-specific211 sequences and measured540second pause windows. One
  unread28byte302 is pinned explicitly in both packet views. Test limits2/1
  and restored100/10 are verified in saved/reopened GUI screenshots; no
  ROM/disk committed. Full operations and identified peers remain required.
  Added ten completed cleanup/seed cases, paired exact streams, native HFS+
  fork bytes and first-observed packet/request/ACK timing with retransmissions
  deduplicated. A28byte unread departure is pinned explicitly. Three immediate
  and three partial-read races plus nonowner delivery establish finite
  outcomes, not all-operation or identified-peer conformance. Added17 final
  folder cases,3 initial probes and1 auxiliary finalization. Core andtimed
  pairedpacket phases, positive before/after catalogue/fork snapshots and
  measured pauses are retained. Two initial failures occur before folder
  requests; one hostwrite never reaches guest boundary and is pinned
  separately. Path-based HFS enumeration fails; positive direct lookup
  succeeds, withoutabsence/exhaustiveness claims. Full operations
  andidentifiedpeers remain required. Added24 final banner cases with exact
  paired packet streams, positive native GIF fork/catalogue observations and
  retained exploratory failures. GUI phases overlap the expiry observation and
  are disclosed. Full operation and identified historical-peer coverage remain
  required. Added17 final format/recovery/reset sessions, five original
  exploratory reports and nine additional setup observations. Eight
  independently observed native file/type controls, protocol-confirmed
  absence/restoration, concurrent owner/observer reset and positive post-reset
  login are retained. All final packet streams reconcile; one
  exploratory22-byte post-reset host suffix never reaches the guest. Three
  completed exploratory Save hypotheses retain the wrong loaded configuration.
  Full operations and identified historical peers remain required. Delayed
  recovery directly retains an owner122 before disappearance; both early and
  delayed recovery streams pass independent packet/phase checks. Two rejected
  setup trials pin unread57-byte banner suffixes and301/302 controls
  explicitly. Added17 HTXF sessions plus preflight; all inputs/outputs
  independently reconcile at both packet boundaries. Three positive native
  DATA forks and seven semantic/mutation tests strengthen header/reference
  acceptance; complete operations and identified historical peers remain
  required. Added24 paired native ID/envelope/EOF sessions and25 read-only
  oracle queries, including a preserved rejected interior-address query. No
  unread packet suffixes. Zero/high-bit IDs, collision/reuse, late replies,
  emitted notifications, unsupported requests and underfilled EOF now have
  acceptance evidence; other operations and historical peers remain required.
  Added33accepted auth/lookup/state reports,2retained exploratory
  reports,14read-onlyoraclequeries,5positive UserData records
  andagreementfork. Everypacketstream reconciles withliteral28-byte
  delayed302tail retained. Fulloperations, configuration paths
  andhistoricalpeers remain required.
  Added42acceptedagreementcases,28setupcontrols,12exploratoryreports
  and16identitycheckedqueries withnativepath/type/fork controls. All42accepted
  and39nonstalled auxiliary streams reconcile exactly; host-timer
  failedboundary isexplicitly bounded withlateSYNACK retained.
  Originalagreementandaccountcleanupverified. Fulloperations/peers/mxd
  acceptance remain required.
  Added34acceptedlogin-extra/name-change/referencecases,11setupcontrols,5exploratoryreports
  and14identitycheckedqueries withpositivePrefs controls.49reportstreams
  reconcile exactly; failed90secondtrialexplicitlyretains hostonlylate121
  andguestonly302. Allaccepted streams matchbothboundaries.
  Broaderoperations,identifiedpeers andmxd acceptance remain required. Five
  full historical-source terminal sessions plus a controlled script witness
  now reconcile sixpeer sockets and onewitness socket at both host and guest
  boundaries. SavedDATA13/MACR317 match knownfixture and FILP;
  hostrecorder170packets/zerodrops. This extends fixture coverage without
  closing otheroperation/peer/mxd acceptance requirements. Three actual native
  configured-name sessions andthree nativeflushcontrols reconcile
  bothpacketboundaries; four realpeer receiverfixtures reconcile
  hostPCAP/syscalls/listenerevents. PositivePrefs andbaseline restoration
  arechecked; controlled delivery isnever labellednative execution.
  Native-mkdir-01 adds47creation/path cases plus sixempty-root
  inputs,51reports/53paired sockets, tenidentitycheckedqueries
  andpositivecatalogues. Literal1374+43 hostrecordings, zero drops,
  exactmergedcapture and44ownedTrashobjects are retained. Broader
  operation/peer/mxd acceptance remains active. Nativealias01
  adds44completedreports
  plusoneinitialEOFtimeout,66pairedsockets,14identitycheckedqueries
  and33positiveprecleanupcatalogueobjects. Newtimerpatchedruntimeprovenance
  retained.
  Cleanuprestores41entrywirelisting;postcleanupdiskviewonly3positiveobservations,notcompletepersistenceproof.
  Native-metadata01adds49reports/72pairedsockets,36mainmutations,sixcombined-emptycases,22boundarywrites,13freshoraclequeriesandindependentadminfinalviews.
  Initialwrong351cleanupencodingandcorrectedrecoverybothretained;ownedaccountsabsentandFileswirelistingrestored.
  Broaderoperation/peer/mxdcriteriaremainactive.
  Native-move01adds39reports/75pairedsockets,11freshoraclequeries,72seeded/73finalpositiveobjectsand70postcleanupTrashobservations.
  Fileswirelistingrestored;threepostcleanupmarkerprobesnotpositive.
  Broaderoperation/peer/mxdacceptanceremainsactive.
  Native-news01adds43reports/45sockets,29freshoraclequeries,ninecontrolledversions,threaded/cached321andfivepositive/fournegativebodycases.
  Initialzero-positivecleanupviewisretainedinconclusive;subsequentnativeuploadpublishes10originalTrashobjectsandpreservedHLNZcaches.
  Broaderoperation/actual-peer/mxdacceptanceremainsactive. Article deletion
  adds 58 reports (56 completed, two retained failures), 60 paired
  connections, 15 fresh queries and independently verified native
  counts/caches. Distinct old/recovered runtime identities and prefix-only
  recovery retained. Broader operation and actual-peer acceptance remains
  active. Added 20 completed reports, 22 paired connections, ten fresh
  identity-checked queries, native 103-record/index versus 102-entry
  list/cache boundary and positive owned cleanup. Initial out-of-range and
  unrelated Trash probes stay explicitly inconclusive. Wider native/peer
  acceptance remains active. Added 31 completed reports, 34 paired
  connections, eleven identity-checked queries, complete before/after 734-byte
  records, nine positive/eight negative logins and positive owned
  Trash/cleanup observations. Broader operations and actual-peer acceptance
  remain active. Added 18 complete reports and an expected stopped failure, 25
  host socket lifetimes with 24 established guest connections, sixteen
  identity-checked queries, explicit unread removal tails and application
  restart evidence. Host stage exit143 is retained with independent
  confirmation, not erased or called a native crash. Wider operations and
  actual peers remain required. Added 70 reports, 75 paired connections,
  eighteen primary batches and a distinct-password collision contrast, twelve
  oracle queries and complete native records. All 29 owned accounts removed;
  64 original objects positively preserved in Trash. Actual peer and
  wider-operation fixtures remain active. Added fourteen complete reports,
  sixteen paired connections, ten identity-checked queries, two unread removal
  tails and nine independent regressions for duplicate/lookup echo, kick
  protection, self-delete ordering and server-first FIN. Actual peer and
  wider-operation evidence remain active. Added thirteen completed
  observations, two failed recorder expectations, 45 paired TCP lifetimes,
  sixteen oracle queries and sixteen regressions. All original account/Files
  listings restored. Wider operations, actual peers and mxd evidence remain
  active. Added five complete 303 native reports/six paired lifetimes with
  cleanup, plus independently labelled controlled peer and mxd source/test
  evidence. Only the diagnostic captures are new native-server exchanges;
  broader conformance requirements remain active. Five native representative
  failure classes are now rendered with exact plan/report/action indexes,
  hashes and bytes from existing identified captures. These are newly
  documented witnesses, not new runtime execution; broader conformance
  criteria remain active. Disposable runtime recovery now has preboot
  source/copy/ROM hashes, positive application forks, recorded automatic disk
  check on only the working copy and two readiness smokes. The first lacks
  independent host pcap and is preserved with that limit; the second has exact
  host/guest stream reconciliation and two-account enumeration. Preboot
  identity does not prove live post-repair image bytes. This restores a
  bounded runtime capability without closing broader conformance criteria.
  Three new paired-boundary observations preserve a failed diagnostic fixture
  and its controlled cleanup rather than relabel it successful. Active/queue
  conformance remains missing; at that checkpoint the separately acquired Mac
  client was not yet an interoperability fixture. Latest captured session: A
  new actual Classic-peer corpus retains all three raw control views and both
  guest data views, exact delayed agreement/roster/banner exchange and five
  automatic GET/404 exchanges. Offline verifier and four fault-control tests
  replay it. Recorder ready/drop/stop output was not saved as raw logs and is
  explicitly transcript-derived. This partial session does not complete the
  original native conformance criterion. Latest A8 phase 1: The A8 corpus adds
  two paired captures: one active/queued diagnostic and a complete restoration
  postflight. Original failed parser output is preserved; corrected semantic
  and packet checks replay without live execution. All 14 focused unit tests
  pass, including wrong-section grammar/count/cancellation controls. Broader
  original conformance criteria remain open. Root acceptance revision54:
  Native core-session fixtures and identified shx captures retain
  decoded/events results, reproducible runners, pinned identities and matched
  host/guest packet provenance. The isolated Classic session additionally
  checks login/agreement/roster and banner transfer bytes across three capture
  views, with a finite quiet interval and explicit UI limitation. This
  satisfies the original core-session fixture criterion; wider operation
  support and release selection remain separate requirements. Revision75
  retains the aborted firstboard lab: receipt-property-shape mismatch and
  missingcorrection-script127 bothbeforefirstprotocolsocket;
  host/namespacePCAPs24B, guestbootDHCP/ARPonly, no18readiness andno
  boardcase. Five stoppednamedforks unchanged, boardDATA/RSRCremainzero.
  B79/B80offlineboardmatrix passes11tests inclrealmalformedtailcleanup;
  thisdoesnotfulfilnativeboardacceptance. Exactreceiptbuilder has7faulttests,
  independentreview andrealmanagedlease/passivecapturefunctionrehearsal;
  fullnewMac/runtimeCLIreadiness remainsseparate.
  Freshstoppedboard02preparationdoesnotimplyliveauthority.
  Prioracceptednativefixturesremainvalid; no mxdvalidationresumes.
- **Evidence:** [Native format/recovery/reset
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-banner-02/manifest.json);
  [Banner type/recovery
  contract](transfer-contracts.md#captured-banner-formats-and-recovery);
  [Repeatable format/recovery
  workflow](native-capture-workflow.md#reproducing-banner-format-and-recovery-fixtures);
  [Native HTXF header/reference
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-htxf-01/manifest.json);
  [Native ID/envelope/EOF
  corpus](../mothra/evidence/gap-remediation/2026-11-12/native-correlation-01/manifest.json);
  [Native authentication/state
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-auth-01/manifest.json);
  [Native agreement
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-agreement-01/manifest.json);
  [Native login-extra
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-login-extras-01/manifest.json);
  [Full historical peer
  sessions](identified-client-source.md#full-native-peer-acceptance-matrix);
  [Native shx
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-01/manifest.json);
  [Configured native names and controlled receiver
  matrix](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix);
  [Second full-peer
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-shx-02/manifest.json);
  [Native directory and path
  matrix](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths);
  [Directory/path
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-mkdir-01/manifest.json);
  [Native alias and metadata
  matrix](filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix);
  [Alias
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-alias-01/manifest.json);
  [Native rename/comment
  matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix);
  [Metadata
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-metadata-01/manifest.json);
  [Captured move and Trash
  outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes);
  [Native move
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-move-01/manifest.json);
  [Captured native news
  contracts](news-contracts.md#captured-category-versions-and-header-metadata);
  [Native news
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-01/manifest.json);
  [Captured article
  deletion](news-contracts.md#captured-article-deletion-and-index-effects);
  [Article deletion
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01/manifest.json);
  [Repeatable deletion
  workflow](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures);
  [Captured child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary);
  [Captured account
  replacements](native-wire-details.md#captured-account-replacement-and-password-boundaries);
  [Native account update
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-update-01/manifest.json);
  [Repeatable account update
  workflow](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries);
  [Live account events and
  restart](native-wire-details.md#captured-live-account-changes-and-server-restart);
  [Native live account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-live-accounts-01/manifest.json);
  [Repeatable live/restart
  workflow](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart);
  [Captured batch account
  rules](operation-contracts.md#captured-batch-account-framing-and-partial-effects);
  [Native batch account
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01/manifest.json);
  [Repeatable batch
  workflow](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects);
  [Captured identity/protection
  contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts);
  [Native identity
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-account-identity-01/manifest.json);
  [Repeatable identity
  workflow](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts);
  [Native room
  contract](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes);
  [Native room
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-rooms-01/manifest.json);
  [Repeatable room
  workflow](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures);
  [Native diagnostic replies](diagnostic-replies.md); [Native diagnostic
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-diagnostics-01/manifest.json);
  [Second delegated investigation](failure-representatives.md); [Second
  delegated investigation](runtime-recovery-20261113.md); [Second delegated
  investigation](diagnostic-transfer-boundaries.md); [First Classic peer
  session](mac-peer-first-session.md); [Active and queued native
  diagnostic](native-diagnostic-existing-witness.md); [Identified peer
  core-session fixtures](mac-peer-isolated-session.md); [Native board fixture
  preparation](native-board-preparation.md); [Aborted pre-contact board
  lab](native-board-readiness-failure.md); [Receipt-builder workflow and
  limits](../mothra/docs/native-capture-receipt.md)
- **Closure:** Native core-session fixtures and identified shx captures retain
  decoded/events results, reproducible runners, pinned identities and matched
  host/guest packet provenance. The isolated Classic session additionally
  checks login/agreement/roster and banner transfer bytes across three capture
  views, with a finite quiet interval and explicit UI limitation. This
  satisfies the original core-session fixture criterion; wider operation
  support and release selection remain separate requirements.

### GAP-085

#### mxd implementation and test evidence

- **Tracking:** P2; Evidence; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Historical reported mxd
  test
  coverage](internal-compatibility-matrix.md#historical-reported-mxd-test-coverage)
  (snapshot lines 172–199); [internal-compatibility-matrix.md — Open
  compatibility gaps and QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 324–360)
- **Question:** Do the named test/source references exist and pass at a
  recorded mxd revision, and do their assertions match the corrected protocol?
- **Implementation impact:** The matrix cannot claim supported implementation
  from unexecuted citations that may encode old assumptions.
- **Close when:** Record checkout/revision, reviewed assertions, commands and
  outputs; fix or retire stale expectations and map passing cases to protocol
  requirements.
- **Prior ledger entries:** M008, M009
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-001](#gap-001)
- **Progress:** Reviewed frozen source/assertions and executed 55 focused mxd
  tests at 2e4c9c1df20b37a6f98a1369e0a8f09f9ee2a131. Disputed
  classifier/login-extra expectations still pass and require implementation
  reconciliation; no false native-conformance claim is made. Native child
  append has an observed list/index inconsistency. Documenting it does not
  require reproducing it in mxd; actual checkout/test reconciliation and a
  separate compatibility policy remain required. At unchanged 2e4c9c1, four
  focused locked/offline commands pass 55 tests. Fourteen frozen source
  snapshots and optional live-source checks preserve portability. The
  assertion map identifies stale sub-version classification, login-extra
  omission, configured-name assumptions and type 107 versus native type 0
  routing. No Rust correction was made; implementation reconciliation remains
  open. The portable uncommitted mxd patch and base/final snapshots document a
  logical/physical framing correction with44 focused passing tests. Full make
  test remains blocked at linking; no canonical Rust change or complete
  implementation reconciliation is claimed. Canonical mxd commits
  50360beb/48129491 fix the demonstrated logical/physical reassembly bug and
  an independently diagnosed watchdog test assumption. All seven nextest
  profiles and both doctest commands passed, retaining one skip/four ignores;
  source bytes match the supervised fast-forward. Other stale
  classifier/login-extra/routing assertions and requirement mappings remain
  open. User instruction13November2026: further mxd validation/fixes are on
  hold; consolidate completed evidence in mxd-validation.md. Canonical
  sourcecb907 has accepted framing/directACK/loginextras corrections. Actual
  Classic authenticates with fully transmitted24-byte fixture secret but waits
  for missing agreement handoff; no121/300/212 follows. This is partial
  startup, not release or complete compatibility evidence.
- **Evidence:** [Operation contracts](operation-contracts.md); [Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1); [Captured
  child append
  boundary](news-contracts.md#captured-child-append-boundary-and-indexed-orphan);
  [Native boundary
  corpus](../mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01/manifest.json);
  [Repeatable boundary
  workflow](native-capture-workflow.md#reproducing-the-child-append-boundary);
  [Pinned mxd reconciliation](mxd-reconciliation.md); [Frozen mxd source and
  test
  evidence](../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json);
  [Second delegated investigation](mxd-limit-contracts.md); [Accepted mxd
  correction](../mothra/evidence/gap-remediation/2026-11-13/mxd-correction-01/manifest.json);
  [mxd validation findings and hold](mxd-validation.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

### GAP-086

#### Release/proof acceptance criteria

- **Tracking:** P2; Decision; Investigating; owner: Protocol documentation
  investigation.
- **Sources:** [internal-compatibility-matrix.md — Open compatibility gaps and
  QA
  requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)
  (snapshot lines 324–360); [internal-compatibility-matrix.md — Scope and
  status labels](internal-compatibility-matrix.md#scope-and-status-labels)
  (snapshot lines 15–34); [baseline-correction-map.md — Baseline correction
  map](baseline-correction-map.md#baseline-correction-map) (snapshot lines
  1–112)
- **Question:** What protocol subset, remaining-gap policy, client coverage
  and proof/test evidence are required for QA sign-off, and are the cited
  roadmap/proof items current?
- **Implementation impact:** Neither an old roadmap pointer nor a correction
  disposition defines a release acceptance threshold.
- **Close when:** Publish current sign-off criteria and owners at an
  identified revision, including deferred gaps and the scope/results of any
  Kani claims.
- **Prior ledger entries:** M008, M009, V001
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** [GAP-001](#gap-001), [GAP-080](#gap-080),
  [GAP-084](#gap-084), [GAP-085](#gap-085)
- **Progress:** Reviewed the actual release checklist, checked roadmap
  statuses and bounded Kani harness source at the recorded revision. Kani was
  not run; release owner, native acceptance criteria and deliberate-deviation
  decisions remain open. Current release/checklist, stale compatibility matrix
  and unrun Kani policy assertions are mapped to exact frozen sources. No
  release owner, subset, deferred-gap rule or proof result is invented; those
  decisions remain open. A complete managed quality gate now has retained
  successful oneshot properties, exact source snapshots and offline acceptance
  replay at mxd 48129491. Recorded skips/ignores are explicit; no Kani proof
  was run and release-owner/subset decisions remain unmet. User
  instruction13November2026: further mxd validation/fixes are on hold;
  consolidate completed evidence in mxd-validation.md. Canonical sourcecb907
  has accepted framing/directACK/loginextras corrections. Actual Classic
  authenticates with fully transmitted24-byte fixture secret but waits for
  missing agreement handoff; no121/300/212 follows. This is partial startup,
  not release or complete compatibility evidence.
- **Evidence:** [Operation contracts](operation-contracts.md); [Compatibility
  review](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1); [Pinned mxd
  reconciliation](mxd-reconciliation.md); [Frozen mxd source and test
  evidence](../mothra/evidence/gap-remediation/2026-11-13/delegated-mxd-01/manifest.json);
  [Accepted mxd
  correction](../mothra/evidence/gap-remediation/2026-11-13/mxd-correction-01/manifest.json);
  [mxd validation findings and hold](mxd-validation.md)
- **Closure:** Not closed: remaining acceptance evidence is listed above.

## Documentation provenance

### GAP-087

#### Portable, versioned evidence and document references

- **Tracking:** P2; Missing; Resolved; owner: Protocol documentation
  investigation.
- **Sources:** [protocol.md — References and Correction
  Traceability](protocol.md#references-and-correction-traceability) (snapshot
  lines 1272–1313); [baseline-correction-map.md — Baseline correction
  map](baseline-correction-map.md#baseline-correction-map) (snapshot lines
  1–112); [internal-compatibility-matrix.md — Scope and status
  labels](internal-compatibility-matrix.md#scope-and-status-labels) (snapshot
  lines 15–34)
- **Question:** How will readers obtain the sibling mothra evidence, identify
  the corrected uncommitted document revision and follow stable claim/line
  references after edits?
- **Implementation impact:** Working sibling-relative links and an old Git
  HEAD are not sufficient to reproduce a published baseline in another
  checkout.
- **Close when:** Publish or package the hashed evidence and corrected docs
  with stable revision/artifact references; retain historical snapshots and
  define gap refresh/closure rules.
- **Prior ledger entries:** V001, M008, M009
- **Investigation leads:** Needs peer/source/project evidence or an explicit
  policy decision.
- **Depends on:** No prerequisite recorded.
- **Evidence:** [Portable export and refresh
  procedure](evidence-portability.md); [Full source revisions and artifact
  hashes](../mothra/evidence/gap-remediation/2026-11-12/package-review/export-manifest.json);
  [Fresh extraction
  verification](../mothra/evidence/gap-remediation/2026-11-12/package-review/verification.json);
  [Verification
  log](../mothra/evidence/gap-remediation/2026-11-12/package-review/verification.log)
- **Closure:** Packaged both committed repositories with stable full
  revisions, artifact SHA256 values and intact sibling paths. Fresh extraction
  passed22 outer/nested hash and baseline/current-document verification
  commands. Historical snapshots remain immutable, and documented stable-ID
  refresh/closure rules are enforced by the renderer. No external publication
  or native runtime conformance is implied.

## Sweep coverage

Every heading/text block in the listed input documents was reviewed.
Parent-section rows include gaps in their child sections. A section without a
new local gap is associated with the applicable shared schema/fixture
question. This table records documentation coverage, not exhaustive coverage
of binary paths, clients or packet inputs.

| Document | Section | Snapshot lines | Related gaps |
| --- | --- | --- | --- |
| protocol.md | [Hotline Server Protocol 1.9: Transactions and Functionality Guide](protocol.md#hotline-server-protocol-19-transactions-and-functionality-guide) | 1–34 | 83 gaps; see section-specific rows and JSON register |
| protocol.md | [Binary Message Formats (Hotline Protocol 1.9)](protocol.md#binary-message-formats-hotline-protocol-19) | 35–42 | 23 gaps; see section-specific rows and JSON register |
| protocol.md | [1 Session-initialization handshake](protocol.md#1-session-initialization-handshake) | 43–87 | [GAP-005](#gap-005), [GAP-007](#gap-007), [GAP-008](#gap-008), [GAP-009](#gap-009) |
| protocol.md | [2 General transaction frame](protocol.md#2-general-transaction-frame) | 88–114 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [2.1 Parameter list (payload block)](protocol.md#21-parameter-list-payload-block) | 115–161 | [GAP-002](#gap-002), [GAP-014](#gap-014), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-019](#gap-019), [GAP-024](#gap-024) |
| protocol.md | [2.2 Date parameters](protocol.md#22-date-parameters) | 162–184 | [GAP-020](#gap-020) |
| protocol.md | [3 Fragmentation rules](protocol.md#3-fragmentation-rules) | 185–214 | [GAP-004](#gap-004), [GAP-011](#gap-011), [GAP-012](#gap-012), [GAP-014](#gap-014) |
| protocol.md | [4 Reply semantics](protocol.md#4-reply-semantics) | 215–239 | [GAP-003](#gap-003), [GAP-005](#gap-005), [GAP-006](#gap-006), [GAP-013](#gap-013), [GAP-021](#gap-021) |
| protocol.md | [5 Worked example (Login)](protocol.md#5-worked-example-login) | 240–274 | [GAP-016](#gap-016), [GAP-022](#gap-022), [GAP-084](#gap-084) |
| protocol.md | [6 Implementation checklist](protocol.md#6-implementation-checklist) | 275–289 | [GAP-084](#gap-084) |
| protocol.md | [User Login and Presence](protocol.md#user-login-and-presence) | 290–291 | 25 gaps; see section-specific rows and JSON register |
| protocol.md | [Session Handshake (Before Transactions Begin)](protocol.md#session-handshake-before-transactions-begin) | 292–299 | [GAP-007](#gap-007), [GAP-008](#gap-008) |
| protocol.md | [Login (Transaction 107) – Client Initiates](protocol.md#login-transaction-107--client-initiates) | 300–351 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [Server Agreement (Transaction 109) – Server Initiates](protocol.md#server-agreement-transaction-109--server-initiates) | 352–386 | [GAP-025](#gap-025), [GAP-027](#gap-027) |
| protocol.md | [Agreement Acceptance (Transaction 121) – Client Initiates](protocol.md#agreement-acceptance-transaction-121--client-initiates) | 387–415 | [GAP-007](#gap-007), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-029](#gap-029), [GAP-030](#gap-030) |
| protocol.md | [Banner Metadata (Transaction 122) – Server Initiates](protocol.md#banner-metadata-transaction-122--server-initiates) | 416–430 | [GAP-028](#gap-028), [GAP-063](#gap-063) |
| protocol.md | [User Access Privileges (Transaction 354) – Server Initiates](protocol.md#user-access-privileges-transaction-354--server-initiates) | 431–439 | [GAP-031](#gap-031), [GAP-032](#gap-032), [GAP-073](#gap-073) |
| protocol.md | [Access Privilege Bits (Field 110)](protocol.md#access-privilege-bits-field-110) | 440–478 | [GAP-031](#gap-031), [GAP-032](#gap-032) |
| protocol.md | [Retrieving the User List (Transaction 300) – Client Initiates](protocol.md#retrieving-the-user-list-transaction-300--client-initiates) | 479–511 | [GAP-033](#gap-033), [GAP-034](#gap-034), [GAP-035](#gap-035) |
| protocol.md | [User Appearance and Updates (Transaction 301 & 302) – Server Initiates](protocol.md#user-appearance-and-updates-transaction-301--302--server-initiates) | 512–530 | [GAP-034](#gap-034), [GAP-035](#gap-035), [GAP-036](#gap-036) |
| protocol.md | [Viewing User Info (Transaction 303) – Client Initiates](protocol.md#viewing-user-info-transaction-303--client-initiates) | 531–541 | [GAP-037](#gap-037) |
| protocol.md | [Changing User Settings (Transaction 304) – Client Initiates](protocol.md#changing-user-settings-transaction-304--client-initiates) | 542–575 | [GAP-006](#gap-006), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-029](#gap-029), [GAP-030](#gap-030), [GAP-045](#gap-045) |
| protocol.md | [Chat (Public and Private Chat Rooms)](protocol.md#chat-public-and-private-chat-rooms) | 576–577 | 13 gaps; see section-specific rows and JSON register |
| protocol.md | [Sending a Chat Message (Transaction 105) – Client Initiates](protocol.md#sending-a-chat-message-transaction-105--client-initiates) | 578–589 | [GAP-006](#gap-006), [GAP-019](#gap-019), [GAP-038](#gap-038), [GAP-042](#gap-042), [GAP-044](#gap-044), [GAP-045](#gap-045) |
| protocol.md | [Receiving a Chat Message (Transaction 106) – Server Initiates](protocol.md#receiving-a-chat-message-transaction-106--server-initiates) | 590–599 | [GAP-018](#gap-018), [GAP-042](#gap-042) |
| protocol.md | [Joining a Chat Room (Transaction 115) – Client Initiates](protocol.md#joining-a-chat-room-transaction-115--client-initiates) | 600–611 | [GAP-038](#gap-038), [GAP-040](#gap-040) |
| protocol.md | [Leaving a Chat Room (Transaction 116) – Client Initiates](protocol.md#leaving-a-chat-room-transaction-116--client-initiates) | 612–621 | [GAP-006](#gap-006), [GAP-036](#gap-036), [GAP-040](#gap-040) |
| protocol.md | [Chat Room Notifications (Transactions 117 & 118) – Server Initiates](protocol.md#chat-room-notifications-transactions-117--118--server-initiates) | 622–633 | [GAP-040](#gap-040) |
| protocol.md | [Chat Invitations (Transactions 112, 113, 114) – Private Chats](protocol.md#chat-invitations-transactions-112-113-114--private-chats) | 634–655 | [GAP-017](#gap-017), [GAP-033](#gap-033), [GAP-038](#gap-038), [GAP-039](#gap-039) |
| protocol.md | [Chat Subject Management (Transactions 119 & 120)](protocol.md#chat-subject-management-transactions-119--120) | 656–664 | [GAP-041](#gap-041) |
| protocol.md | [Private Messaging (Instant Messages)](protocol.md#private-messaging-instant-messages) | 665–666 | [GAP-021](#gap-021), [GAP-030](#gap-030), [GAP-043](#gap-043), [GAP-044](#gap-044), [GAP-045](#gap-045), [GAP-046](#gap-046) |
| protocol.md | [Sending an Instant Message (Transaction 108) – Client Initiates](protocol.md#sending-an-instant-message-transaction-108--client-initiates) | 667–699 | [GAP-021](#gap-021), [GAP-030](#gap-030), [GAP-043](#gap-043), [GAP-045](#gap-045) |
| protocol.md | [Receiving a Private Message (Transaction 104) – Server Initiates](protocol.md#receiving-a-private-message-transaction-104--server-initiates) | 700–717 | [GAP-044](#gap-044) |
| protocol.md | [Legacy Message Board (Transactions 101, 102, 103)](protocol.md#legacy-message-board-transactions-101-102-103) | 718–732 | [GAP-046](#gap-046) |
| protocol.md | [File Services (Files and Folders)](protocol.md#file-services-files-and-folders) | 733–747 | 25 gaps; see section-specific rows and JSON register |
| protocol.md | [Listing Files in a Folder (Transaction 200) – Client Initiates](protocol.md#listing-files-in-a-folder-transaction-200--client-initiates) | 748–760 | [GAP-018](#gap-018), [GAP-047](#gap-047), [GAP-048](#gap-048) |
| protocol.md | [Downloading a File (Transaction 202) – Client Initiates](protocol.md#downloading-a-file-transaction-202--client-initiates) | 761–788 | [GAP-015](#gap-015), [GAP-056](#gap-056), [GAP-057](#gap-057), [GAP-058](#gap-058), [GAP-061](#gap-061) |
| protocol.md | [Uploading a File (Transaction 203) – Client Initiates](protocol.md#uploading-a-file-transaction-203--client-initiates) | 789–803 | [GAP-056](#gap-056), [GAP-058](#gap-058) |
| protocol.md | [Deleting a File (Transaction 204) – Client Initiates](protocol.md#deleting-a-file-transaction-204--client-initiates) | 804–818 | [GAP-050](#gap-050) |
| protocol.md | [Creating a New Folder (Transaction 205) – Client Initiates](protocol.md#creating-a-new-folder-transaction-205--client-initiates) | 819–836 | [GAP-051](#gap-051) |
| protocol.md | [Getting File/Folder Info (Transaction 206) – Client Initiates](protocol.md#getting-filefolder-info-transaction-206--client-initiates) | 837–854 | [GAP-049](#gap-049) |
| protocol.md | [Setting File/Folder Info (Transaction 207) – Client Initiates](protocol.md#setting-filefolder-info-transaction-207--client-initiates) | 855–873 | [GAP-052](#gap-052) |
| protocol.md | [Moving Files/Folders (Transaction 208) – Client Initiates](protocol.md#moving-filesfolders-transaction-208--client-initiates) | 874–886 | [GAP-047](#gap-047), [GAP-053](#gap-053) |
| protocol.md | [Creating an Alias (Shortcut) (Transaction 209) – Client Initiates](protocol.md#creating-an-alias-shortcut-transaction-209--client-initiates) | 887–900 | [GAP-054](#gap-054) |
| protocol.md | [Downloading an Entire Folder (Transaction 210) – Client Initiates](protocol.md#downloading-an-entire-folder-transaction-210--client-initiates) | 901–918 | [GAP-059](#gap-059), [GAP-061](#gap-061) |
| protocol.md | [Uploading an Entire Folder (Transaction 213) – Client Initiates](protocol.md#uploading-an-entire-folder-transaction-213--client-initiates) | 919–936 | [GAP-060](#gap-060), [GAP-064](#gap-064) |
| protocol.md | [Banner Download (Transaction 212) – Client Initiates](protocol.md#banner-download-transaction-212--client-initiates) | 937–954 | [GAP-028](#gap-028), [GAP-055](#gap-055), [GAP-063](#gap-063) |
| protocol.md | [Transfer Connection and Reference Cleanup](protocol.md#transfer-connection-and-reference-cleanup) | 955–974 | [GAP-009](#gap-009), [GAP-010](#gap-010), [GAP-033](#gap-033), [GAP-055](#gap-055), [GAP-056](#gap-056), [GAP-062](#gap-062), [GAP-064](#gap-064) |
| protocol.md | [News (Bulletin Board System)](protocol.md#news-bulletin-board-system) | 975–976 | 10 gaps; see section-specific rows and JSON register |
| protocol.md | [News Hierarchy](protocol.md#news-hierarchy) | 977–985 | [GAP-065](#gap-065), [GAP-070](#gap-070) |
| protocol.md | [Listing News Categories (Transaction 370) – Client Initiates](protocol.md#listing-news-categories-transaction-370--client-initiates) | 986–1003 | [GAP-047](#gap-047), [GAP-065](#gap-065) |
| protocol.md | [Listing News Articles (Transaction 371) – Client Initiates](protocol.md#listing-news-articles-transaction-371--client-initiates) | 1004–1018 | [GAP-066](#gap-066) |
| protocol.md | [Reading a News Article (Transaction 400) – Client Initiates](protocol.md#reading-a-news-article-transaction-400--client-initiates) | 1019–1047 | [GAP-020](#gap-020), [GAP-067](#gap-067) |
| protocol.md | [Posting a News Article (Transaction 410) – Client Initiates](protocol.md#posting-a-news-article-transaction-410--client-initiates) | 1048–1069 | [GAP-021](#gap-021), [GAP-068](#gap-068) |
| protocol.md | [Deleting a News Article (Transaction 411) – Client Initiates](protocol.md#deleting-a-news-article-transaction-411--client-initiates) | 1070–1086 | [GAP-069](#gap-069) |
| protocol.md | [Managing News Structure (Transactions 380, 381, 382) – Client Initiates (Admin/Mods)](protocol.md#managing-news-structure-transactions-380-381-382--client-initiates-adminmods) | 1087–1103 | [GAP-032](#gap-032), [GAP-070](#gap-070) |
| protocol.md | [Administrative Functions](protocol.md#administrative-functions) | 1104–1105 | 17 gaps; see section-specific rows and JSON register |
| protocol.md | [User Account Management – Client Initiates (Admin) (Tx 350–353)](protocol.md#user-account-management--client-initiates-admin-tx-350353) | 1106–1153 | 9 gaps; see section-specific rows and JSON register |
| protocol.md | [Disconnecting a User (Transaction 110 & 111) – Admin/Server Use](protocol.md#disconnecting-a-user-transaction-110--111--adminserver-use) | 1154–1199 | [GAP-003](#gap-003), [GAP-036](#gap-036), [GAP-044](#gap-044), [GAP-074](#gap-074), [GAP-075](#gap-075) |
| protocol.md | [Broadcasting a Message (Transaction 355) – Admin/Server Initiated](protocol.md#broadcasting-a-message-transaction-355--adminserver-initiated) | 1200–1214 | [GAP-045](#gap-045), [GAP-076](#gap-076) |
| protocol.md | [Additional Admin Privileges Note](protocol.md#additional-admin-privileges-note) | 1215–1223 | [GAP-038](#gap-038), [GAP-073](#gap-073) |
| protocol.md | [Additional Observed Requests and Scope Gaps](protocol.md#additional-observed-requests-and-scope-gaps) | 1224–1271 | [GAP-005](#gap-005), [GAP-007](#gap-007), [GAP-075](#gap-075), [GAP-077](#gap-077), [GAP-078](#gap-078), [GAP-079](#gap-079) |
| protocol.md | [References and Correction Traceability](protocol.md#references-and-correction-traceability) | 1272–1313 | [GAP-083](#gap-083), [GAP-087](#gap-087) |
| internal-compatibility-matrix.md | [Internal compatibility matrix (Hotline and SynHX)](internal-compatibility-matrix.md#internal-compatibility-matrix-hotline-and-synhx) | 1–14 | 13 gaps; see section-specific rows and JSON register |
| internal-compatibility-matrix.md | [Scope and status labels](internal-compatibility-matrix.md#scope-and-status-labels) | 15–34 | [GAP-086](#gap-086), [GAP-087](#gap-087) |
| internal-compatibility-matrix.md | [Compatibility matrix](internal-compatibility-matrix.md#compatibility-matrix) | 35–62 | [GAP-024](#gap-024), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-083](#gap-083) |
| internal-compatibility-matrix.md | [Login reply and banner policy](internal-compatibility-matrix.md#login-reply-and-banner-policy) | 63–111 | [GAP-026](#gap-026), [GAP-081](#gap-081) |
| internal-compatibility-matrix.md | [Credential obfuscation and text compatibility](internal-compatibility-matrix.md#credential-obfuscation-and-text-compatibility) | 112–139 | [GAP-018](#gap-018), [GAP-022](#gap-022), [GAP-082](#gap-082) |
| internal-compatibility-matrix.md | [Repeated fields and presence records](internal-compatibility-matrix.md#repeated-fields-and-presence-records) | 140–171 | [GAP-017](#gap-017), [GAP-034](#gap-034), [GAP-035](#gap-035), [GAP-081](#gap-081) |
| internal-compatibility-matrix.md | [Historical reported mxd test coverage](internal-compatibility-matrix.md#historical-reported-mxd-test-coverage) | 172–199 | [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [mxd review at 2e4c9c1](internal-compatibility-matrix.md#mxd-review-at-2e4c9c1) | 200–222 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| internal-compatibility-matrix.md | [Assertions requiring protocol reconciliation](internal-compatibility-matrix.md#assertions-requiring-protocol-reconciliation) | 223–238 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [Exact current text heuristic](internal-compatibility-matrix.md#exact-current-text-heuristic) | 239–259 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-082](#gap-082), [GAP-085](#gap-085) |
| internal-compatibility-matrix.md | [Proof and QA limits](internal-compatibility-matrix.md#proof-and-qa-limits) | 260–274 | [GAP-001](#gap-001), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| internal-compatibility-matrix.md | [Newly identified client source evidence](internal-compatibility-matrix.md#newly-identified-client-source-evidence) | 275–289 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083) |
| internal-compatibility-matrix.md | [Historical source lineage and build limits](internal-compatibility-matrix.md#historical-source-lineage-and-build-limits) | 290–323 | [GAP-083](#gap-083) |
| internal-compatibility-matrix.md | [Open compatibility gaps and QA requirements](internal-compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements) | 324–360 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-084](#gap-084), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| baseline-correction-map.md | [Baseline correction map](baseline-correction-map.md#baseline-correction-map) | 1–112 | [GAP-086](#gap-086), [GAP-087](#gap-087) |
| native-wire-details.md | [Hotline 1.9 native wire details](native-wire-details.md#hotline-19-native-wire-details) | 1–8 | 13 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Parameter parsing and scalar access](native-wire-details.md#parameter-parsing-and-scalar-access) | 9–35 | [GAP-014](#gap-014), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-018](#gap-018), [GAP-019](#gap-019) |
| native-wire-details.md | [Captured TLV and scalar boundaries](native-wire-details.md#captured-tlv-and-scalar-boundaries) | 36–73 | [GAP-014](#gap-014), [GAP-015](#gap-015), [GAP-017](#gap-017), [GAP-084](#gap-084) |
| native-wire-details.md | [Credential bytes, lookup and account updates](native-wire-details.md#credential-bytes-lookup-and-account-updates) | 74–93 | [GAP-016](#gap-016), [GAP-018](#gap-018), [GAP-019](#gap-019), [GAP-022](#gap-022), [GAP-023](#gap-023), [GAP-071](#gap-071), [GAP-072](#gap-072), [GAP-073](#gap-073) |
| native-wire-details.md | [Account record and field schema](native-wire-details.md#account-record-and-field-schema) | 94–138 | [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-071](#gap-071), [GAP-072](#gap-072) |
| native-wire-details.md | [Account lookup name encodings](native-wire-details.md#account-lookup-name-encodings) | 139–158 | [GAP-022](#gap-022), [GAP-071](#gap-071), [GAP-072](#gap-072) |
| native-wire-details.md | [Login lookup transformations](native-wire-details.md#login-lookup-transformations) | 159–173 | [GAP-018](#gap-018), [GAP-022](#gap-022), [GAP-023](#gap-023) |
| native-wire-details.md | [Captured login lookup and guest phases](native-wire-details.md#captured-login-lookup-and-guest-phases) | 174–214 | [GAP-023](#gap-023), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-035](#gap-035), [GAP-036](#gap-036), [GAP-084](#gap-084) |
| native-wire-details.md | [Changes to connected accounts](native-wire-details.md#changes-to-connected-accounts) | 215–224 | [GAP-073](#gap-073) |
| native-wire-details.md | [Structured file paths and file-list entries](native-wire-details.md#structured-file-paths-and-file-list-entries) | 225–269 | [GAP-047](#gap-047), [GAP-048](#gap-048) |
| native-wire-details.md | [Captured listing kinds and enumeration order](native-wire-details.md#captured-listing-kinds-and-enumeration-order) | 270–300 | 9 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Captured field 202 directory-creation boundaries](native-wire-details.md#captured-field-202-directory-creation-boundaries) | 301–312 | 11 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Privilege access and connection timers](native-wire-details.md#privilege-access-and-connection-timers) | 313–368 | [GAP-005](#gap-005), [GAP-031](#gap-031), [GAP-032](#gap-032), [GAP-045](#gap-045) |
| native-wire-details.md | [Captured agreement configurations and partial login failures](native-wire-details.md#captured-agreement-configurations-and-partial-login-failures) | 369–444 | [GAP-003](#gap-003), [GAP-019](#gap-019), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-084](#gap-084) |
| native-wire-details.md | [Captured login extras, configuration bytes and refresh](native-wire-details.md#captured-login-extras-configuration-bytes-and-refresh) | 445–509 | [GAP-005](#gap-005), [GAP-018](#gap-018), [GAP-019](#gap-019), [GAP-026](#gap-026), [GAP-084](#gap-084) |
| native-wire-details.md | [Captured account replacement and password boundaries](native-wire-details.md#captured-account-replacement-and-password-boundaries) | 510–576 | 9 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Captured live account changes and server restart](native-wire-details.md#captured-live-account-changes-and-server-restart) | 577–672 | 9 gaps; see section-specific rows and JSON register |
| native-wire-details.md | [Captured account identity and protection contrasts](native-wire-details.md#captured-account-identity-and-protection-contrasts) | 673–726 | [GAP-003](#gap-003), [GAP-018](#gap-018), [GAP-021](#gap-021), [GAP-031](#gap-031), [GAP-036](#gap-036), [GAP-072](#gap-072), [GAP-074](#gap-074), [GAP-084](#gap-084) |
| operation-contracts.md | [Native operation and session dispatch contracts](operation-contracts.md#native-operation-and-session-dispatch-contracts) | 1–8 | 12 gaps; see section-specific rows and JSON register |
| operation-contracts.md | [Session eligibility and invalid transitions](operation-contracts.md#session-eligibility-and-invalid-transitions) | 9–29 | [GAP-003](#gap-003), [GAP-007](#gap-007), [GAP-025](#gap-025), [GAP-079](#gap-079) |
| operation-contracts.md | [Request catalogue](operation-contracts.md#request-catalogue) | 30–86 | [GAP-002](#gap-002), [GAP-006](#gap-006), [GAP-021](#gap-021) |
| operation-contracts.md | [Per-operation reply and fan-out map](operation-contracts.md#per-operation-reply-and-fan-out-map) | 87–150 | [GAP-006](#gap-006), [GAP-003](#gap-003), [GAP-084](#gap-084) |
| operation-contracts.md | [Server notification catalogue](operation-contracts.md#server-notification-catalogue) | 151–175 | [GAP-006](#gap-006), [GAP-036](#gap-036), [GAP-044](#gap-044), [GAP-061](#gap-061), [GAP-075](#gap-075) |
| operation-contracts.md | [Frame acceptance and reassembly boundaries](operation-contracts.md#frame-acceptance-and-reassembly-boundaries) | 176–198 | [GAP-004](#gap-004), [GAP-011](#gap-011), [GAP-012](#gap-012), [GAP-013](#gap-013) |
| operation-contracts.md | [Administrative account list and batch mutation](operation-contracts.md#administrative-account-list-and-batch-mutation) | 199–231 | [GAP-021](#gap-021), [GAP-072](#gap-072), [GAP-077](#gap-077), [GAP-078](#gap-078) |
| operation-contracts.md | [Captured batch account framing and partial effects](operation-contracts.md#captured-batch-account-framing-and-partial-effects) | 232–306 | 11 gaps; see section-specific rows and JSON register |
| operation-contracts.md | [Rename collision does not preserve the destination account](operation-contracts.md#rename-collision-does-not-preserve-the-destination-account) | 307–344 | 11 gaps; see section-specific rows and JSON register |
| operation-contracts.md | [Account deletion and allocated Trash records](operation-contracts.md#account-deletion-and-allocated-trash-records) | 345–358 | [GAP-072](#gap-072), [GAP-021](#gap-021) |
| transfer-contracts.md | [Native transfer contracts](transfer-contracts.md#native-transfer-contracts) | 1–16 | 9 gaps; see section-specific rows and JSON register |
| transfer-contracts.md | [HTXF connection header and dispatch](transfer-contracts.md#htxf-connection-header-and-dispatch) | 17–57 | [GAP-055](#gap-055) |
| transfer-contracts.md | [Captured HTXF field and reference cases](transfer-contracts.md#captured-htxf-field-and-reference-cases) | 58–118 | [GAP-033](#gap-033), [GAP-055](#gap-055), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Reference allocation and request 214](transfer-contracts.md#reference-allocation-and-request-214) | 119–162 | [GAP-033](#gap-033), [GAP-062](#gap-062) |
| transfer-contracts.md | [Captured cancellation and completion races](transfer-contracts.md#captured-cancellation-and-completion-races) | 163–208 | [GAP-062](#gap-062), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Buffered receipt and packet ordering](transfer-contracts.md#buffered-receipt-and-packet-ordering) | 209–224 | [GAP-062](#gap-062), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Resume data: RFLT](transfer-contracts.md#resume-data-rflt) | 225–259 | [GAP-058](#gap-058) |
| transfer-contracts.md | [Captured RFLT download boundaries](transfer-contracts.md#captured-rflt-download-boundaries) | 260–307 | [GAP-058](#gap-058), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured upload continuation and inconsistent state](transfer-contracts.md#captured-upload-continuation-and-inconsistent-state) | 308–344 | [GAP-058](#gap-058), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Flattened ordinary-file stream](transfer-contracts.md#flattened-ordinary-file-stream) | 345–374 | [GAP-056](#gap-056), [GAP-057](#gap-057) |
| transfer-contracts.md | [INFO metadata value](transfer-contracts.md#info-metadata-value) | 375–402 | [GAP-020](#gap-020), [GAP-056](#gap-056) |
| transfer-contracts.md | [INFO restoration after upload](transfer-contracts.md#info-restoration-after-upload) | 403–424 | [GAP-020](#gap-020), [GAP-056](#gap-056), [GAP-064](#gap-064) |
| transfer-contracts.md | [Upload consumption and completion](transfer-contracts.md#upload-consumption-and-completion) | 425–441 | [GAP-056](#gap-056), [GAP-064](#gap-064) |
| transfer-contracts.md | [Queue notification 211](transfer-contracts.md#queue-notification-211) | 442–458 | [GAP-061](#gap-061) |
| transfer-contracts.md | [Captured controlled queues](transfer-contracts.md#captured-controlled-queues) | 459–516 | [GAP-057](#gap-057), [GAP-061](#gap-061), [GAP-062](#gap-062), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured pending-reference timeout](transfer-contracts.md#captured-pending-reference-timeout) | 517–543 | [GAP-061](#gap-061), [GAP-084](#gap-084) |
| transfer-contracts.md | [Banner bytes and worker timers](transfer-contracts.md#banner-bytes-and-worker-timers) | 544–566 | [GAP-005](#gap-005), [GAP-063](#gap-063), [GAP-064](#gap-064) |
| transfer-contracts.md | [Captured ordinary-file round trips](transfer-contracts.md#captured-ordinary-file-round-trips) | 567–612 | [GAP-009](#gap-009), [GAP-055](#gap-055), [GAP-056](#gap-056), [GAP-057](#gap-057), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured completion and EOF behaviour](transfer-contracts.md#captured-completion-and-eof-behaviour) | 613–638 | [GAP-062](#gap-062), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Transfer timer origins and resets](transfer-contracts.md#transfer-timer-origins-and-resets) | 639–670 | [GAP-005](#gap-005), [GAP-059](#gap-059), [GAP-060](#gap-060), [GAP-061](#gap-061), [GAP-064](#gap-064) |
| transfer-contracts.md | [Folder-download control states](transfer-contracts.md#folder-download-control-states) | 671–691 | [GAP-059](#gap-059) |
| transfer-contracts.md | [Folder item descriptor bytes](transfer-contracts.md#folder-item-descriptor-bytes) | 692–725 | [GAP-047](#gap-047), [GAP-059](#gap-059), [GAP-060](#gap-060) |
| transfer-contracts.md | [Captured folder downloads](transfer-contracts.md#captured-folder-downloads) | 726–769 | [GAP-059](#gap-059), [GAP-084](#gap-084) |
| transfer-contracts.md | [Folder-upload control states](transfer-contracts.md#folder-upload-control-states) | 770–806 | [GAP-060](#gap-060) |
| transfer-contracts.md | [Captured folder uploads](transfer-contracts.md#captured-folder-uploads) | 807–833 | [GAP-060](#gap-060), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured folder timing and filesystem observations](transfer-contracts.md#captured-folder-timing-and-filesystem-observations) | 834–873 | [GAP-059](#gap-059), [GAP-060](#gap-060), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured banner observations](transfer-contracts.md#captured-banner-observations) | 874–917 | [GAP-055](#gap-055), [GAP-063](#gap-063), [GAP-084](#gap-084) |
| transfer-contracts.md | [Captured banner formats and recovery](transfer-contracts.md#captured-banner-formats-and-recovery) | 918–988 | [GAP-055](#gap-055), [GAP-063](#gap-063), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| news-contracts.md | [Native nested news contracts](news-contracts.md#native-nested-news-contracts) | 1–8 | [GAP-020](#gap-020), [GAP-065](#gap-065), [GAP-066](#gap-066), [GAP-067](#gap-067), [GAP-068](#gap-068), [GAP-069](#gap-069), [GAP-070](#gap-070) |
| news-contracts.md | [Category-list variants](news-contracts.md#category-list-variants) | 9–57 | [GAP-065](#gap-065) |
| news-contracts.md | [Article-list field 321](news-contracts.md#article-list-field-321) | 58–104 | [GAP-066](#gap-066) |
| news-contracts.md | [Reading bodies and navigation](news-contracts.md#reading-bodies-and-navigation) | 105–139 | [GAP-067](#gap-067) |
| news-contracts.md | [News dates](news-contracts.md#news-dates) | 140–147 | [GAP-020](#gap-020), [GAP-067](#gap-067) |
| news-contracts.md | [Posting, partial effects and deletion](news-contracts.md#posting-partial-effects-and-deletion) | 148–170 | [GAP-021](#gap-021), [GAP-068](#gap-068), [GAP-069](#gap-069) |
| news-contracts.md | [Deletion graph rewrite](news-contracts.md#deletion-graph-rewrite) | 171–198 | [GAP-067](#gap-067), [GAP-069](#gap-069) |
| news-contracts.md | [Scope of hierarchy evidence](news-contracts.md#scope-of-hierarchy-evidence) | 199–208 | [GAP-047](#gap-047), [GAP-070](#gap-070) |
| news-contracts.md | [Structure operation effects and conflicts](news-contracts.md#structure-operation-effects-and-conflicts) | 209–272 | [GAP-021](#gap-021), [GAP-047](#gap-047), [GAP-070](#gap-070) |
| news-contracts.md | [Captured category versions and header metadata](news-contracts.md#captured-category-versions-and-header-metadata) | 273–318 | 14 gaps; see section-specific rows and JSON register |
| news-contracts.md | [Captured threaded article lists and partial posts](news-contracts.md#captured-threaded-article-lists-and-partial-posts) | 319–381 | 14 gaps; see section-specific rows and JSON register |
| news-contracts.md | [Captured hierarchy failures and owned cleanup](news-contracts.md#captured-hierarchy-failures-and-owned-cleanup) | 382–409 | 14 gaps; see section-specific rows and JSON register |
| news-contracts.md | [Captured article deletion and index effects](news-contracts.md#captured-article-deletion-and-index-effects) | 410–490 | 9 gaps; see section-specific rows and JSON register |
| news-contracts.md | [Captured child append boundary and indexed orphan](news-contracts.md#captured-child-append-boundary-and-indexed-orphan) | 491–554 | 9 gaps; see section-specific rows and JSON register |
| presence-messaging-contracts.md | [Native presence, messaging and administration contracts](presence-messaging-contracts.md#native-presence-messaging-and-administration-contracts) | 1–7 | 18 gaps; see section-specific rows and JSON register |
| presence-messaging-contracts.md | [Settings and login visibility](presence-messaging-contracts.md#settings-and-login-visibility) | 8–63 | [GAP-025](#gap-025), [GAP-029](#gap-029), [GAP-030](#gap-030), [GAP-035](#gap-035) |
| presence-messaging-contracts.md | [Settings persistence boundary](presence-messaging-contracts.md#settings-persistence-boundary) | 64–91 | [GAP-029](#gap-029) |
| presence-messaging-contracts.md | [Captured configured login states and visibility](presence-messaging-contracts.md#captured-configured-login-states-and-visibility) | 92–141 | [GAP-023](#gap-023), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-035](#gap-035), [GAP-036](#gap-036), [GAP-084](#gap-084) |
| presence-messaging-contracts.md | [Agreement and banner condition tables](presence-messaging-contracts.md#agreement-and-banner-condition-tables) | 142–163 | [GAP-026](#gap-026), [GAP-027](#gap-027), [GAP-028](#gap-028) |
| presence-messaging-contracts.md | [Early completion and metadata changes](presence-messaging-contracts.md#early-completion-and-metadata-changes) | 164–182 | [GAP-028](#gap-028), [GAP-063](#gap-063), [GAP-084](#gap-084) |
| presence-messaging-contracts.md | [Login extras and configured content](presence-messaging-contracts.md#login-extras-and-configured-content) | 183–184 | [GAP-026](#gap-026), [GAP-028](#gap-028) |
| presence-messaging-contracts.md | [Fields 160, 161 and 162](presence-messaging-contracts.md#fields-160-161-and-162) | 185–227 | [GAP-026](#gap-026) |
| presence-messaging-contracts.md | [Agreement and banner loading](presence-messaging-contracts.md#agreement-and-banner-loading) | 228–256 | [GAP-026](#gap-026), [GAP-027](#gap-027), [GAP-028](#gap-028) |
| presence-messaging-contracts.md | [Content byte limits and reload effects](presence-messaging-contracts.md#content-byte-limits-and-reload-effects) | 257–284 | [GAP-011](#gap-011), [GAP-018](#gap-018), [GAP-019](#gap-019), [GAP-027](#gap-027), [GAP-028](#gap-028) |
| presence-messaging-contracts.md | [Status word, separate from the privilege bitmap](presence-messaging-contracts.md#status-word-separate-from-the-privilege-bitmap) | 285–324 | [GAP-034](#gap-034) |
| presence-messaging-contracts.md | [Roster snapshots and concurrent updates](presence-messaging-contracts.md#roster-snapshots-and-concurrent-updates) | 325–367 | [GAP-035](#gap-035) |
| presence-messaging-contracts.md | [Disconnect teardown and notification 302](presence-messaging-contracts.md#disconnect-teardown-and-notification-302) | 368–384 | [GAP-036](#gap-036) |
| presence-messaging-contracts.md | [Private-message routing](presence-messaging-contracts.md#private-message-routing) | 385–443 | [GAP-043](#gap-043), [GAP-044](#gap-044), [GAP-045](#gap-045) |
| presence-messaging-contracts.md | [Rooms, invitations and subjects](presence-messaging-contracts.md#rooms-invitations-and-subjects) | 444–479 | [GAP-038](#gap-038), [GAP-039](#gap-039), [GAP-040](#gap-040), [GAP-041](#gap-041), [GAP-042](#gap-042) |
| presence-messaging-contracts.md | [Kick options and native console messages](presence-messaging-contracts.md#kick-options-and-native-console-messages) | 480–575 | [GAP-074](#gap-074), [GAP-075](#gap-075), [GAP-076](#gap-076) |
| presence-messaging-contracts.md | [Captured private rooms, invitations and chat bytes](presence-messaging-contracts.md#captured-private-rooms-invitations-and-chat-bytes) | 576–680 | 12 gaps; see section-specific rows and JSON register |
| presence-messaging-contracts.md | [Captured console and client broadcast recipients](presence-messaging-contracts.md#captured-console-and-client-broadcast-recipients) | 681–693 | [GAP-044](#gap-044), [GAP-076](#gap-076) |
| core-field-schemas.md | [Core transaction field schemas](core-field-schemas.md#core-transaction-field-schemas) | 1–8 | [GAP-002](#gap-002), [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017), [GAP-019](#gap-019) |
| core-field-schemas.md | [Types, occurrence and direction conventions](core-field-schemas.md#types-occurrence-and-direction-conventions) | 9–33 | [GAP-002](#gap-002), [GAP-015](#gap-015), [GAP-017](#gap-017) |
| core-field-schemas.md | [Login and settings requests](core-field-schemas.md#login-and-settings-requests) | 34–55 | [GAP-002](#gap-002), [GAP-016](#gap-016), [GAP-024](#gap-024), [GAP-029](#gap-029), [GAP-030](#gap-030) |
| core-field-schemas.md | [Captured settings-option widths and defaults](core-field-schemas.md#captured-settings-option-widths-and-defaults) | 56–66 | [GAP-085](#gap-085), [GAP-086](#gap-086) |
| core-field-schemas.md | [Login width and feature-condition matrix](core-field-schemas.md#login-width-and-feature-condition-matrix) | 67–101 | [GAP-024](#gap-024), [GAP-015](#gap-015), [GAP-025](#gap-025) |
| core-field-schemas.md | [Login and presence outputs](core-field-schemas.md#login-and-presence-outputs) | 102–121 | [GAP-002](#gap-002), [GAP-025](#gap-025), [GAP-026](#gap-026), [GAP-027](#gap-027), [GAP-028](#gap-028), [GAP-035](#gap-035), [GAP-036](#gap-036), [GAP-037](#gap-037) |
| core-field-schemas.md | [Chat, PM and room requests](core-field-schemas.md#chat-pm-and-room-requests) | 122–139 | [GAP-002](#gap-002), [GAP-038](#gap-038), [GAP-039](#gap-039), [GAP-040](#gap-040), [GAP-041](#gap-041), [GAP-042](#gap-042), [GAP-043](#gap-043) |
| core-field-schemas.md | [Room and message outputs](core-field-schemas.md#room-and-message-outputs) | 140–158 | [GAP-002](#gap-002), [GAP-044](#gap-044), [GAP-075](#gap-075), [GAP-076](#gap-076) |
| session-transport-contracts.md | [Native session and transport contracts](session-transport-contracts.md#native-session-and-transport-contracts) | 1–8 | [GAP-008](#gap-008), [GAP-009](#gap-009), [GAP-010](#gap-010), [GAP-011](#gap-011), [GAP-024](#gap-024), [GAP-033](#gap-033) |
| session-transport-contracts.md | [Configured endpoints](session-transport-contracts.md#configured-endpoints) | 9–44 | [GAP-010](#gap-010) |
| session-transport-contracts.md | [Handshake consumption and failures](session-transport-contracts.md#handshake-consumption-and-failures) | 45–66 | [GAP-008](#gap-008) |
| session-transport-contracts.md | [Captured handshake boundaries](session-transport-contracts.md#captured-handshake-boundaries) | 67–95 | [GAP-008](#gap-008), [GAP-010](#gap-010), [GAP-084](#gap-084) |
| session-transport-contracts.md | [Sub-version 3 versus the data endpoint](session-transport-contracts.md#sub-version-3-versus-the-data-endpoint) | 96–120 | [GAP-009](#gap-009), [GAP-055](#gap-055) |
| session-transport-contracts.md | [Receive-limit assignment at startup](session-transport-contracts.md#receive-limit-assignment-at-startup) | 121–136 | [GAP-011](#gap-011) |
| session-transport-contracts.md | [Captured framing and reassembly boundaries](session-transport-contracts.md#captured-framing-and-reassembly-boundaries) | 137–166 | [GAP-011](#gap-011), [GAP-012](#gap-012), [GAP-013](#gap-013), [GAP-084](#gap-084) |
| session-transport-contracts.md | [Transaction IDs, reassembly and correlation](session-transport-contracts.md#transaction-ids-reassembly-and-correlation) | 167–226 | [GAP-004](#gap-004), [GAP-012](#gap-012), [GAP-013](#gap-013), [GAP-084](#gap-084) |
| session-transport-contracts.md | [Native envelope acceptance and emission](session-transport-contracts.md#native-envelope-acceptance-and-emission) | 227–251 | [GAP-004](#gap-004), [GAP-012](#gap-012), [GAP-013](#gap-013), [GAP-084](#gap-084) |
| session-transport-contracts.md | [Identifier domains](session-transport-contracts.md#identifier-domains) | 252–267 | [GAP-024](#gap-024), [GAP-033](#gap-033) |
| session-transport-contracts.md | [Activity clocks and incomplete input](session-transport-contracts.md#activity-clocks-and-incomplete-input) | 268–302 | [GAP-005](#gap-005), [GAP-008](#gap-008), [GAP-012](#gap-012) |
| session-transport-contracts.md | [Captured failure-wait observations](session-transport-contracts.md#captured-failure-wait-observations) | 303–325 | [GAP-005](#gap-005), [GAP-084](#gap-084) |
| session-transport-contracts.md | [Captured selected-request and partial-input timing](session-transport-contracts.md#captured-selected-request-and-partial-input-timing) | 326–368 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| session-transport-contracts.md | [Flood and connection-burst counters](session-transport-contracts.md#flood-and-connection-burst-counters) | 369–399 | [GAP-005](#gap-005), [GAP-045](#gap-045), [GAP-074](#gap-074) |
| filesystem-and-board-contracts.md | [Native filesystem, diagnostics and legacy-board contracts](filesystem-and-board-contracts.md#native-filesystem-diagnostics-and-legacy-board-contracts) | 1–8 | [GAP-037](#gap-037), [GAP-046](#gap-046), [GAP-049](#gap-049), [GAP-050](#gap-050), [GAP-051](#gap-051), [GAP-052](#gap-052), [GAP-053](#gap-053), [GAP-054](#gap-054) |
| filesystem-and-board-contracts.md | [File-info target kinds and field presence](filesystem-and-board-contracts.md#file-info-target-kinds-and-field-presence) | 9–30 | [GAP-049](#gap-049) |
| filesystem-and-board-contracts.md | [Delete, create, rename, comment, move and alias](filesystem-and-board-contracts.md#delete-create-rename-comment-move-and-alias) | 31–62 | [GAP-050](#gap-050), [GAP-051](#gap-051), [GAP-052](#gap-052), [GAP-053](#gap-053), [GAP-054](#gap-054) |
| filesystem-and-board-contracts.md | [Request 207 presence and mutation order](filesystem-and-board-contracts.md#request-207-presence-and-mutation-order) | 63–88 | [GAP-052](#gap-052) |
| filesystem-and-board-contracts.md | [Move and alias distinctions](filesystem-and-board-contracts.md#move-and-alias-distinctions) | 89–111 | [GAP-053](#gap-053), [GAP-054](#gap-054) |
| filesystem-and-board-contracts.md | [Legacy board 101/102/103](filesystem-and-board-contracts.md#legacy-board-101102103) | 112–144 | [GAP-046](#gap-046) |
| filesystem-and-board-contracts.md | [Diagnostic text 303](filesystem-and-board-contracts.md#diagnostic-text-303) | 145–160 | [GAP-037](#gap-037) |
| filesystem-and-board-contracts.md | [Captured native folder creation and field 202 paths](filesystem-and-board-contracts.md#captured-native-folder-creation-and-field-202-paths) | 161–170 | 11 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Create inputs, permissions and replies](filesystem-and-board-contracts.md#create-inputs-permissions-and-replies) | 171–201 | 11 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Name bytes and structured-path acceptance](filesystem-and-board-contracts.md#name-bytes-and-structured-path-acceptance) | 202–228 | 11 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Listing, file-info and owned cleanup controls](filesystem-and-board-contracts.md#listing-file-info-and-owned-cleanup-controls) | 229–260 | 11 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Captured alias and metadata matrix](filesystem-and-board-contracts.md#captured-alias-and-metadata-matrix) | 261–269 | 9 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [File-info presence and values](filesystem-and-board-contracts.md#file-info-presence-and-values) | 270–301 | 9 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Alias creation, collisions and transfer resolution](filesystem-and-board-contracts.md#alias-creation-collisions-and-transfer-resolution) | 302–348 | 9 gaps; see section-specific rows and JSON register |
| filesystem-and-board-contracts.md | [Captured rename and comment mutation matrix](filesystem-and-board-contracts.md#captured-rename-and-comment-mutation-matrix) | 349–416 | [GAP-003](#gap-003), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031), [GAP-052](#gap-052), [GAP-084](#gap-084) |
| filesystem-and-board-contracts.md | [Captured move and Trash outcomes](filesystem-and-board-contracts.md#captured-move-and-trash-outcomes) | 417–491 | [GAP-003](#gap-003), [GAP-021](#gap-021), [GAP-031](#gap-031), [GAP-047](#gap-047), [GAP-050](#gap-050), [GAP-053](#gap-053), [GAP-054](#gap-054), [GAP-084](#gap-084) |
| evidence-portability.md | [Reproducing the protocol evidence baseline](evidence-portability.md#reproducing-the-protocol-evidence-baseline) | 1–8 | [GAP-087](#gap-087) |
| evidence-portability.md | [Build a revision-pinned package](evidence-portability.md#build-a-revision-pinned-package) | 9–29 | [GAP-087](#gap-087) |
| evidence-portability.md | [Verify and extract elsewhere](evidence-portability.md#verify-and-extract-elsewhere) | 30–55 | [GAP-087](#gap-087) |
| evidence-portability.md | [Updating evidence without rewriting history](evidence-portability.md#updating-evidence-without-rewriting-history) | 56–70 | [GAP-087](#gap-087) |
| evidence-portability.md | [Recorded extraction verification](evidence-portability.md#recorded-extraction-verification) | 71–83 | [GAP-087](#gap-087) |
| error-outcomes.md | [Native error and failure outcomes](error-outcomes.md#native-error-and-failure-outcomes) | 1–8 | [GAP-003](#gap-003), [GAP-021](#gap-021) |
| error-outcomes.md | [Wire status and failure classes](error-outcomes.md#wire-status-and-failure-classes) | 9–35 | [GAP-003](#gap-003), [GAP-021](#gap-021) |
| error-outcomes.md | [Recorded representative native outcomes](error-outcomes.md#recorded-representative-native-outcomes) | 36–78 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| error-outcomes.md | [Derived unknown-operation example](error-outcomes.md#derived-unknown-operation-example) | 79–98 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| error-outcomes.md | [Internal exceptions and text resources](error-outcomes.md#internal-exceptions-and-text-resources) | 99–169 | [GAP-003](#gap-003) |
| identified-client-source.md | [Identified shx source profile and bounded callback results](identified-client-source.md#identified-shx-source-profile-and-bounded-callback-results) | 1–21 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-083](#gap-083) |
| identified-client-source.md | [Basic login and unknown fields](identified-client-source.md#basic-login-and-unknown-fields) | 22–40 | [GAP-024](#gap-024), [GAP-080](#gap-080), [GAP-081](#gap-081) |
| identified-client-source.md | [Executed host callback matrix](identified-client-source.md#executed-host-callback-matrix) | 41–75 | [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085) |
| identified-client-source.md | [Other receiver observations and negative scope](identified-client-source.md#other-receiver-observations-and-negative-scope) | 76–108 | [GAP-008](#gap-008), [GAP-018](#gap-018), [GAP-071](#gap-071), [GAP-075](#gap-075), [GAP-079](#gap-079), [GAP-082](#gap-082) |
| identified-client-source.md | [Identified complete terminal build](identified-client-source.md#identified-complete-terminal-build) | 109–131 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| identified-client-source.md | [Full native peer acceptance matrix](identified-client-source.md#full-native-peer-acceptance-matrix) | 132–163 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| identified-client-source.md | [Ambiguous text at the real peer boundary](identified-client-source.md#ambiguous-text-at-the-real-peer-boundary) | 164–189 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| identified-client-source.md | [Reproducing and checking full peer sessions](identified-client-source.md#reproducing-and-checking-full-peer-sessions) | 190–220 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| identified-client-source.md | [Native configured-name and controlled receiver matrix](identified-client-source.md#native-configured-name-and-controlled-receiver-matrix) | 221–274 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| identified-client-source.md | [Source package identities and configuration applicability](identified-client-source.md#source-package-identities-and-configuration-applicability) | 275–326 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| privilege-contracts.md | [Native privilege registry and composition](privilege-contracts.md#native-privilege-registry-and-composition) | 1–8 | [GAP-031](#gap-031), [GAP-032](#gap-032) |
| privilege-contracts.md | [Bitmap numbering and known uses](privilege-contracts.md#bitmap-numbering-and-known-uses) | 9–64 | [GAP-031](#gap-031), [GAP-034](#gap-034) |
| privilege-contracts.md | [Operation-specific composition](privilege-contracts.md#operation-specific-composition) | 65–86 | [GAP-032](#gap-032), [GAP-047](#gap-047) |
| privilege-contracts.md | [Account creation, update and batch rules](privilege-contracts.md#account-creation-update-and-batch-rules) | 87–130 | [GAP-032](#gap-032), [GAP-072](#gap-072), [GAP-073](#gap-073), [GAP-078](#gap-078) |
| privilege-contracts.md | [Remaining acceptance evidence](privilege-contracts.md#remaining-acceptance-evidence) | 131–149 | [GAP-031](#gap-031), [GAP-032](#gap-032), [GAP-072](#gap-072), [GAP-073](#gap-073), [GAP-078](#gap-078) |
| native-capture-workflow.md | [Reproducing native protocol captures](native-capture-workflow.md#reproducing-native-protocol-captures) | 1–8 | [GAP-008](#gap-008), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Prepare the emulator and application](native-capture-workflow.md#prepare-the-emulator-and-application) | 9–86 | [GAP-008](#gap-008), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Capture an exchange](native-capture-workflow.md#capture-an-exchange) | 87–153 | [GAP-008](#gap-008), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native core fixtures](native-capture-workflow.md#recorded-native-core-fixtures) | 154–230 | [GAP-022](#gap-022), [GAP-025](#gap-025), [GAP-071](#gap-071), [GAP-077](#gap-077), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native transport fixtures](native-capture-workflow.md#recorded-native-transport-fixtures) | 231–273 | [GAP-008](#gap-008), [GAP-009](#gap-009), [GAP-010](#gap-010), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native framing fixtures](native-capture-workflow.md#recorded-native-framing-fixtures) | 274–308 | [GAP-014](#gap-014), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native ordinary-file fixtures](native-capture-workflow.md#recorded-native-ordinary-file-fixtures) | 309–358 | [GAP-009](#gap-009), [GAP-056](#gap-056), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native resume fixtures](native-capture-workflow.md#recorded-native-resume-fixtures) | 359–399 | [GAP-058](#gap-058), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native queue fixtures](native-capture-workflow.md#recorded-native-queue-fixtures) | 400–442 | [GAP-057](#gap-057), [GAP-061](#gap-061), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native cleanup fixtures](native-capture-workflow.md#recorded-native-cleanup-fixtures) | 443–478 | [GAP-062](#gap-062), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native folder fixtures](native-capture-workflow.md#recorded-native-folder-fixtures) | 479–540 | [GAP-059](#gap-059), [GAP-060](#gap-060), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Acceptance and corpus coverage](native-capture-workflow.md#acceptance-and-corpus-coverage) | 541–571 | [GAP-008](#gap-008), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Recorded native banner fixtures](native-capture-workflow.md#recorded-native-banner-fixtures) | 572–632 | [GAP-055](#gap-055), [GAP-063](#gap-063), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing banner format and recovery fixtures](native-capture-workflow.md#reproducing-banner-format-and-recovery-fixtures) | 633–702 | [GAP-055](#gap-055), [GAP-063](#gap-063), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing HTXF header and reference fixtures](native-capture-workflow.md#reproducing-htxf-header-and-reference-fixtures) | 703–753 | [GAP-033](#gap-033), [GAP-055](#gap-055), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing ID, envelope and partial-input fixtures](native-capture-workflow.md#reproducing-id-envelope-and-partial-input-fixtures) | 754–807 | [GAP-004](#gap-004), [GAP-012](#gap-012), [GAP-013](#gap-013), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing native authentication and visibility fixtures](native-capture-workflow.md#reproducing-native-authentication-and-visibility-fixtures) | 808–861 | [GAP-023](#gap-023), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-035](#gap-035), [GAP-036](#gap-036), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing agreement configuration and partial-failure fixtures](native-capture-workflow.md#reproducing-agreement-configuration-and-partial-failure-fixtures) | 862–936 | [GAP-003](#gap-003), [GAP-019](#gap-019), [GAP-025](#gap-025), [GAP-027](#gap-027), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing login-extra configuration and refresh fixtures](native-capture-workflow.md#reproducing-login-extra-configuration-and-refresh-fixtures) | 937–1013 | [GAP-005](#gap-005), [GAP-018](#gap-018), [GAP-019](#gap-019), [GAP-026](#gap-026), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing full historical shx sessions](native-capture-workflow.md#reproducing-full-historical-shx-sessions) | 1014–1038 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing banner and roster-subject receiver fixtures](native-capture-workflow.md#reproducing-banner-and-roster-subject-receiver-fixtures) | 1039–1058 | [GAP-018](#gap-018), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-083](#gap-083), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing directory creation and path fixtures](native-capture-workflow.md#reproducing-directory-creation-and-path-fixtures) | 1059–1101 | 11 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing alias and metadata fixtures](native-capture-workflow.md#reproducing-alias-and-metadata-fixtures) | 1102–1153 | 9 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing rename and comment fixtures](native-capture-workflow.md#reproducing-rename-and-comment-fixtures) | 1154–1201 | [GAP-003](#gap-003), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031), [GAP-052](#gap-052), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing move and Trash fixtures](native-capture-workflow.md#reproducing-move-and-trash-fixtures) | 1202–1249 | [GAP-003](#gap-003), [GAP-021](#gap-021), [GAP-031](#gap-031), [GAP-047](#gap-047), [GAP-050](#gap-050), [GAP-053](#gap-053), [GAP-054](#gap-054), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing category and threaded news fixtures](native-capture-workflow.md#reproducing-category-and-threaded-news-fixtures) | 1250–1313 | 14 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing isolated article deletion fixtures](native-capture-workflow.md#reproducing-isolated-article-deletion-fixtures) | 1314–1366 | 9 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing the child append boundary](native-capture-workflow.md#reproducing-the-child-append-boundary) | 1367–1423 | 9 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing account replacement and password boundaries](native-capture-workflow.md#reproducing-account-replacement-and-password-boundaries) | 1424–1490 | 9 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing live account edits, deletion and restart](native-capture-workflow.md#reproducing-live-account-edits-deletion-and-restart) | 1491–1561 | 9 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing account batch framing and partial effects](native-capture-workflow.md#reproducing-account-batch-framing-and-partial-effects) | 1562–1631 | 11 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing account identity and protection contrasts](native-capture-workflow.md#reproducing-account-identity-and-protection-contrasts) | 1632–1685 | [GAP-003](#gap-003), [GAP-018](#gap-018), [GAP-021](#gap-021), [GAP-031](#gap-031), [GAP-036](#gap-036), [GAP-072](#gap-072), [GAP-074](#gap-074), [GAP-084](#gap-084) |
| native-capture-workflow.md | [Reproducing private rooms and chat byte fixtures](native-capture-workflow.md#reproducing-private-rooms-and-chat-byte-fixtures) | 1686–1748 | 12 gaps; see section-specific rows and JSON register |
| native-capture-workflow.md | [Reproducing console and client broadcast fixtures](native-capture-workflow.md#reproducing-console-and-client-broadcast-fixtures) | 1749–1765 | [GAP-076](#gap-076) |
| diagnostic-replies.md | [Native 1.9 client diagnostics (303)](diagnostic-replies.md#native-19-client-diagnostics-303) | 1–11 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| diagnostic-replies.md | [Representative reply matrix](diagnostic-replies.md#representative-reply-matrix) | 12–52 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| diagnostic-replies.md | [Contract boundary](diagnostic-replies.md#contract-boundary) | 53–87 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| diagnostic-replies.md | [Reproduction and checks](diagnostic-replies.md#reproduction-and-checks) | 88–128 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| peer-tolerance-matrix.md | [Identified shx peer field tolerance: controlled matrix](peer-tolerance-matrix.md#identified-shx-peer-field-tolerance-controlled-matrix) | 1–57 | [GAP-026](#gap-026), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082) |
| peer-tolerance-matrix.md | [Reproduce and verify](peer-tolerance-matrix.md#reproduce-and-verify) | 58–86 | [GAP-026](#gap-026), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082) |
| peer-tolerance-matrix.md | [Cross-peer acceptance and omission rules](peer-tolerance-matrix.md#cross-peer-acceptance-and-omission-rules) | 87–124 | [GAP-081](#gap-081) |
| mxd-reconciliation.md | [mxd compatibility reconciliation at 2e4c9c1](mxd-reconciliation.md#mxd-compatibility-reconciliation-at-2e4c9c1) | 1–17 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-reconciliation.md | [Oracle and identified peer boundary](mxd-reconciliation.md#oracle-and-identified-peer-boundary) | 18–39 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-reconciliation.md | [Assertion-to-requirement map](mxd-reconciliation.md#assertion-to-requirement-map) | 40–94 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-reconciliation.md | [Bounded correction proposal](mxd-reconciliation.md#bounded-correction-proposal) | 95–131 | [GAP-001](#gap-001), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-082](#gap-082), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| bitmap-boundaries.md | [Native 1.9 privilege bitmap replacement and width observations](bitmap-boundaries.md#native-19-privilege-bitmap-replacement-and-width-observations) | 1–11 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031) |
| bitmap-boundaries.md | [All 64 bit positions](bitmap-boundaries.md#all-64-bit-positions) | 12–36 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031) |
| bitmap-boundaries.md | [Field-110 presence and width](bitmap-boundaries.md#field-110-presence-and-width) | 37–64 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031) |
| bitmap-boundaries.md | [Enforcement and remaining criteria](bitmap-boundaries.md#enforcement-and-remaining-criteria) | 65–89 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031) |
| bitmap-boundaries.md | [Verification](bitmap-boundaries.md#verification) | 90–130 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-019](#gap-019), [GAP-031](#gap-031) |
| account-attribute-trace.md | [Account field 111: stored-record and consumer trace](account-attribute-trace.md#account-field-111-stored-record-and-consumer-trace) | 1–10 | [GAP-071](#gap-071) |
| account-attribute-trace.md | [Positive field and storage evidence](account-attribute-trace.md#positive-field-and-storage-evidence) | 11–43 | [GAP-071](#gap-071) |
| account-attribute-trace.md | [Direct reader boundary and forwarded records](account-attribute-trace.md#direct-reader-boundary-and-forwarded-records) | 44–77 | [GAP-071](#gap-071) |
| account-attribute-trace.md | [Resource-fork search boundary](account-attribute-trace.md#resource-fork-search-boundary) | 78–93 | [GAP-085](#gap-085), [GAP-086](#gap-086) |
| account-attribute-trace.md | [Identified Classic client construction boundary](account-attribute-trace.md#identified-classic-client-construction-boundary) | 94–104 | [GAP-071](#gap-071) |
| account-attribute-trace.md | [Reproduce and decision boundary](account-attribute-trace.md#reproduce-and-decision-boundary) | 105–138 | [GAP-071](#gap-071) |
| mxd-limit-contracts.md | [mxd framing and memory limits through 4812949](mxd-limit-contracts.md#mxd-framing-and-memory-limits-through-4812949) | 1–9 | [GAP-011](#gap-011), [GAP-085](#gap-085) |
| mxd-limit-contracts.md | [Native boundary and mxd policy](mxd-limit-contracts.md#native-boundary-and-mxd-policy) | 10–26 | [GAP-011](#gap-011), [GAP-085](#gap-085) |
| mxd-limit-contracts.md | [Implementation paths and comparisons](mxd-limit-contracts.md#implementation-paths-and-comparisons) | 27–69 | [GAP-011](#gap-011), [GAP-085](#gap-085) |
| mxd-limit-contracts.md | [Boundary witnesses and error results](mxd-limit-contracts.md#boundary-witnesses-and-error-results) | 70–124 | [GAP-011](#gap-011), [GAP-085](#gap-085) |
| failure-representatives.md | [Captured representative native failures](failure-representatives.md#captured-representative-native-failures) | 1–19 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| failure-representatives.md | [Authentication: rejected password](failure-representatives.md#authentication-rejected-password) | 20–34 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| failure-representatives.md | [Permission: account enumeration denied](failure-representatives.md#permission-account-enumeration-denied) | 35–48 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| failure-representatives.md | [Missing object: file information lookup](failure-representatives.md#missing-object-file-information-lookup) | 49–62 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| failure-representatives.md | [Malformed request: zero-size frame](failure-representatives.md#malformed-request-zero-size-frame) | 63–77 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| failure-representatives.md | [Unsupported operation: unknown online transaction](failure-representatives.md#unsupported-operation-unknown-online-transaction) | 78–116 | [GAP-003](#gap-003), [GAP-084](#gap-084) |
| runtime-recovery-20261113.md | [Disposable Mac OS 9 runtime recovery, 13 November 2026](runtime-recovery-20261113.md#disposable-mac-os-9-runtime-recovery-13-november-2026) | 1–9 | [GAP-084](#gap-084) |
| runtime-recovery-20261113.md | [Recovery boundary](runtime-recovery-20261113.md#recovery-boundary) | 10–48 | [GAP-084](#gap-084) |
| runtime-recovery-20261113.md | [Boot and guest observation](runtime-recovery-20261113.md#boot-and-guest-observation) | 49–75 | [GAP-084](#gap-084) |
| runtime-recovery-20261113.md | [Read-only readiness smokes](runtime-recovery-20261113.md#read-only-readiness-smokes) | 76–120 | [GAP-084](#gap-084) |
| receive-limit-origin.md | [Receive-limit origin and indexed reference boundary](receive-limit-origin.md#receive-limit-origin-and-indexed-reference-boundary) | 1–8 | [GAP-011](#gap-011) |
| receive-limit-origin.md | [Positive native-code comparison](receive-limit-origin.md#positive-native-code-comparison) | 9–43 | [GAP-011](#gap-011) |
| receive-limit-origin.md | [Configuration and remaining question](receive-limit-origin.md#configuration-and-remaining-question) | 44–60 | [GAP-011](#gap-011) |
| receive-limit-origin.md | [Reproduce the bounded query](receive-limit-origin.md#reproduce-the-bounded-query) | 61–96 | [GAP-011](#gap-011) |
| diagnostic-transfer-boundaries.md | [GAP-037 transfer-state diagnostic attempt](diagnostic-transfer-boundaries.md#gap-037-transfer-state-diagnostic-attempt) | 1–9 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| diagnostic-transfer-boundaries.md | [Bounded preparation and failure](diagnostic-transfer-boundaries.md#bounded-preparation-and-failure) | 10–32 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| diagnostic-transfer-boundaries.md | [Positive partial-file cleanup](diagnostic-transfer-boundaries.md#positive-partial-file-cleanup) | 33–77 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| mac-peer-first-session.md | [First Classic Mac peer session: finite wire observations](mac-peer-first-session.md#first-classic-mac-peer-session-finite-wire-observations) | 1–19 | [GAP-026](#gap-026), [GAP-079](#gap-079), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-084](#gap-084) |
| mac-peer-first-session.md | [Observed control exchange](mac-peer-first-session.md#observed-control-exchange) | 20–49 | [GAP-026](#gap-026), [GAP-079](#gap-079), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-084](#gap-084) |
| mac-peer-first-session.md | [Measured limits and safety stop](mac-peer-first-session.md#measured-limits-and-safety-stop) | 50–68 | [GAP-026](#gap-026), [GAP-079](#gap-079), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-084](#gap-084) |
| native-diagnostic-existing-preparation.md | [Existing-file diagnostic load preparation](native-diagnostic-existing-preparation.md#existing-file-diagnostic-load-preparation) | 1–17 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| native-diagnostic-existing-preparation.md | [Bounds and order](native-diagnostic-existing-preparation.md#bounds-and-order) | 18–49 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| native-diagnostic-existing-preparation.md | [Prepared commands](native-diagnostic-existing-preparation.md#prepared-commands) | 50–112 | [GAP-037](#gap-037), [GAP-084](#gap-084) |
| native-diagnostic-existing-witness.md | [Native 1.9 diagnostic with one active and one waiting download](native-diagnostic-existing-witness.md#native-19-diagnostic-with-one-active-and-one-waiting-download) | 1–8 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| native-diagnostic-existing-witness.md | [Native observation](native-diagnostic-existing-witness.md#native-observation) | 9–67 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| native-diagnostic-existing-witness.md | [Scope and reproduction](native-diagnostic-existing-witness.md#scope-and-reproduction) | 68–110 | [GAP-021](#gap-021), [GAP-037](#gap-037), [GAP-064](#gap-064), [GAP-084](#gap-084) |
| native-diagnostic-density-witness.md | [Native 1.9 diagnostic density with existing downloads](native-diagnostic-density-witness.md#native-19-diagnostic-density-with-existing-downloads) | 1–9 | [GAP-037](#gap-037) |
| native-diagnostic-density-witness.md | [Fixed 303 observations](native-diagnostic-density-witness.md#fixed-303-observations) | 10–41 | [GAP-037](#gap-037) |
| native-diagnostic-density-witness.md | [Packet views and restoration](native-diagnostic-density-witness.md#packet-views-and-restoration) | 42–64 | [GAP-037](#gap-037) |
| native-diagnostic-density-witness.md | [Replay](native-diagnostic-density-witness.md#replay) | 65–81 | [GAP-037](#gap-037) |
| mxd-direct-ack-correction.md | [mxd direct reply correction through 20e891a](mxd-direct-ack-correction.md#mxd-direct-reply-correction-through-20e891a) | 1–69 | [GAP-085](#gap-085) |
| mxd-login-extras-correction.md | [mxd successful Login107 extras correction](mxd-login-extras-correction.md#mxd-successful-login107-extras-correction) | 1–12 | [GAP-081](#gap-081), [GAP-085](#gap-085) |
| mxd-login-extras-correction.md | [Native baseline and corrected mxd behaviour](mxd-login-extras-correction.md#native-baseline-and-corrected-mxd-behaviour) | 13–49 | [GAP-081](#gap-081), [GAP-085](#gap-085) |
| mxd-login-extras-correction.md | [Acceptance and replay](mxd-login-extras-correction.md#acceptance-and-replay) | 50–83 | [GAP-081](#gap-081), [GAP-085](#gap-085) |
| native-diagnostic-near-preparation.md | [Native 303 near-boundary preparation](native-diagnostic-near-preparation.md#native-303-near-boundary-preparation) | 1–13 | [GAP-037](#gap-037) |
| native-diagnostic-near-preparation.md | [Fixed bounds and decision gate](native-diagnostic-near-preparation.md#fixed-bounds-and-decision-gate) | 14–43 | [GAP-037](#gap-037) |
| native-diagnostic-near-preparation.md | [Offline preparation and replay commands](native-diagnostic-near-preparation.md#offline-preparation-and-replay-commands) | 44–69 | [GAP-037](#gap-037) |
| native-diagnostic-near-witness.md | [Native 1.9 diagnostic near-boundary observation](native-diagnostic-near-witness.md#native-19-diagnostic-near-boundary-observation) | 1–47 | [GAP-037](#gap-037) |
| native-diagnostic-near-witness.md | [Replay](native-diagnostic-near-witness.md#replay) | 48–73 | [GAP-037](#gap-037) |
| mac-peer-isolated-session.md | [Isolated Classic client: one finite 1.9 session](mac-peer-isolated-session.md#isolated-classic-client-one-finite-19-session) | 1–59 | [GAP-079](#gap-079), [GAP-081](#gap-081), [GAP-084](#gap-084) |
| request-500-contract.md | [Request 500: native reply and one modern client's schedule](request-500-contract.md#request-500-native-reply-and-one-modern-clients-schedule) | 1–46 | [GAP-079](#gap-079) |
| native-console-broadcast.md | [Native console broadcast and client 355: bounded D1 witness](native-console-broadcast.md#native-console-broadcast-and-client-355-bounded-d1-witness) | 1–63 | [GAP-044](#gap-044), [GAP-076](#gap-076) |
| mxd-peer-capture-workflow.md | [Run an actual Classic peer against an isolated mxd fixture](mxd-peer-capture-workflow.md#run-an-actual-classic-peer-against-an-isolated-mxd-fixture) | 1–8 | [GAP-080](#gap-080), [GAP-085](#gap-085) |
| mxd-peer-capture-workflow.md | [Pin the binary and prepare a new fixture](mxd-peer-capture-workflow.md#pin-the-binary-and-prepare-a-new-fixture) | 9–67 | [GAP-080](#gap-080), [GAP-085](#gap-085) |
| mxd-peer-capture-workflow.md | [Supervise inside the existing client namespace](mxd-peer-capture-workflow.md#supervise-inside-the-existing-client-namespace) | 68–127 | [GAP-080](#gap-080), [GAP-085](#gap-085) |
| mxd-classic-login.md | [Classic client login against an isolated mxd fixture](mxd-classic-login.md#classic-client-login-against-an-isolated-mxd-fixture) | 1–35 | [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-085](#gap-085) |
| classic-login-proxy.md | [Classic Login107 field-161 proxy](classic-login-proxy.md#classic-login107-field-161-proxy) | 1–12 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-login-proxy.md | [Fixed topology and authority boundary](classic-login-proxy.md#fixed-topology-and-authority-boundary) | 13–41 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-login-proxy.md | [Wire transformation](classic-login-proxy.md#wire-transformation) | 42–110 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-login-proxy.md | [Automatic observation cutoff (B27 preparation)](classic-login-proxy.md#automatic-observation-cutoff-b27-preparation) | 111–141 | [GAP-085](#gap-085), [GAP-086](#gap-086) |
| classic-login-proxy.md | [Offline checks and remaining gate](classic-login-proxy.md#offline-checks-and-remaining-gate) | 142–196 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-login-proxy.md | [Read-only actual namespace guard receipt](classic-login-proxy.md#read-only-actual-namespace-guard-receipt) | 197–215 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| mxd-validation.md | [mxd validation findings and deferred work](mxd-validation.md#mxd-validation-findings-and-deferred-work) | 1–7 | [GAP-001](#gap-001), [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-validation.md | [Recorded checkout and corrections](mxd-validation.md#recorded-checkout-and-corrections) | 8–32 | [GAP-001](#gap-001), [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-validation.md | [Two actual Classic-client trials](mxd-validation.md#two-actual-classic-client-trials) | 33–59 | [GAP-001](#gap-001), [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-validation.md | [Startup hand-off missing from the current implementation](mxd-validation.md#startup-hand-off-missing-from-the-current-implementation) | 60–83 | [GAP-001](#gap-001), [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-validation.md | [Handoff locations](mxd-validation.md#handoff-locations) | 84–104 | [GAP-085](#gap-085), [GAP-086](#gap-086) |
| mxd-validation.md | [Repeatability and deferred validation](mxd-validation.md#repeatability-and-deferred-validation) | 105–131 | [GAP-001](#gap-001), [GAP-019](#gap-019), [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-085](#gap-085), [GAP-086](#gap-086) |
| native-pm-preparation.md | [Native private-message fixture preparation (A26)](native-pm-preparation.md#native-private-message-fixture-preparation-a26) | 1–8 | [GAP-044](#gap-044) |
| native-pm-preparation.md | [Matrix](native-pm-preparation.md#matrix) | 9–29 | [GAP-044](#gap-044) |
| native-pm-preparation.md | [Operator sequence after separate START](native-pm-preparation.md#operator-sequence-after-separate-start) | 30–71 | [GAP-044](#gap-044) |
| native-pm-witness.md | [Native 1.9 private-message 104 witness (A29)](native-pm-witness.md#native-19-private-message-104-witness-a29) | 1–72 | [GAP-044](#gap-044) |
| native-104-variants.md | [Native 1.9 type-104 producer matrix (A28)](native-104-variants.md#native-19-type-104-producer-matrix-a28) | 1–21 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-104-variants.md | [Parsing and evidence limits](native-104-variants.md#parsing-and-evidence-limits) | 22–63 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-settings-preparation.md | [Native 1.9 settings field 113 preparation](native-settings-preparation.md#native-19-settings-field-113-preparation) | 1–13 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017) |
| native-settings-preparation.md | [Bounded matrix and observer](native-settings-preparation.md#bounded-matrix-and-observer) | 14–38 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017) |
| native-settings-preparation.md | [Preparation and later authorised capture](native-settings-preparation.md#preparation-and-later-authorised-capture) | 39–69 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017) |
| native-settings-witness.md | [Native 1.9 settings field 113 witness](native-settings-witness.md#native-19-settings-field-113-witness) | 1–69 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-017](#gap-017) |
| native-ban-notices.md | [Native 1.9 temporary ban notice: disposable option-one witness](native-ban-notices.md#native-19-temporary-ban-notice-disposable-option-one-witness) | 1–9 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-notices.md | [Identity and baseline](native-ban-notices.md#identity-and-baseline) | 10–30 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-notices.md | [One option-one exchange](native-ban-notices.md#one-option-one-exchange) | 31–63 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-notices.md | [Isolation and limits](native-ban-notices.md#isolation-and-limits) | 64–92 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| parameter-multiplicity.md | [Parameter multiplicity and ordering in Hotline Server 1.9](parameter-multiplicity.md#parameter-multiplicity-and-ordering-in-hotline-server-19) | 1–55 | [GAP-017](#gap-017) |
| native-transfer-stall.md | [Disposable lab transfer stall before the option-two ban fixture](native-transfer-stall.md#disposable-lab-transfer-stall-before-the-option-two-ban-fixture) | 1–21 | [GAP-044](#gap-044), [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-transfer-stall.md | [What the frozen TCP views establish](native-transfer-stall.md#what-the-frozen-tcp-views-establish) | 22–58 | [GAP-044](#gap-044), [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-transfer-stall.md | [Repeated baseline and a successful comparison](native-transfer-stall.md#repeated-baseline-and-a-successful-comparison) | 59–109 | [GAP-044](#gap-044), [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-transfer-stall.md | [One focus event on the repeated prefix](native-transfer-stall.md#one-focus-event-on-the-repeated-prefix) | 110–120 | [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-settings-transition-prep.md | [Same-session 304 transition preparation (A32)](native-settings-transition-prep.md#same-session-304-transition-preparation-a32) | 1–64 | [GAP-029](#gap-029), [GAP-030](#gap-030) |
| native-settings-transition-witness.md | [Native 1.9 same-session 304 transition witness (A33)](native-settings-transition-witness.md#native-19-same-session-304-transition-witness-a33) | 1–77 | [GAP-015](#gap-015), [GAP-016](#gap-016), [GAP-029](#gap-029), [GAP-030](#gap-030) |
| native-download-send-path.md | [Native ordinary-download send path](native-download-send-path.md#native-ordinary-download-send-path) | 1–11 | [GAP-021](#gap-021), [GAP-064](#gap-064) |
| native-download-send-path.md | [Request, attachment and producer](native-download-send-path.md#request-attachment-and-producer) | 12–53 | [GAP-021](#gap-021), [GAP-064](#gap-064) |
| native-download-send-path.md | [Limits and next proof](native-download-send-path.md#limits-and-next-proof) | 54–86 | [GAP-021](#gap-021), [GAP-064](#gap-064) |
| classic-account-constructors.md | [Classic client account request constructors](classic-account-constructors.md#classic-client-account-request-constructors) | 1–13 | [GAP-071](#gap-071), [GAP-080](#gap-080) |
| classic-account-constructors.md | [What the executable trace establishes](classic-account-constructors.md#what-the-executable-trace-establishes) | 14–48 | [GAP-071](#gap-071), [GAP-080](#gap-080) |
| classic-account-constructors.md | [Repeat or check without a live server](classic-account-constructors.md#repeat-or-check-without-a-live-server) | 49–76 | [GAP-071](#gap-071), [GAP-080](#gap-080) |
| native-121-default-preparation.md | [Delayed 121 default-text preparation (A35)](native-121-default-preparation.md#delayed-121-default-text-preparation-a35) | 1–84 | [GAP-029](#gap-029), [GAP-030](#gap-030) |
| native-121-default-witness.md | [Native 1.9 delayed 121 default response (A37)](native-121-default-witness.md#native-19-delayed-121-default-response-a37) | 1–74 | [GAP-029](#gap-029), [GAP-030](#gap-030) |
| classic-native-baseline.md | [Classic client to native Hotline 1.9 baseline through the fixed proxy](classic-native-baseline.md#classic-client-to-native-hotline-19-baseline-through-the-fixed-proxy) | 1–12 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-native-baseline.md | [Provenance and finite result](classic-native-baseline.md#provenance-and-finite-result) | 13–58 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| classic-native-baseline.md | [Offline replay](classic-native-baseline.md#offline-replay) | 59–85 | [GAP-080](#gap-080), [GAP-081](#gap-081) |
| native-ui-focus-witness.md | [One server Log focus event during a stalled native download](native-ui-focus-witness.md#one-server-log-focus-event-during-a-stalled-native-download) | 1–20 | [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-ui-focus-witness.md | [Measured event and result](native-ui-focus-witness.md#measured-event-and-result) | 21–68 | [GAP-064](#gap-064), [GAP-074](#gap-074) |
| native-control-readiness.md | [Readiness for isolated control-operation fixtures](native-control-readiness.md#readiness-for-isolated-control-operation-fixtures) | 1–16 | [GAP-029](#gap-029), [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-control-readiness.md | [Why a separate profile is appropriate](native-control-readiness.md#why-a-separate-profile-is-appropriate) | 17–29 | [GAP-029](#gap-029), [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-control-readiness.md | [Required gates](native-control-readiness.md#required-gates) | 30–46 | [GAP-029](#gap-029), [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-control-readiness.md | [Ban fixture boundary](native-control-readiness.md#ban-fixture-boundary) | 47–71 | [GAP-029](#gap-029), [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-control-readiness.md | [Acceptance and escalation](native-control-readiness.md#acceptance-and-escalation) | 72–82 | [GAP-029](#gap-029), [GAP-044](#gap-044), [GAP-074](#gap-074) |
| classic-field161-matrix.md | [Classic client field-161 width and omission matrix](classic-field161-matrix.md#classic-client-field-161-width-and-omission-matrix) | 1–78 | [GAP-026](#gap-026), [GAP-080](#gap-080), [GAP-081](#gap-081) |
| native-ban-control-preparation.md | [Isolated permanent-ban control fixture (C52 preparation)](native-ban-control-preparation.md#isolated-permanent-ban-control-fixture-c52-preparation) | 1–10 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-control-preparation.md | [Prepared image and immutable inputs](native-ban-control-preparation.md#prepared-image-and-immutable-inputs) | 11–28 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-control-preparation.md | [Bounded next live sequence (requires separate grant)](native-ban-control-preparation.md#bounded-next-live-sequence-requires-separate-grant) | 29–87 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| notification-104-variants.md | [Native type-104 notification variants](notification-104-variants.md#native-type-104-notification-variants) | 1–25 | [GAP-044](#gap-044) |
| notification-104-variants.md | [Discrimination and ambiguity](notification-104-variants.md#discrimination-and-ambiguity) | 26–52 | [GAP-044](#gap-044) |
| notification-104-variants.md | [Provenance and remaining acceptance](notification-104-variants.md#provenance-and-remaining-acceptance) | 53–76 | [GAP-044](#gap-044) |
| peer-profile-rules.md | [Identified peer profiles and the unknown-peer rule](peer-profile-rules.md#identified-peer-profiles-and-the-unknown-peer-rule) | 1–9 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-026](#gap-026) |
| peer-profile-rules.md | [Evaluated build identities](peer-profile-rules.md#evaluated-build-identities) | 10–47 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-026](#gap-026) |
| peer-profile-rules.md | [Profile assignment and unknown-peer fallback](peer-profile-rules.md#profile-assignment-and-unknown-peer-fallback) | 48–76 | [GAP-080](#gap-080), [GAP-081](#gap-081), [GAP-026](#gap-026) |
| native-settings-persistence-preparation.md | [Isolated native settings persistence preparation (A42)](native-settings-persistence-preparation.md#isolated-native-settings-persistence-preparation-a42) | 1–11 | [GAP-029](#gap-029) |
| native-settings-persistence-preparation.md | [Assets and authority](native-settings-persistence-preparation.md#assets-and-authority) | 12–33 | [GAP-029](#gap-029) |
| native-settings-persistence-preparation.md | [Fixed observation](native-settings-persistence-preparation.md#fixed-observation) | 34–121 | [GAP-029](#gap-029) |
| native-ban-control-witness.md | [Native 1.9 permanent ban control witness](native-ban-control-witness.md#native-19-permanent-ban-control-witness) | 1–8 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-control-witness.md | [Scope and provenance](native-ban-control-witness.md#scope-and-provenance) | 9–28 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-control-witness.md | [Observed sequence](native-ban-control-witness.md#observed-sequence) | 29–60 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-ban-control-witness.md | [Offline replay](native-ban-control-witness.md#offline-replay) | 61–75 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| classic-server-name-162.md | [Classic client acceptance of one ASCII server-name field](classic-server-name-162.md#classic-client-acceptance-of-one-ascii-server-name-field) | 1–63 | [GAP-026](#gap-026), [GAP-080](#gap-080), [GAP-081](#gap-081) |
| native-configured-ban-static.md | [Native 1.9 configured-ban application: static preparation](native-configured-ban-static.md#native-19-configured-ban-application-static-preparation) | 1–6 | [GAP-044](#gap-044) |
| native-configured-ban-static.md | [Raw text and source path](native-configured-ban-static.md#raw-text-and-source-path) | 7–34 | [GAP-044](#gap-044) |
| native-configured-ban-static.md | [Next preparation gate](native-configured-ban-static.md#next-preparation-gate) | 35–52 | [GAP-044](#gap-044) |
| native-configured-ban-ui-resources.md | [Configured-ban Options resource reconnaissance](native-configured-ban-ui-resources.md#configured-ban-options-resource-reconnaissance) | 1–31 | [GAP-044](#gap-044) |
| native-ban-reload-witness.md | [Native 1.9 persisted-ban reload witness](native-ban-reload-witness.md#native-19-persisted-ban-reload-witness) | 1–9 | [GAP-074](#gap-074) |
| native-ban-reload-witness.md | [Pinned stopped image and UI](native-ban-reload-witness.md#pinned-stopped-image-and-ui) | 10–34 | [GAP-074](#gap-074) |
| native-ban-reload-witness.md | [One fresh Login 107](native-ban-reload-witness.md#one-fresh-login-107) | 35–59 | [GAP-074](#gap-074) |
| native-ban-reload-witness.md | [Offline replay and limit](native-ban-reload-witness.md#offline-replay-and-limit) | 60–79 | [GAP-074](#gap-074) |
| native-settings-persistence-witness.md | [Native 1.9 settings persistence witness (A46/A48)](native-settings-persistence-witness.md#native-19-settings-persistence-witness-a46a48) | 1–10 | [GAP-029](#gap-029) |
| native-settings-persistence-witness.md | [Controlled sequence](native-settings-persistence-witness.md#controlled-sequence) | 11–67 | [GAP-029](#gap-029) |
| native-settings-persistence-witness.md | [Replay and provenance](native-settings-persistence-witness.md#replay-and-provenance) | 68–109 | [GAP-029](#gap-029) |
| classic-roster-subject-115.md | [Classic client: first roster reply with field 115](classic-roster-subject-115.md#classic-client-first-roster-reply-with-field-115) | 1–8 | [GAP-081](#gap-081) |
| classic-roster-subject-115.md | [B62 session, 14 November 2026](classic-roster-subject-115.md#b62-session-14-november-2026) | 9–46 | [GAP-081](#gap-081) |
| classic-roster-subject-115.md | [Provenance and replay](classic-roster-subject-115.md#provenance-and-replay) | 47–72 | [GAP-081](#gap-081) |
| native-configured-ban-preparation.md | [Configured-address ban application: control-only preparation](native-configured-ban-preparation.md#configured-address-ban-application-control-only-preparation) | 1–7 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-preparation.md | [Owned image and identity](native-configured-ban-preparation.md#owned-image-and-identity) | 8–23 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-preparation.md | [Planned traffic and gates](native-configured-ban-preparation.md#planned-traffic-and-gates) | 24–61 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-preparation.md | [Later live handoff and retirement](native-configured-ban-preparation.md#later-live-handoff-and-retirement) | 62–80 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-preparation.md | [Observed result](native-configured-ban-preparation.md#observed-result) | 81–86 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-witness.md | [Hotline Server 1.9 configured-address ban application](native-configured-ban-witness.md#hotline-server-19-configured-address-ban-application) | 1–13 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-witness.md | [Boundary and setup](native-configured-ban-witness.md#boundary-and-setup) | 14–36 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-witness.md | [One Add and Save](native-configured-ban-witness.md#one-add-and-save) | 37–69 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| native-configured-ban-witness.md | [Limits](native-configured-ban-witness.md#limits) | 70–78 | [GAP-044](#gap-044), [GAP-074](#gap-074) |
| diagnostic-formatting-trace.md | [Native 1.9 diagnostic text: formatting and wire length](diagnostic-formatting-trace.md#native-19-diagnostic-text-formatting-and-wire-length) | 1–9 | [GAP-037](#gap-037), [GAP-019](#gap-019) |
| diagnostic-formatting-trace.md | [Formatter-to-field trace](diagnostic-formatting-trace.md#formatter-to-field-trace) | 10–31 | [GAP-037](#gap-037), [GAP-019](#gap-019) |
| diagnostic-formatting-trace.md | [Observed lengths and compatibility](diagnostic-formatting-trace.md#observed-lengths-and-compatibility) | 32–57 | [GAP-037](#gap-037), [GAP-019](#gap-019) |
| diagnostic-formatting-trace.md | [Reproduction and limits](diagnostic-formatting-trace.md#reproduction-and-limits) | 58–77 | [GAP-037](#gap-037), [GAP-019](#gap-019) |
| native-ban-file-format.md | [Native Hotline Server 1.9 `Banned` data fork: observed v2 layout](native-ban-file-format.md#native-hotline-server-19-banned-data-fork-observed-v2-layout) | 1–36 | [GAP-074](#gap-074) |
| native-ban-file-format.md | [Reader and writer bounds](native-ban-file-format.md#reader-and-writer-bounds) | 37–65 | [GAP-074](#gap-074) |
| native-ban-file-format.md | [Request 110 reason-copy path](native-ban-file-format.md#request-110-reason-copy-path) | 66–89 | [GAP-074](#gap-074) |
| native-ban-file-format.md | [Replay and limits](native-ban-file-format.md#replay-and-limits) | 90–106 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Native temporary-ban expiry fixture preparation](native-ban-expiry-preparation.md#native-temporary-ban-expiry-fixture-preparation) | 1–6 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Scope and owned identities](native-ban-expiry-preparation.md#scope-and-owned-identities) | 7–38 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Prepared case order](native-ban-expiry-preparation.md#prepared-case-order) | 39–64 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Repeatable offline commands and live prerequisites](native-ban-expiry-preparation.md#repeatable-offline-commands-and-live-prerequisites) | 65–142 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Time and interpretation](native-ban-expiry-preparation.md#time-and-interpretation) | 143–156 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Verification and decision gates](native-ban-expiry-preparation.md#verification-and-decision-gates) | 157–174 | [GAP-074](#gap-074) |
| native-ban-expiry-preparation.md | [Observed first epoch](native-ban-expiry-preparation.md#observed-first-epoch) | 175–180 | [GAP-074](#gap-074) |
| native-roster-overlap-preparation.md | [Native roster overlap fixture preparation](native-roster-overlap-preparation.md#native-roster-overlap-fixture-preparation) | 1–11 | [GAP-035](#gap-035) |
| native-roster-overlap-preparation.md | [Plan and isolation](native-roster-overlap-preparation.md#plan-and-isolation) | 12–63 | [GAP-035](#gap-035) |
| native-roster-overlap-preparation.md | [Bounded causal sequence](native-roster-overlap-preparation.md#bounded-causal-sequence) | 64–107 | [GAP-035](#gap-035) |
| native-roster-overlap-preparation.md | [Verification and unresolved requirements](native-roster-overlap-preparation.md#verification-and-unresolved-requirements) | 108–129 | [GAP-035](#gap-035) |
| native-ban-expiry-cleanup.md | [Restore the owned ban-expiry accounts after the final probe](native-ban-expiry-cleanup.md#restore-the-owned-ban-expiry-accounts-after-the-final-probe) | 1–8 | [GAP-074](#gap-074) |
| native-ban-expiry-cleanup.md | [Guard, then delete](native-ban-expiry-cleanup.md#guard-then-delete) | 9–44 | [GAP-074](#gap-074) |
| native-ban-expiry-cleanup.md | [Postflight and evidence limits](native-ban-expiry-cleanup.md#postflight-and-evidence-limits) | 45–69 | [GAP-074](#gap-074) |
| native-ban-expiry-first-witness.md | [Native temporary-ban first epoch](native-ban-expiry-first-witness.md#native-temporary-ban-first-epoch) | 1–6 | [GAP-074](#gap-074) |
| native-ban-expiry-first-witness.md | [Reproducible record](native-ban-expiry-first-witness.md#reproducible-record) | 7–51 | [GAP-074](#gap-074) |
| native-ban-expiry-first-witness.md | [Offline replay](native-ban-expiry-first-witness.md#offline-replay) | 52–73 | [GAP-074](#gap-074) |
| native-ban-expiry-later-witness.md | [Native temporary-ban later epoch](native-ban-expiry-later-witness.md#native-temporary-ban-later-epoch) | 1–8 | [GAP-074](#gap-074), [GAP-072](#gap-072), [GAP-021](#gap-021) |
| native-ban-expiry-later-witness.md | [The missed pre-window](native-ban-expiry-later-witness.md#the-missed-pre-window) | 9–24 | [GAP-074](#gap-074), [GAP-072](#gap-072), [GAP-021](#gap-021) |
| native-ban-expiry-later-witness.md | [Later login and cleanup](native-ban-expiry-later-witness.md#later-login-and-cleanup) | 25–75 | [GAP-074](#gap-074), [GAP-072](#gap-072), [GAP-021](#gap-021) |
| native-ban-expiry-later-witness.md | [Offline replay and limits](native-ban-expiry-later-witness.md#offline-replay-and-limits) | 76–100 | [GAP-074](#gap-074), [GAP-072](#gap-072), [GAP-021](#gap-021) |
| native-roster-overlap-witness.md | [Native roster overlap witness](native-roster-overlap-witness.md#native-roster-overlap-witness) | 1–13 | [GAP-035](#gap-035) |
| native-roster-overlap-witness.md | [Scope and result](native-roster-overlap-witness.md#scope-and-result) | 14–81 | [GAP-035](#gap-035) |
| account-write-ordering.md | [Hotline Server 1.9 account write ordering](account-write-ordering.md#hotline-server-19-account-write-ordering) | 1–10 | [GAP-072](#gap-072), [GAP-021](#gap-021) |
| account-write-ordering.md | [Direct 353 replacement path](account-write-ordering.md#direct-353-replacement-path) | 11–51 | [GAP-072](#gap-072), [GAP-021](#gap-021) |
| account-write-ordering.md | [GAP-072 boundary](account-write-ordering.md#gap-072-boundary) | 52–68 | [GAP-072](#gap-072), [GAP-021](#gap-021) |
| native-liveness-preparation.md | [Native preonline liveness fixture preparation](native-liveness-preparation.md#native-preonline-liveness-fixture-preparation) | 1–7 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| native-liveness-preparation.md | [Source and case boundary](native-liveness-preparation.md#source-and-case-boundary) | 8–40 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| native-liveness-preparation.md | [Preflight and exact runner inputs](native-liveness-preparation.md#preflight-and-exact-runner-inputs) | 41–88 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| native-liveness-preparation.md | [Retained output and interpretation](native-liveness-preparation.md#retained-output-and-interpretation) | 89–114 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| classic-privilege-discovery.md | [Classic privilege editor string discovery](classic-privilege-discovery.md#classic-privilege-editor-string-discovery) | 1–18 | [GAP-031](#gap-031), [GAP-071](#gap-071) |
| classic-privilege-discovery.md | [What the queries found](classic-privilege-discovery.md#what-the-queries-found) | 19–60 | [GAP-031](#gap-031), [GAP-071](#gap-071) |
| native-liveness-witness.md | [Native preonline liveness witness](native-liveness-witness.md#native-preonline-liveness-witness) | 1–18 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| native-liveness-witness.md | [Finite results](native-liveness-witness.md#finite-results) | 19–73 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| native-liveness-witness.md | [Provenance and limits](native-liveness-witness.md#provenance-and-limits) | 74–97 | [GAP-005](#gap-005), [GAP-036](#gap-036) |
| legacy-board-format.md | [Native 1.9 legacy board format: static constants](legacy-board-format.md#native-19-legacy-board-format-static-constants) | 1–10 | [GAP-046](#gap-046) |
| legacy-board-format.md | [Pointers and literal bytes](legacy-board-format.md#pointers-and-literal-bytes) | 11–46 | [GAP-046](#gap-046) |
| native-board-preparation.md | [Isolated legacy message board fixture preparation](native-board-preparation.md#isolated-legacy-message-board-fixture-preparation) | 1–9 | [GAP-046](#gap-046), [GAP-084](#gap-084) |
| native-board-preparation.md | [Evidence and source boundaries](native-board-preparation.md#evidence-and-source-boundaries) | 10–30 | [GAP-046](#gap-046), [GAP-084](#gap-084) |
| native-board-preparation.md | [Separate guarded epochs](native-board-preparation.md#separate-guarded-epochs) | 31–115 | [GAP-046](#gap-046), [GAP-084](#gap-084) |
| native-board-preparation.md | [Readiness receipts and the aborted first lab](native-board-preparation.md#readiness-receipts-and-the-aborted-first-lab) | 116–129 | [GAP-046](#gap-046), [GAP-084](#gap-084) |
| native-board-readiness-failure.md | [Native board lab: aborted readiness](native-board-readiness-failure.md#native-board-lab-aborted-readiness) | 1–73 | [GAP-046](#gap-046), [GAP-084](#gap-084) |

## Maintaining this analysis

Edit gap-register.json as the canonical register and regenerate this report
with the command below. Keep IDs stable: add new entries, cross-link overlaps
and retain resolved/deferred records rather than renumbering or deleting them.
Assign an owner and record evidence as work progresses; do not automatically
close an entry because its containing document was rewritten.

For Resolved, record resolution.evidence with exact binary/client hashes or
repository revisions, queries/captures/test outputs, the updated document
section and the checked closure outcome. For Deferred, record the scope
decision, rationale and revisit condition under resolution.evidence; it
remains an unanswered protocol question. Update last_updated when changing the
register.

When an audited source changes, preserve the old dated snapshots, capture a
new source manifest/section inventory and refresh affected source ranges and
coverage after review. The check deliberately rejects source drift rather than
silently moving historical references. The baseline validity ledger and its
original snapshots remain immutable.

From the sibling mothra checkout:

```sh
python3 scripts/render-protocol-gap-analysis.py
python3 scripts/render-protocol-gap-analysis.py --check
make gap-check
```

The check validates snapshot/current-source hashes, references, IDs,
dependency acyclicity, section coverage and generated-report consistency.
