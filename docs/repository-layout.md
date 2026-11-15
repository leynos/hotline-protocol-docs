# Repository layout

This document explains where the protocol documentation, the evidence, the
tooling and the checks live, what each path holds, and who maintains it. The
tree below is complete for the top level and for `docs/`, `scripts/`, `tools/`,
`tests/` and `evidence/` to two levels. Files below the first level are shown
by family where a directory holds many similar files, so the tree is
illustrative for those, and the paths named in it are authoritative.

```plaintext
.
├── AGENTS.md                            Rules for contributors and agents
├── README.md                            Entry point for readers
├── Makefile                             Every gate, as a named target
├── gap-analysis.md                      Report generated from the gap register
├── gap-register.json                    Canonical list of open questions
├── docs/
│   ├── contents.md                      Index of every document
│   ├── repository-layout.md             This document
│   ├── glossary.md                      Terms the protocol documents use
│   ├── documentation-style-guide.md     Upstream conventions, copied verbatim
│   ├── baseline-validity-ledger.md      First static baseline, claim by claim
│   ├── execplans/                       Execution plans
│   ├── protocol/                        Set: the Hotline 1.9 protocol
│   ├── presence-and-messaging/          Set: presence, notifications, messages
│   ├── accounts-and-privileges/         Set: accounts, privileges, bans
│   ├── files-and-transfers/             Set: files, transfers, paths
│   ├── news/                            Set: news and the legacy board
│   ├── peers/                           Set: identified clients and peers
│   ├── mxd/                             Set: mxd validation
│   ├── native-evidence/                 Set: native preparations and witnesses
│   └── provenance/                      Set: baseline, handoff, remaining work
│       └── records/                     Working records of individual runs
├── evidence/                            Imported corpora and records; not edited
│   ├── gap-remediation/<date>/<corpus>/ Corpora from the remediation work
│   ├── hotline-server-1.9/              Corpus of the native server
│   ├── protocol-gap-analysis/<date>/revision-N/  Audit revisions
│   ├── curation.json                    Record of the imported corpora
│   ├── withheld.json                    Record of the withheld files
│   └── local-corpora.json               Record of corpora cut in this repository
├── scripts/                             Inherited capture planners and verifiers
│   ├── native_*_cases.py                Case planners for native captures
│   ├── native_*_control.py              Control runners for native fixtures
│   ├── verify_*.py                      Evidence verifiers
│   ├── test_*.py                        Unit tests of the scripts
│   ├── tests/                           Pytest tests of the inherited scripts
│   ├── fixtures/                        Fixture data read by the scripts
│   ├── render-protocol-gap-analysis.py  Renders gap-analysis.md; checks the audit
│   ├── legacy-modules.txt               Scripts held at the earlier lint rules
│   └── ruff.toml                        Lint rules for the legacy scripts
├── tools/                               Repository checks, curation and audit
│   ├── check_*.py                       Checks run by the gates
│   ├── curate_*.py                      Evidence curation and copying
│   ├── refresh_audit.py                 Writes new audit revisions
│   ├── capture_goldens.py               Records and compares goldens
│   ├── layout_*.py                      Document layout checks and rewriting
│   └── layout_moves.json                Record of the document moves
├── tests/                               Tests of the tools
│   └── goldens/                         Recorded outputs for goldens-check
├── fixtures/banner/                     Banner image samples and provenance.json
├── patches/                             Patches to retained sources
├── pyproject.toml                       Python project and lint configuration
├── uv.lock                              Locked Python dependencies
├── typos.toml                           Spelling configuration; generated
├── typos.local.toml                     Repository-specific spellings
├── json-exceptions.txt                  JSON files exempt from canonical layout
├── .markdownlint-cli2.jsonc             Markdown lint rules
└── .gitattributes                       Git LFS rules for captures and images
```

_Figure 1: The repository tree, with one line on each path._

## Who maintains each path

Each path is one of four kinds. Handwritten paths are edited directly.
Generated paths are produced by a tool and are never edited by hand. Imported
paths are copied from the mothra repository, are hash-pinned, and are never
edited. Record paths are written by the evidence import or the audit, and a
gate checks them.

_Table 1: What each top-level path holds, and who maintains it._

| Path                                | Holds                                                                                    | Maintained by                                                             |
| ----------------------------------- | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `AGENTS.md`                         | Rules for contributors and agents, including the rules that protect the evidence         | Handwritten                                                               |
| `README.md`                         | The reader's entry point, the only document that may address the reader                  | Handwritten                                                               |
| `Makefile`                          | Every gate, as a named target                                                            | Handwritten                                                               |
| `gap-register.json`                 | The canonical list of open questions                                                     | Handwritten; `AGENTS.md` names it the authority                           |
| `gap-analysis.md`                   | The report generated from the gap register                                               | Generated; never edit                                                     |
| `docs/`                             | The protocol documentation, in sets                                                      | Handwritten                                                               |
| `docs/documentation-style-guide.md` | The upstream conventions every document follows                                          | Upstream copy; never edit                                                 |
| `docs/baseline-validity-ledger.md`  | The first static baseline                                                                | Handwritten and hash-pinned; not reflowed                                 |
| `evidence/`                         | Imported corpora, audit revisions and the records of the import                          | Imported and hash-pinned; never edit                                      |
| `scripts/`                          | Inherited capture planners, verifiers and their tests                                    | Handwritten; held at the earlier lint rules until brought to the standard |
| `tools/`                            | The repository's own checks, curation, audit and layout tools                            | Handwritten                                                               |
| `tests/`                            | Tests of the tools, and the recorded goldens                                             | Handwritten; the goldens are generated by `tools/capture_goldens.py`      |
| `fixtures/`                         | Banner image samples, read by `scripts/native_banner_formats.py`, with `provenance.json` | Committed; see `provenance.json`                                          |
| `patches/`                          | The compatibility patch for the historical shx build, used by `scripts/build-shx.py`     | Committed; handwritten patch                                              |
| `typos.toml`                        | The spelling configuration                                                               | Generated; never edit                                                     |
| `typos.local.toml`                  | Repository-specific spellings, as exact patterns                                         | Handwritten                                                               |
| `json-exceptions.txt`               | JSON files exempt from canonical layout, by hash                                         | Handwritten                                                               |
| `.markdownlint-cli2.jsonc`          | Markdown lint rules                                                                      | Handwritten                                                               |
| `.gitattributes`                    | Git LFS rules for PNG, PCAP and gzip evidence                                            | Handwritten                                                               |

## The evidence directory

The `evidence/` directory is imported and hash-pinned. Nothing in it is
reformatted or linted, because its bytes are covered by recorded hashes. It has
three families of corpora and three records.

_Table 2: The three families of corpora in `evidence/`._

| Family                                     | Holds                                                                                                                                                          | Maintained by                                     |
| ------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `gap-remediation/<date>/<corpus>/`         | One directory per corpus, dated by the day its work was done; each holds the manifest, plans, captures, reports, verifiers and checksums that the corpus needs | Imported and hash-pinned                          |
| `hotline-server-1.9/`                      | The corpus of the native Hotline Server 1.9: its manifest, claims, dispatcher map, query records and `SHA256SUMS`                                              | Imported and hash-pinned                          |
| `protocol-gap-analysis/<date>/revision-N/` | One audit revision, with its `manifest.json`, `sections.json`, `SHA256SUMS` and the `inputs/` copies of the documents it reviewed                              | Generated by `tools/refresh_audit.py`; never edit |

_Table 3: The records at the top of `evidence/`._

| Record               | What it records                                                                                                                                           | Maintained by       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------- |
| `curation.json`      | Which corpora were imported from which mothra commit, and why each was included or excluded; `make curation-check` verifies the imported files against it | The evidence import |
| `withheld.json`      | The forks of the native binary that are withheld, with their sizes, hashes and any patch; `make withheld-check` verifies it                               | The evidence import |
| `local-corpora.json` | The four audit revisions cut in this repository (`revision-90` to `revision-93`), with the reason for each                                                | The audit           |

## Where the documents were

Documents that once sat at the repository root, or under flat names in `docs/`,
now sit in the sets under `docs/`. Each document kept its file name and its
headings; only the targets of its relative links changed. The move is recorded
in `tools/layout_moves.json`, and the table below is taken from it. It omits
the eight mxd notes, which the next table covers. `gap-analysis.md`,
`gap-register.json` and `docs/baseline-validity-ledger.md` are not in either
table: they are at the paths shown in the tree.

_Table 4: Where each document was moved from, with its present path._

| Old path                                     | Present path                                                                                                                          |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| `account-attribute-trace.md`                 | [`docs/accounts-and-privileges/account-attribute-trace.md`](accounts-and-privileges/account-attribute-trace.md)                       |
| `account-write-ordering.md`                  | [`docs/accounts-and-privileges/account-write-ordering.md`](accounts-and-privileges/account-write-ordering.md)                         |
| `alias-record-v2.md`                         | [`docs/files-and-transfers/alias-record-v2.md`](files-and-transfers/alias-record-v2.md)                                               |
| `baseline-correction-map.md`                 | [`docs/provenance/baseline-correction-map.md`](provenance/baseline-correction-map.md)                                                 |
| `bitmap-boundaries.md`                       | [`docs/protocol/bitmap-boundaries.md`](protocol/bitmap-boundaries.md)                                                                 |
| `classic-account-constructors.md`            | [`docs/accounts-and-privileges/classic-account-constructors.md`](accounts-and-privileges/classic-account-constructors.md)             |
| `classic-field161-matrix.md`                 | [`docs/peers/classic-field161-matrix.md`](peers/classic-field161-matrix.md)                                                           |
| `classic-login-proxy.md`                     | [`docs/peers/classic-login-proxy.md`](peers/classic-login-proxy.md)                                                                   |
| `classic-native-baseline.md`                 | [`docs/peers/classic-native-baseline.md`](peers/classic-native-baseline.md)                                                           |
| `classic-privilege-discovery.md`             | [`docs/accounts-and-privileges/classic-privilege-discovery.md`](accounts-and-privileges/classic-privilege-discovery.md)               |
| `classic-roster-subject-115.md`              | [`docs/peers/classic-roster-subject-115.md`](peers/classic-roster-subject-115.md)                                                     |
| `classic-server-name-162.md`                 | [`docs/peers/classic-server-name-162.md`](peers/classic-server-name-162.md)                                                           |
| `core-field-schemas.md`                      | [`docs/protocol/core-field-schemas.md`](protocol/core-field-schemas.md)                                                               |
| `date-contracts.md`                          | [`docs/protocol/date-contracts.md`](protocol/date-contracts.md)                                                                       |
| `diagnostic-formatting-trace.md`             | [`docs/protocol/diagnostic-formatting-trace.md`](protocol/diagnostic-formatting-trace.md)                                             |
| `diagnostic-replies.md`                      | [`docs/protocol/diagnostic-replies.md`](protocol/diagnostic-replies.md)                                                               |
| `diagnostic-transfer-boundaries.md`          | [`docs/protocol/diagnostic-transfer-boundaries.md`](protocol/diagnostic-transfer-boundaries.md)                                       |
| `docs/delegation/classic-proxy-rehearsal.md` | [`docs/provenance/records/classic-proxy-rehearsal.md`](provenance/records/classic-proxy-rehearsal.md)                                 |
| `docs/delegation/mac-peer-candidate.md`      | [`docs/provenance/records/mac-peer-candidate.md`](provenance/records/mac-peer-candidate.md)                                           |
| `docs/delegation/mxd-peer-runtime.md`        | [`docs/provenance/records/mxd-peer-runtime.md`](provenance/records/mxd-peer-runtime.md)                                               |
| `docs/execplans/missing-target-alias.md`     | [`docs/provenance/records/missing-target-alias.md`](provenance/records/missing-target-alias.md)                                       |
| `docs/native-clock-evidence.md`              | [`docs/native-evidence/native-clock-evidence.md`](native-evidence/native-clock-evidence.md)                                           |
| `docs/protocol-handoff.md`                   | [`docs/provenance/protocol-handoff.md`](provenance/protocol-handoff.md)                                                               |
| `error-outcomes.md`                          | [`docs/protocol/error-outcomes.md`](protocol/error-outcomes.md)                                                                       |
| `evidence-portability.md`                    | [`docs/provenance/evidence-portability.md`](provenance/evidence-portability.md)                                                       |
| `failure-representatives.md`                 | [`docs/protocol/failure-representatives.md`](protocol/failure-representatives.md)                                                     |
| `filesystem-and-board-contracts.md`          | [`docs/files-and-transfers/filesystem-and-board-contracts.md`](files-and-transfers/filesystem-and-board-contracts.md)                 |
| `identified-client-source.md`                | [`docs/peers/identified-client-source.md`](peers/identified-client-source.md)                                                         |
| `legacy-board-format.md`                     | [`docs/news/legacy-board-format.md`](news/legacy-board-format.md)                                                                     |
| `mac-peer-first-session.md`                  | [`docs/peers/mac-peer-first-session.md`](peers/mac-peer-first-session.md)                                                             |
| `mac-peer-isolated-session.md`               | [`docs/peers/mac-peer-isolated-session.md`](peers/mac-peer-isolated-session.md)                                                       |
| `native-104-variants.md`                     | [`docs/presence-and-messaging/native-104-variants.md`](presence-and-messaging/native-104-variants.md)                                 |
| `native-121-default-preparation.md`          | [`docs/native-evidence/native-121-default-preparation.md`](native-evidence/native-121-default-preparation.md)                         |
| `native-121-default-witness.md`              | [`docs/native-evidence/native-121-default-witness.md`](native-evidence/native-121-default-witness.md)                                 |
| `native-ban-control-preparation.md`          | [`docs/native-evidence/native-ban-control-preparation.md`](native-evidence/native-ban-control-preparation.md)                         |
| `native-ban-control-witness.md`              | [`docs/native-evidence/native-ban-control-witness.md`](native-evidence/native-ban-control-witness.md)                                 |
| `native-ban-expiry-cleanup.md`               | [`docs/native-evidence/native-ban-expiry-cleanup.md`](native-evidence/native-ban-expiry-cleanup.md)                                   |
| `native-ban-expiry-first-witness.md`         | [`docs/native-evidence/native-ban-expiry-first-witness.md`](native-evidence/native-ban-expiry-first-witness.md)                       |
| `native-ban-expiry-later-witness.md`         | [`docs/native-evidence/native-ban-expiry-later-witness.md`](native-evidence/native-ban-expiry-later-witness.md)                       |
| `native-ban-expiry-preparation.md`           | [`docs/native-evidence/native-ban-expiry-preparation.md`](native-evidence/native-ban-expiry-preparation.md)                           |
| `native-ban-file-format.md`                  | [`docs/accounts-and-privileges/native-ban-file-format.md`](accounts-and-privileges/native-ban-file-format.md)                         |
| `native-ban-notices.md`                      | [`docs/presence-and-messaging/native-ban-notices.md`](presence-and-messaging/native-ban-notices.md)                                   |
| `native-ban-reload-witness.md`               | [`docs/native-evidence/native-ban-reload-witness.md`](native-evidence/native-ban-reload-witness.md)                                   |
| `native-board-preparation.md`                | [`docs/native-evidence/native-board-preparation.md`](native-evidence/native-board-preparation.md)                                     |
| `native-board-readiness-failure.md`          | [`docs/native-evidence/native-board-readiness-failure.md`](native-evidence/native-board-readiness-failure.md)                         |
| `native-board-witness.md`                    | [`docs/native-evidence/native-board-witness.md`](native-evidence/native-board-witness.md)                                             |
| `native-capture-workflow.md`                 | [`docs/native-evidence/native-capture-workflow.md`](native-evidence/native-capture-workflow.md)                                       |
| `native-configured-ban-preparation.md`       | [`docs/native-evidence/native-configured-ban-preparation.md`](native-evidence/native-configured-ban-preparation.md)                   |
| `native-configured-ban-static.md`            | [`docs/accounts-and-privileges/native-configured-ban-static.md`](accounts-and-privileges/native-configured-ban-static.md)             |
| `native-configured-ban-ui-resources.md`      | [`docs/accounts-and-privileges/native-configured-ban-ui-resources.md`](accounts-and-privileges/native-configured-ban-ui-resources.md) |
| `native-configured-ban-witness.md`           | [`docs/native-evidence/native-configured-ban-witness.md`](native-evidence/native-configured-ban-witness.md)                           |
| `native-console-broadcast.md`                | [`docs/presence-and-messaging/native-console-broadcast.md`](presence-and-messaging/native-console-broadcast.md)                       |
| `native-control-readiness.md`                | [`docs/native-evidence/native-control-readiness.md`](native-evidence/native-control-readiness.md)                                     |
| `native-diagnostic-boundary-preparation.md`  | [`docs/native-evidence/native-diagnostic-boundary-preparation.md`](native-evidence/native-diagnostic-boundary-preparation.md)         |
| `native-diagnostic-density-witness.md`       | [`docs/native-evidence/native-diagnostic-density-witness.md`](native-evidence/native-diagnostic-density-witness.md)                   |
| `native-diagnostic-existing-preparation.md`  | [`docs/native-evidence/native-diagnostic-existing-preparation.md`](native-evidence/native-diagnostic-existing-preparation.md)         |
| `native-diagnostic-existing-witness.md`      | [`docs/native-evidence/native-diagnostic-existing-witness.md`](native-evidence/native-diagnostic-existing-witness.md)                 |
| `native-diagnostic-near-preparation.md`      | [`docs/native-evidence/native-diagnostic-near-preparation.md`](native-evidence/native-diagnostic-near-preparation.md)                 |
| `native-diagnostic-near-witness.md`          | [`docs/native-evidence/native-diagnostic-near-witness.md`](native-evidence/native-diagnostic-near-witness.md)                         |
| `native-download-send-path.md`               | [`docs/files-and-transfers/native-download-send-path.md`](files-and-transfers/native-download-send-path.md)                           |
| `native-liveness-preparation.md`             | [`docs/native-evidence/native-liveness-preparation.md`](native-evidence/native-liveness-preparation.md)                               |
| `native-liveness-witness.md`                 | [`docs/native-evidence/native-liveness-witness.md`](native-evidence/native-liveness-witness.md)                                       |
| `native-missing-alias-preparation.md`        | [`docs/native-evidence/native-missing-alias-preparation.md`](native-evidence/native-missing-alias-preparation.md)                     |
| `native-path-fields-preparation.md`          | [`docs/native-evidence/native-path-fields-preparation.md`](native-evidence/native-path-fields-preparation.md)                         |
| `native-path-fields.md`                      | [`docs/files-and-transfers/native-path-fields.md`](files-and-transfers/native-path-fields.md)                                         |
| `native-pm-preparation.md`                   | [`docs/native-evidence/native-pm-preparation.md`](native-evidence/native-pm-preparation.md)                                           |
| `native-pm-witness.md`                       | [`docs/native-evidence/native-pm-witness.md`](native-evidence/native-pm-witness.md)                                                   |
| `native-rate304-first-pair.md`               | [`docs/native-evidence/native-rate304-first-pair.md`](native-evidence/native-rate304-first-pair.md)                                   |
| `native-rate304-preparation.md`              | [`docs/native-evidence/native-rate304-preparation.md`](native-evidence/native-rate304-preparation.md)                                 |
| `native-rate304-sequence.md`                 | [`docs/native-evidence/native-rate304-sequence.md`](native-evidence/native-rate304-sequence.md)                                       |
| `native-rate304-startup-gate.md`             | [`docs/native-evidence/native-rate304-startup-gate.md`](native-evidence/native-rate304-startup-gate.md)                               |
| `native-roster-overlap-preparation.md`       | [`docs/native-evidence/native-roster-overlap-preparation.md`](native-evidence/native-roster-overlap-preparation.md)                   |
| `native-roster-overlap-witness.md`           | [`docs/native-evidence/native-roster-overlap-witness.md`](native-evidence/native-roster-overlap-witness.md)                           |
| `native-settings-persistence-preparation.md` | [`docs/native-evidence/native-settings-persistence-preparation.md`](native-evidence/native-settings-persistence-preparation.md)       |
| `native-settings-persistence-witness.md`     | [`docs/native-evidence/native-settings-persistence-witness.md`](native-evidence/native-settings-persistence-witness.md)               |
| `native-settings-preparation.md`             | [`docs/native-evidence/native-settings-preparation.md`](native-evidence/native-settings-preparation.md)                               |
| `native-settings-transition-prep.md`         | [`docs/native-evidence/native-settings-transition-prep.md`](native-evidence/native-settings-transition-prep.md)                       |
| `native-settings-transition-witness.md`      | [`docs/native-evidence/native-settings-transition-witness.md`](native-evidence/native-settings-transition-witness.md)                 |
| `native-settings-witness.md`                 | [`docs/native-evidence/native-settings-witness.md`](native-evidence/native-settings-witness.md)                                       |
| `native-transfer-stall.md`                   | [`docs/files-and-transfers/native-transfer-stall.md`](files-and-transfers/native-transfer-stall.md)                                   |
| `native-ui-focus-witness.md`                 | [`docs/native-evidence/native-ui-focus-witness.md`](native-evidence/native-ui-focus-witness.md)                                       |
| `native-wire-details.md`                     | [`docs/protocol/native-wire-details.md`](protocol/native-wire-details.md)                                                             |
| `news-contracts.md`                          | [`docs/news/news-contracts.md`](news/news-contracts.md)                                                                               |
| `notification-104-variants.md`               | [`docs/presence-and-messaging/notification-104-variants.md`](presence-and-messaging/notification-104-variants.md)                     |
| `operation-contracts.md`                     | [`docs/protocol/operation-contracts.md`](protocol/operation-contracts.md)                                                             |
| `parameter-multiplicity.md`                  | [`docs/protocol/parameter-multiplicity.md`](protocol/parameter-multiplicity.md)                                                       |
| `peer-profile-rules.md`                      | [`docs/peers/peer-profile-rules.md`](peers/peer-profile-rules.md)                                                                     |
| `peer-tolerance-matrix.md`                   | [`docs/peers/peer-tolerance-matrix.md`](peers/peer-tolerance-matrix.md)                                                               |
| `presence-defaults.md`                       | [`docs/presence-and-messaging/presence-defaults.md`](presence-and-messaging/presence-defaults.md)                                     |
| `presence-messaging-contracts.md`            | [`docs/presence-and-messaging/presence-messaging-contracts.md`](presence-and-messaging/presence-messaging-contracts.md)               |
| `privilege-bits.md`                          | [`docs/accounts-and-privileges/privilege-bits.md`](accounts-and-privileges/privilege-bits.md)                                         |
| `privilege-contracts.md`                     | [`docs/accounts-and-privileges/privilege-contracts.md`](accounts-and-privileges/privilege-contracts.md)                               |
| `protocol.md`                                | [`docs/protocol/protocol.md`](protocol/protocol.md)                                                                                   |
| `rate304-contract.md`                        | [`docs/presence-and-messaging/rate304-contract.md`](presence-and-messaging/rate304-contract.md)                                       |
| `rate304-recipient-predicate.md`             | [`docs/presence-and-messaging/rate304-recipient-predicate.md`](presence-and-messaging/rate304-recipient-predicate.md)                 |
| `receive-limit-origin.md`                    | [`docs/protocol/receive-limit-origin.md`](protocol/receive-limit-origin.md)                                                           |
| `request-500-contract.md`                    | [`docs/protocol/request-500-contract.md`](protocol/request-500-contract.md)                                                           |
| `runtime-recovery-20261113.md`               | [`docs/native-evidence/runtime-recovery-20261113.md`](native-evidence/runtime-recovery-20261113.md)                                   |
| `session-transport-contracts.md`             | [`docs/protocol/session-transport-contracts.md`](protocol/session-transport-contracts.md)                                             |
| `shx-peer.md`                                | [`docs/peers/shx-peer.md`](peers/shx-peer.md)                                                                                         |
| `transfer-contracts.md`                      | [`docs/files-and-transfers/transfer-contracts.md`](files-and-transfers/transfer-contracts.md)                                         |

The eight mxd notes were consolidated into the six documents of the mxd set,
rather than moved one for one. Where the notes disagreed and the evidence did
not decide, the consolidated text keeps both statements, each attributed to its
note, in a paragraph that begins "Unreconciled:". The mapping below comes from
the opening paragraphs of the documents and from the attributions in
[the mxd overview](mxd/README.md).

_Table 5: The eight mxd notes and the documents that took their content._

| Old note                           | Present document                                            | Basis                                                                                                                           |
| ---------------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- |
| `mxd-validation.md`                | [Validation status](mxd/validation-status.md)               | Its Unreconciled notes record the canonical revision and the validation record it gives                                         |
| `internal-compatibility-matrix.md` | [Compatibility matrix](mxd/compatibility-matrix.md)         | Validation status says the note is now the compatibility matrix; the assertion reconciliation also draws on its review sections |
| `mxd-reconciliation.md`            | [Assertion reconciliation](mxd/assertion-reconciliation.md) | Its closing section says it was consolidated from this note and the review sections of the matrix note                          |
| `mxd-direct-ack-correction.md`     | [Accepted corrections](mxd/corrections.md)                  | The "Direct replies" section                                                                                                    |
| `mxd-login-extras-correction.md`   | [Accepted corrections](mxd/corrections.md)                  | The "Login extras" section                                                                                                      |
| `mxd-limit-contracts.md`           | [Accepted corrections](mxd/corrections.md)                  | The "Framing limits" section                                                                                                    |
| `mxd-classic-login.md`             | [Classic client trials](mxd/classic-client-trials.md)       | The failed Classic login trial; validation status records what this note reports about it                                       |
| `mxd-peer-capture-workflow.md`     | [Classic client trials](mxd/classic-client-trials.md)       | Its opening paragraph describes the procedure for running a Classic peer against the fixture                                    |

Note that the layout tool's `moves` table still maps the eight old mxd notes to
`docs/mxd/` paths of the same names. Those paths do not exist; the table above
gives the documents that now hold the content.
