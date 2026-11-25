# Baseline correction map

This revision applies the 12 November 2026
[Hotline 1.9 validity ledger](../baseline-validity-ledger.md) to
[protocol.md](../protocol/protocol.md) and the
[compatibility matrix](../mxd/compatibility-matrix.md).

This document belongs to the [provenance](README.md) set; the
[glossary](../glossary.md) defines the terms it uses.

The ledger and its preserved input/evidence snapshots remain unchanged. Its
line references refer to the original documents, not these revised files. All
83 entries have a disposition below. A qualified or unresolved claim has not
been promoted to verified behaviour simply because the document was edited.

This table preserves the initial correction dispositions, including then-open
claims. Subsequent findings and closures are tracked in the
[gap analysis](../../gap-analysis.md) and linked supplements; for example,
password representation and native 111/302 producers are now traced. The
original ledger statuses and evidence remain historical rather than being
rewritten.

The evidence checkout is the sibling `mothra` repository in this workspace.
Keep that checkout or the hashed evidence package available when reviewing
these provenance links. No mxd source change or new interoperability test
execution is asserted by this documentation revision.

The [gap analysis](../../gap-analysis.md) tracks the unresolved work after
these corrections. A correction disposition is not evidence that its broader
feature has a complete, validated specification.

| Ledger entry | Original status | Revised section                                                                         | Disposition                                                                              |
| ------------ | --------------- | --------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| V001         | Doc defect      | [Section](../protocol/protocol.md#additional-observed-requests-and-scope-gaps)          | Retitled for 1.9 and removed the exhaustive-catalogue claim.                             |
| V002         | Supported       | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Retained the big-endian, unpadded twenty-byte envelope.                                  |
| V003         | Contradicted    | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Required HOTL rather than arbitrary sub-protocol tags.                                   |
| V004         | Contradicted    | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Recorded normal-session mode 2 and the distinct mode-3 path.                             |
| V005         | Supported       | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Retained the eight-byte handshake reply.                                                 |
| V006         | Doc defect      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Required consumption/checking of both reply magic and status.                            |
| V007         | Supported       | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Retained reply correlation by request ID.                                                |
| V008         | Partial         | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Separated server ID generation and mxd policy from unverified peer acceptance.           |
| V009         | Partial         | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Described observed accumulation without certifying every fragment invariant.             |
| V010         | Unverified      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Marked fragment consistency and malformed-input behaviour unresolved.                    |
| V011         | Contradicted    | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Specified a zero-count payload and twenty-two-byte empty replies.                        |
| V012         | Partial         | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Separated emitted zero flags from receiver policy; removed mandatory disconnect notice.  |
| V013         | Supported       | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Retained count-prefixed TLVs and the native value-length limit.                          |
| V014         | Contradicted    | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Removed global uniqueness and listed multiple valid repetition contexts.                 |
| V015         | Partial         | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Separated two/four-byte writer convention from one-byte reader acceptance.               |
| V016         | Unverified      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Kept text byte-oriented; left per-field encoding unresolved.                             |
| V017         | Partial         | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Documented the observed 1904/zero/timestamp form; withdrew the unvalidated conversion.   |
| V018         | Doc defect      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Recounted the explicit example to twenty-one payload bytes and forty-one frame bytes.    |
| V019         | Contradicted    | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Complemented the example login bytes and bounded the credential claims.                  |
| V020         | Unverified      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Removed unsupported claims about client fragmentation frequency.                         |
| V021         | Doc defect      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Recorded the image size-limit value without treating it as immutable at runtime.         |
| V022         | Doc defect      | [Section](../protocol/protocol.md#binary-message-formats-hotline-protocol-19)           | Documented zero type in native direct replies.                                           |
| V023         | Supported       | [Section](../protocol/protocol.md#user-login-and-presence)                              | Retained login fields, optional name/icon and native version value 190.                  |
| V024         | Partial         | [Section](../protocol/protocol.md#user-login-and-presence)                              | Recorded unconditional native extras; separated the matrix omission policy.              |
| V025         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Separated agreement 109, banner metadata 122 and banner fetch 212.                       |
| V026         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Corrected transaction 121 to ACK before applying settings.                               |
| V027         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Documented early completion via name/icon as well as completion through 121.             |
| V028         | Supported       | [Section](../protocol/protocol.md#user-login-and-presence)                              | Retained settings bits and default automatic-response text.                              |
| V029         | Supported       | [Section](../protocol/protocol.md#user-login-and-presence)                              | Specified an eight-byte field-110 notification.                                          |
| V030         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Corrected private messaging to bit 40; added folder bits 38/39 and left gaps unassigned. |
| V031         | Doc defect      | [Section](../protocol/protocol.md#user-login-and-presence)                              | Defined MSB-first bit numbering in transmitted bytes.                                    |
| V032         | Supported       | [Section](../protocol/protocol.md#user-login-and-presence)                              | Retained the packed UID/icon/colour/name-length/name record.                             |
| V033         | Partial         | [Section](../protocol/protocol.md#user-login-and-presence)                              | Separated native roster output from the historical SynHX subject-field addition.         |
| V034         | Partial         | [Section](../protocol/protocol.md#user-login-and-presence)                              | Used zero-or-more structural entries without claiming empty-session reachability.        |
| V035         | Partial         | [Section](../protocol/protocol.md#user-login-and-presence)                              | Bounded 301 findings and marked 302 teardown details unresolved.                         |
| V036         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Replaced profile-text speculation with generated diagnostics.                            |
| V037         | Contradicted    | [Section](../protocol/protocol.md#user-login-and-presence)                              | Removed the promise that omitted settings always preserve old values.                    |
| V038         | Supported       | [Section](../protocol/protocol.md#user-login-and-presence)                              | Retained no normal direct success reply for 304.                                         |
| V039         | Supported       | [Section](../protocol/protocol.md#chat-public-and-private-chat-rooms)                   | Retained chat inputs, formatting/106 routing and no normal success ACK.                  |
| V040         | Supported       | [Section](../protocol/protocol.md#chat-public-and-private-chat-rooms)                   | Retained subject and repeated roster records in the join ACK.                            |
| V041         | Partial         | [Section](../protocol/protocol.md#chat-public-and-private-chat-rooms)                   | Documented explicit room notification send sites; left broader cleanup unresolved.       |
| V042         | Supported       | [Section](../protocol/protocol.md#chat-public-and-private-chat-rooms)                   | Retained repeated target UIDs and corrected the new-chat reply to describe the inviter.  |
| V043         | Supported       | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Retained message fields and enumerated option values, distinct from settings bits.       |
| V044         | Contradicted    | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Corrected private messages to ACK before routing.                                        |
| V045         | Contradicted    | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Recorded server-generated refusal/automatic response and delivery suppression.           |
| V046         | Contradicted    | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Corrected client-requested broadcasts to ACK plus type-355 delivery.                     |
| V047         | Contradicted    | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Retained implemented old-board read/post/update operations.                              |
| V048         | Unverified      | [Section](../protocol/protocol.md#private-messaging-instant-messages)                   | Removed speculative client-window/rendering promises.                                    |
| V049         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Retained list operation and explicit uncertainty about its exact records.                |
| V050         | Unverified      | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Marked structured paths unresolved rather than substituting strings or guessed IDs.      |
| V051         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Qualified download fields, preview handling and conditional reference/queue fields.      |
| V052         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Recorded upload resume option 1 and reply resume-data direction.                         |
| V053         | Contradicted    | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Corrected delete/create/rename/move/alias to success/error ACK operations.               |
| V054         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Documented branch-dependent info fields rather than universal four-character codes.      |
| V055         | Contradicted    | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Corrected folder-download privilege and conditional initiation reply fields.             |
| V056         | Contradicted    | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Corrected folder-upload privilege and successful no-reference case.                      |
| V057         | Unverified      | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Withdrew unvalidated exact folder-stream/control semantics.                              |
| V058         | Supported       | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Retained banner reference/size and type-2 transfer routing.                              |
| V059         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Recorded the incoming sixteen-byte HTXF acceptor while leaving its full layout open.     |
| V060         | Partial         | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Removed server-initiated queued connections; marked listener port arithmetic unverified. |
| V061         | Doc defect      | [Section](../protocol/protocol.md#file-services-files-and-folders)                      | Added request 214 with cleanup observation and provisional cancellation interpretation.  |
| V062         | Partial         | [Section](../protocol/protocol.md#news-bulletin-board-system)                           | Recorded literal threshold 15 and repeated category-list output.                         |
| V063         | Contradicted    | [Section](../protocol/protocol.md#news-bulletin-board-system)                           | Corrected article listing to one field 321 containing a serialized list.                 |
| V064         | Supported       | [Section](../protocol/protocol.md#news-bulletin-board-system)                           | Retained article input/output fields while qualifying navigation/flavour meanings.       |
| V065         | Contradicted    | [Section](../protocol/protocol.md#news-bulletin-board-system)                           | Corrected news mutation operations to success/error ACK operations.                      |
| V066         | Unverified      | [Section](../protocol/protocol.md#news-bulletin-board-system)                           | Removed fixed hierarchy and guessed recursive-deletion outcomes.                         |
| V067         | Contradicted    | [Section](../protocol/protocol.md#administrative-functions)                             | Corrected account mutation operations to ACK operations.                                 |
| V068         | Contradicted    | [Section](../protocol/protocol.md#administrative-functions)                             | Specified password-presence placeholder x and omission for empty passwords.              |
| V069         | Partial         | [Section](../protocol/protocol.md#administrative-functions)                             | Added unresolved account input field 111.                                                |
| V070         | Unverified      | [Section](../protocol/protocol.md#administrative-functions)                             | Marked account/session propagation and durable-storage behaviour unresolved.             |
| V071         | Contradicted    | [Section](../protocol/protocol.md#administrative-functions)                             | Corrected kick ACKs and separated option branches from guessed ban bits.                 |
| V072         | Contradicted    | [Section](../protocol/protocol.md#administrative-functions)                             | Recorded kick notices via 104; marked independent type-111 producers unresolved.         |
| V073         | Unverified      | [Section](../protocol/protocol.md#administrative-functions)                             | Withdrew unproven private-chat administrator overrides.                                  |
| V074         | Doc defect      | [Section](../protocol/protocol.md#additional-observed-requests-and-scope-gaps)          | Listed additional requests 348/349/500 without inventing complete schemas or names.      |
| M001         | Contradicted    | [Section](../mxd/compatibility-matrix.md#compatibility-matrix)                          | Removed the shared sub-version-2 discriminator.                                          |
| M002         | Unverified      | [Section](../mxd/compatibility-matrix.md#compatibility-matrix)                          | Reclassified version ranges as policy requiring client validation.                       |
| M003         | Unverified      | [Section](../mxd/compatibility-matrix.md#login-reply-and-banner-policy)                 | Separated historical server output from unproven client rejection/tolerance.             |
| M004         | Unverified      | [Section](../mxd/compatibility-matrix.md#login-reply-and-banner-policy)                 | Retained conservative omission only as an unverified mxd policy.                         |
| M005         | Unverified      | [Section](../mxd/compatibility-matrix.md#credential-obfuscation-and-text-compatibility) | Separated credential complementing from a universal text-XOR heuristic.                  |
| M006         | Contradicted    | [Section](../mxd/compatibility-matrix.md#repeated-fields-and-presence-records)          | Replaced the transaction-300-only repetition rule with schema-specific handling.         |
| M007         | Supported       | [Section](../mxd/compatibility-matrix.md#repeated-fields-and-presence-records)          | Retained the shared packed roster structure and qualified client scope.                  |
| M008         | Unverified      | [Section](../mxd/compatibility-matrix.md#historical-reported-mxd-test-coverage)         | Preserved supplied test citations as unverified rather than executed guarantees.         |
| M009         | Unverified      | [Section](../mxd/compatibility-matrix.md#open-compatibility-gaps-and-qa-requirements)   | Preserved roadmap/QA/proof pointers as historical references requiring verification.     |

_Table 1: The disposition of each ledger entry for the current revision, with
its original status and revised section._
