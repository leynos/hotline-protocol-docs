"""Name the transaction types, field IDs and record offsets of the native checks.

Each name follows the document that fixes its meaning, so that a number in a
planner or verifier reads as the protocol term and not as a bare literal:

* ``operation-contracts.md`` lists the transaction types and their direction;
* ``core-field-schemas.md`` lists the field IDs of the core operations;
* ``native-wire-details.md`` gives the stored account-record layout;
* ``transfer-contracts.md`` and ``native-wire-details.md`` give the transfer
  operations, their reference, size and queue-position fields.

Nothing here is inferred. A value whose document leaves its purpose open keeps
a name that says so.
"""

# Transaction types (operation-contracts.md, "Request inventory").
TYPE_MESSAGE_NOTIFICATION = 104  # routed PM, feedback, denial and kick notices
TYPE_LOGIN = 107
TYPE_SEND_PRIVATE_MESSAGE = 108
TYPE_LOGIN_AGREEMENT = 109
TYPE_ACCEPT_AGREEMENT = 121
TYPE_DOWNLOAD_FILE = 202
TYPE_QUEUE_NOTIFICATION = 211  # transfer-contracts.md, "Queue notification 211"
TYPE_REFERENCE_CLEANUP = 214  # owner-matched cleanup of a transfer reference
TYPE_GET_USER_ROSTER = 300
TYPE_PRESENCE_UPDATE = 301
TYPE_USER_LEFT = 302  # presence-messaging-contracts.md, "Disconnect teardown"
TYPE_SET_CLIENT_INFO = 304
TYPE_ENUMERATE_ACCOUNTS = 348
TYPE_CREATE_ACCOUNT = 350
TYPE_GET_ACCOUNT = 352
TYPE_UPDATE_ACCOUNT = 353
TYPE_PRIVILEGES_NOTIFICATION = 354  # login completion or changed live privileges
TYPE_EMPTY_ACK = 500  # the undocumented operation that only acknowledges

# Field IDs (core-field-schemas.md).
FIELD_ERROR_TEXT = 100  # status 1 replies carry their text here
FIELD_DATA = 101  # byte string; PM text, agreement text, nested account records
FIELD_NAME = 102
FIELD_USER_ID = 103
FIELD_ICON = 104
FIELD_LOGIN = 105  # complemented on the wire
FIELD_PASSWORD = 106  # complemented on the wire
FIELD_TRANSFER_REFERENCE = 107  # four bytes; the reference of a queued transfer
FIELD_TRANSFER_SIZE = 108  # byte length of the transfer in an ACK
FIELD_ACCESS_BITMAP = 110  # eight bytes, most significant bit first
FIELD_ACCOUNT_ATTRIBUTE = 111  # opaque account attribute (GAP-071)
FIELD_OPTIONS = 113  # low bits: PM refusal, chat refusal, automatic response
FIELD_QUEUE_POSITION = 116  # numeric; zero means admission from the queue
FIELD_VERSION = 160  # reported version; a native success reply carries 190
FIELD_UNNAMED_WORD = 161  # unnamed word that a native success reply zeroes
FIELD_FILE_NAME = 201  # native-wire-details.md, transfer and file requests
FIELD_TRANSFER_OPTION = 204  # transfer-contracts.md: 2 selects a download preview
FIELD_FILE_SIZE = 207  # logical file size in a transfer ACK
FIELD_QUOTE = 214  # quoted text of a private message
FIELD_AUTO_RESPONSE = 215  # automatic-response text, at most 127 bytes

# Physical frame (native-wire-details.md): flags, reply, type, ID, error, total
# size and data size, then the data.
FRAME_HEADER_FORMAT = ">BBHIIII"
FRAME_HEADER_BYTES = 20
FRAME_SIZE_START = 16  # the data size is the last four header bytes
EMPTY_PAYLOAD = b"\0\0"  # a count word of zero fields

# Session start (session-transport-contracts.md): the client sends `TRTP HOTL
# 0001 0002`, a normal session; the server answers `TRTP` and a zero BE32 result.
HANDSHAKE_REQUEST_HEX = "54525450484f544c00010002"
HANDSHAKE_REPLY_HEX = "5452545000000000"
HANDSHAKE_REPLY_BYTES = 8

# Stored account record (native-wire-details.md, "Account record and field
# schema"): 734 bytes, each text field as a BE16 length then its bytes.
ACCOUNT_RECORD_BYTES = 734
ACCOUNT_ATTRIBUTE_LENGTH_OFFSET = 0x254
ACCOUNT_ATTRIBUTE_OFFSET = 0x256
ACCOUNT_PASSWORD_LENGTH_OFFSET = 0x2BC
ACCOUNT_PASSWORD_OFFSET = 0x2BE
