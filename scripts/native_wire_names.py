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
TYPE_SEND_CHAT = 105  # operation-contracts.md: its fan-out is a 106 push
TYPE_CHAT_NOTIFICATION = 106  # operation-contracts.md: "Chat fan-out"
TYPE_LOGIN = 107
TYPE_SEND_PRIVATE_MESSAGE = 108
TYPE_LOGIN_AGREEMENT = 109
TYPE_ACCEPT_AGREEMENT = 121
TYPE_BANNER_METADATA = 122  # operation-contracts.md: configured banner metadata
TYPE_LIST_FILES = 200  # operation-contracts.md: repeated 200 file entries
TYPE_DOWNLOAD_FILE = 202
TYPE_UPLOAD_FILE = 203
TYPE_GET_FILE_INFO = 206
TYPE_DOWNLOAD_BANNER = 212  # operation-contracts.md: banner reference and size ACK
TYPE_QUEUE_NOTIFICATION = 211  # transfer-contracts.md, "Queue notification 211"
TYPE_REFERENCE_CLEANUP = 214  # owner-matched cleanup of a transfer reference
TYPE_GET_USER_ROSTER = 300
TYPE_PRESENCE_UPDATE = 301
TYPE_USER_LEFT = 302  # presence-messaging-contracts.md, "Disconnect teardown"
TYPE_SET_CLIENT_INFO = 304
TYPE_ENUMERATE_ACCOUNTS = 348
TYPE_CREATE_ACCOUNT = 350
TYPE_DELETE_ACCOUNT = 351  # operation-contracts.md, "Request inventory"
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
FIELD_BANNER_TYPE = 152  # four-byte tag of a 122 notification (core-field-schemas.md)
FIELD_BANNER_LINK = 153  # optional link of a 122 notification
FIELD_AGREEMENT_BYPASS = 154  # scalar N of a 109 notification (core-field-schemas.md)
FIELD_VERSION = 160  # reported version; a native success reply carries 190
FIELD_UNNAMED_WORD = 161  # unnamed word that a native success reply zeroes
FIELD_SERVER_NAME = 162  # current server name of a login reply (core-field-schemas.md)
FIELD_FILE_NAME = 201  # native-wire-details.md, transfer and file requests
FIELD_RESUME_DATA = 203  # the RFLT resume descriptor (transfer-contracts.md)
FIELD_TRANSFER_OPTION = 204  # transfer-contracts.md: 2 selects a download preview
FIELD_FILE_SIZE = 207  # logical file size in a transfer ACK
FIELD_FILE_CREATOR = 206  # file-info reply: creator (filesystem-and-board-contracts.md)
FIELD_FILE_TYPE = 213  # file-info reply: raw type (filesystem-and-board-contracts.md)
FIELD_QUOTE = 214  # quoted text of a private message
FIELD_AUTO_RESPONSE = 215  # automatic-response text, at most 127 bytes

FIELD_FILE_ENTRY = 200  # repeated record of a 200 reply (native-wire-details.md)
FIELD_ROSTER_SUBJECT = 115  # optional subject of a 300 reply (core-field-schemas.md)
FIELD_USER_RECORD = 300  # repeated "U" field of a 300 reply (core-field-schemas.md)

# Packed roster record, "U" (core-field-schemas.md): BE16 UID, BE16 icon, BE16
# status and BE16 name length, then the name bytes.
ROSTER_HEADER_BYTES = 8
ROSTER_ICON_START = 2
ROSTER_STATUS_START = 4
ROSTER_NAME_LENGTH_START = 6

# File-list entry (native-wire-details.md, "File-list entry records"): type,
# creator, size, a zero word, a zero BE16 and the BE16 name length, then the name.
FILE_ENTRY_HEADER_BYTES = 20
FILE_ENTRY_NAME_LENGTH_START = 16

# Physical frame (native-wire-details.md): flags, reply, type, ID, error, total
# size and data size, then the data.
FRAME_HEADER_FORMAT = ">BBHIIII"
FRAME_HEADER_BYTES = 20
FRAME_SIZE_START = 16  # the data size is the last four header bytes
EMPTY_PAYLOAD = b"\0\0"  # a count word of zero fields
# session-transport-contracts.md: the server assigns `00080000` (512 KiB) as the
# bound that each frame's total and data sizes are compared with.
MAX_FRAME_BYTES = 524288

# Session start (session-transport-contracts.md): the client sends `TRTP HOTL
# 0001 0002`, a normal session; the server answers `TRTP` and a zero BE32 result.
HANDSHAKE_REQUEST_HEX = "54525450484f544c00010002"
HANDSHAKE_REPLY_HEX = "5452545000000000"
HANDSHAKE_REPLY_BYTES = 8
# session-transport-contracts.md: `TRTP HOTL 0001 0003` hands the connection to
# HTXF processing and queues the same success bytes.
HANDSHAKE_HANDOVER_REQUEST_HEX = "54525450484f544c00010003"

# core-field-schemas.md, "122 notification": the notification follows 121 only
# when the reported version is at least this.
BANNER_MIN_VERSION = 151

# Data connection (transfer-contracts.md, "HTXF"): the magic `HTXF`, the four
# byte reference, a four-byte size word, a two-byte selector and a reserved word.
HTXF_MAGIC_HEX = "48545846"
SELECTOR_FOLDER = 1  # with an odd reference: folder download
SELECTOR_BANNER = 2  # with an odd reference: banner download
PREVIEW_OPTION = 2  # field 204 on request 202: raw preview, no FILP wrapper
RESUME_OPTION = 1  # field 204 on request 203: resume an upload (native-wire-details.md)

# Flattened file (transfer-contracts.md, "Flattened ordinary-file stream"): a
# 24-byte file header, then three forks, each a 16-byte header and its value.
FILP_FILE_HEADER = b"FILP\0\1" + bytes(16) + b"\0\3"
FORK_HEADER_PADDING = 8  # zero bytes between the tag and the value length
FORK_LENGTH_BYTES = 4
# INFO value (transfer-contracts.md, "INFO metadata value").
INFO_TYPE_CREATOR = b"AMACTEXTMOTH"  # AMAC, then file type and creator
INFO_FLAGS_OFFSET = 16
INFO_NAME_LENGTH_OFFSET = 70
INFO_NAME_OFFSET = 72
INFO_FIXED_BYTES = 74  # the value is this plus the name and comment lengths

ACCESS_BITMAP_BYTES = 8  # core-field-schemas.md: A8 is an eight-byte bitmap

# Stored account record (native-wire-details.md, "Account record and field
# schema"): 734 bytes, each text field as a BE16 length then its bytes.
ACCOUNT_RECORD_BYTES = 734
ACCOUNT_ACCESS_OFFSET = 0x004  # the eight-byte access bitmap has no length word
ACCOUNT_NAME_LENGTH_OFFSET = 0x210
ACCOUNT_NAME_OFFSET = 0x212
ACCOUNT_ATTRIBUTE_LENGTH_OFFSET = 0x254
ACCOUNT_ATTRIBUTE_OFFSET = 0x256
ACCOUNT_LOGIN_LENGTH_OFFSET = 0x298
ACCOUNT_LOGIN_OFFSET = 0x29A
ACCOUNT_PASSWORD_LENGTH_OFFSET = 0x2BC
ACCOUNT_PASSWORD_OFFSET = 0x2BE


# Resume descriptor (transfer-contracts.md, "Resume data: RFLT"): a 6-byte header
# of magic and version, 34 bytes that the consumer does not read, a BE16 entry
# count, then 16-byte entries of fork tag, BE32 offset and 8 unread bytes.
RFLT_MAGIC = b"RFLT"
RFLT_VERSION = b"\0\1"
RFLT_HEADER_PADDING = 34
RFLT_ENTRY_PADDING = 8
RFLT_MIN_BYTES = 42  # the shortest descriptor the download consumer accepts

# Login normalization (native-wire-details.md, "Account lookup name encodings"):
# the complemented login passes through a 256-byte table at this address.
LOGIN_TABLE_ADDRESS = "100946c8"
LOGIN_TABLE_BYTES = 256
