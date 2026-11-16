"""Name the routes, limits and variants of the Classic Login107 ACK proxy."""

import typing as typ

CLIENT_HELLO = bytes.fromhex("54525450484f544c00010002")
SERVER_HELLO = bytes.fromhex("5452545000000000")
type Variant = typ.Literal[
    "baseline",
    "omit-161",
    "one-byte-161",
    "four-byte-161",
    "server-name-162",
    "roster-subject-115",
]
VARIANTS = typ.get_args(Variant.__value__)
MAX_FRAME = 65535
IP_BIN = "/usr/sbin/ip"
DEADLINE_SECONDS = 180
OBSERVATION_SECONDS = 28
MAX_OBSERVATION_NS = 30_000_000_000
BACKENDS = {"control": 15500, "data": 15501}
LISTENERS = {"control": 15652, "data": 15653}
# The frame header plus the two-byte field count of a frame with no fields.
MIN_FRAME_BYTES = 22
# The bound, in bytes, on the encoded report.json of one proxy run.
FINAL_LOG_LIMIT = 1_000_000
