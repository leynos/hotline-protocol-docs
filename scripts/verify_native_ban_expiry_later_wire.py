"""Name the identities, ports and limits that the later temporary-ban replay checks.

The values are the ones that the later epoch was recorded with. A value that a
check compares against is named here, so that the checks read as statements.
"""

SCHEMA = "native-ban-expiry-later-01"
PID, START, NS, INODE = 774195, "5983214", 4026533397, 3290756512
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
WORKING = "01e8621f16eb088a178d4e62c09259f8c470625d6fd35b6f34e22f0d894192bb"
DEADLINE = "2026-11-14T06:38:00+00:00"
HOST_PCAP_HEADER = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
MAX_FILES = 250  # the most files that the corpus inventory may hold
POST_SOURCES = 34  # the files in the post-epoch source snapshot
MAX_CORPUS_BYTES = 80 * 1024 * 1024  # the largest accepted corpus
MAX_BRACKET_SECONDS = 3  # the longest accepted host bracket of a clock reading
ORIGINAL_USERS = 2  # the accounts that exist before the later epoch
FIRST_CASES = 9  # the cases of the first epoch that the first witness reports
FIRST_CONNECTIONS = 13  # the control connections of the first epoch
LOCK_FD = 3  # the descriptor on which the managed capture lock was held
CONTROL_PORT = 15800  # the control port inside the namespace
GUEST_PORT = 5500  # the control port on the guest
GUEST_SYNS = 17  # the guest SYNs of the first and later epochs together
NAMESPACE_SYNS = 4  # the namespace SYNs of the later epoch
LATER_CONNECTIONS = 4  # the control connections of the later epoch
POST_EVENTS = 14  # the events of the post-probe case
GUARD_ACTIONS = 12  # the owned guard actions
DELETE_ACTIONS = 18  # the owned delete and readback actions
POSTFLIGHT_ACTIONS = 18  # the control-only postflight actions
DELETE_SENDS = 7  # the send steps of the owned delete plan
OWNED_SIZE = 734  # the byte size of each owned Trash file
HOST_WINDOW_MIN = 1900  # the earliest host elapsed seconds of the post probe
HOST_WINDOW_MAX = 2400  # the latest host elapsed seconds of the post probe
POST_ACK_SECONDS = 0.015954  # the measured ACK bracket of the post ban request
ACK_TOLERANCE = 0.000001  # the tolerance on the measured ACK bracket
