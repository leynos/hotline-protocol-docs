"""Name the identities, ports and limits that the first temporary-ban replay checks.

The values are the ones that the first epoch was recorded with. A value that a
check compares against is named here, so that the checks read as statements.
"""

SCHEMA = "native-ban-expiry-first-01"
FIRST = (
    "guard-zero",
    "guard-protected",
    "seed-zero",
    "seed-protected",
    "kick0",
    "kick0-probe",
    "protected",
    "tempban",
    "immediate-probe",
)
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
PID, START, NS, INODE = 774195, "5983214", "net:[4026533397]", 3290756512
DEADLINE = "2026-11-14T05:56:51+00:00"
PROTECTED_UNREAD = bytes.fromhex(
    "0000012e00000004000000000000000800000008000100670002000a"
)
NS_INODE = 4026533397  # the inode of the network namespace named by NS
LOCK_PID = 772927  # the process that held the managed capture lock
LOCK_FD = 3  # the descriptor on which the managed capture lock was held
LOCK_INODE = 3512552451  # the inode of the managed capture lock file
HOST_RECORDER_PID = 773908  # the host recorder of the first epoch
NAMESPACE_RECORDER_PID = 775272  # the namespace recorder of the first epoch
SYN = 2  # the TCP flags of a bare SYN
CONTROL_PORT = 15800  # the control port inside the namespace
GUEST_PORT = 5500  # the control port on the guest
FIRST_CONNECTIONS = 13  # the control connections of the first epoch
SETTLE_SECONDS = 35  # the quiet interval that follows readiness
MAX_ACK_SECONDS = 20  # the longest accepted ban request-to-ACK bracket
MAX_FILES = 250  # the most files that the corpus inventory may hold
MAX_CORPUS_BYTES = 60 * 1024 * 1024  # the largest accepted corpus
MAX_BRACKET_SECONDS = 3  # the longest accepted host bracket of a clock reading
ORIGINAL_USERS = 2  # the accounts that exist before the first epoch
