"""Recorded identities of the retained board corpus: hashes, process and deadline.

Each value is a fact that the corpus or the plan that produced it records. A check
compares a value with a file's digest or with a recorded field, so a value changes
only when the evidence that it records changes.
"""

SCHEMA = "native-board-01"
PID, START, NS, INODE = 1441133, "7213582", "net:[4026532471]", 1678261667
DEADLINE = "2026-11-14T09:22:28.893022+00:00"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
CASES = "19e699317afd769c4a4b483e6094337fe92a5baaed279ae6ab98c18b7b554344"
RUNNER = "da343b8d39f35c18bc267f301fdac316c720c0d5d4334eaec1d389ef381d1f6c"
PLAN = "95270ece3efe4da57cabd07ecf0a99ddb35cc11c3d353b69b7df3ae429b577ed"
BOARD = "a676c6349bb500411c0e0d73f29763a092cc1d9471809636c93433c5b430c4e0"
BOARD_BYTES = 65629  # the length of the stopped MessageBoard.txt data fork
ENDPOINT_PORT = 15860  # the board plan's endpoint, native_board_cases.PORT
PORTS = (
    ("readiness", "main", 44446),
    ("coordinator", "sender", 52838),
    ("coordinator", "eligible", 52852),
    ("coordinator", "denied", 52854),
    ("coordinator", "waiting", 46468),
    ("postflight", "main", 47550),
)
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": RSRC,
}
