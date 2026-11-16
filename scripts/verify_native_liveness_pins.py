"""Pinned identities, digests and ports of the retained native liveness corpus.

Every value here is recorded by the as-run evidence. The verifier modules
compare the corpus against these values and never derive them from it.
"""

SCHEMA = "native-liveness-01"
PID, START, NS, INODE = 1221811, "6825819", "net:[4026533605]", 71221932
DEADLINE = "2026-11-14T08:17:11.974963+00:00"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
A7 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
CASES = "6c475a226bb0a294727fe2d3c3ed01c09e364ac5801ba71913940203cb240633"
RUNNER = "ad939bae0f3355c1e680fb3cc4d25d25f8fb730eb4deb8facff899db01408269"
PLAN = "b196ed191fdc61cea65d4c600e97fb332f74e23f7a8e2029bcb0d49a51270ca5"
FLOWS = ("o", "a", "b", "f", "s35", "s75", "s120")
PORTS = (
    ("readiness", "main", 58728),
    ("coordinator", "o", 50122),
    ("coordinator", "a", 50132),
    ("coordinator", "b", 50144),
    ("coordinator", "f", 50148),
    ("coordinator", "s35", 36346),
    ("coordinator", "s75", 39636),
    ("coordinator", "s120", 45508),
    ("postflight", "main", 49674),
)
EXPECTED_302 = ("0005", "0006", "0003", "0007", "0004", "0008")
