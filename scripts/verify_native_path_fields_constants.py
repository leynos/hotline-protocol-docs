"""Pinned digests, identities and expected counts of the path-fields corpus."""

PREFIX = "evidence/gap-remediation/2026-11-14/native-path-fields-01/"
PLAN = "dac0a99b766855d07005195c279f34396ea6c966308ba0bb7ee00fb725c0f947"
CASES = "eeca1a3b9c150c25de4c6e3e0d1cef9ff2f187c3dc112f6b1d4025bc5ce4f5b3"
CONTROL = "6d7dbe35c919b648b8e0ae6370c3414ab577b949e38a3fd8224e1cb4f60b1371"
SOURCE_APPROVAL = "f59977429992350607fa9ddcc7a56774577030a2f0f706624cdc8350a7e02760"
HELPER_APPROVAL = "65b56c87f306dd31521056eca22085e711071d6698b52fd9bba3d17f3431dd45"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
# The emulator process, its start time, its network namespace and its working image.
PID, START, NS, INODE = 1058709, "8937287", 4026533805, 5999397982
DEADLINE = "2026-11-14T14:09:46.041564+00:00"
# The local ports of the readiness and the case connections.
PORTS = {"readiness": 52304, "case": 39238}
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
}
# The port of the isolated control-only case endpoint.
CASE_PORT = 15900
# A line of a pin file holds a digest and a name.
PIN_FIELDS = 2
# A SHA-256 digest has this many hexadecimal digits.
DIGEST_LENGTH = 64
# A pinned module name has a directory and a file name.
NAME_PARTS = 2
# The approved closure holds this many modules.
APPROVED_MODULES = 37
# The approved helper modules.
HELPER_MODULES = 3
# The prewritten preparation scripts that are pinned.
PREWRITTEN_SCRIPTS = 8
# The readiness actions that complete before the case.
READINESS_ACTIONS = 18
# The requests of the case, including the login.
CASE_REQUESTS = 82
# The requests of the case that change the server.
MUTATION_COUNT = 20
# The frames of the case capture.
CASE_FRAMES = 84
# The views of the case capture.
CASE_VIEWS = 31
# The events of the case report.
CASE_EVENTS = 173
# The results, one per tested value.
CASE_RESULTS = 12
# The progress entries, one per request before the case ends.
PROGRESS_ENTRIES = 81
# The cells that move a file; the later cells are news folders.
FILE_CELLS = 6
# The news field and the kind that name the category folder.
CATEGORY_FIELD = 323
CATEGORY_KIND = 3
# The user identifier that the case runs as.
OWNER_UID = 1000
# The descriptor that the guest capture holds.
GUEST_FD = 16
# The window, in seconds, that the fixed epoch deadline must fall in.
EPOCH_MIN = 719
EPOCH_MAX = 721
# The seconds the case must start before its deadline.
CASE_MARGIN = 390
# The network namespace of the host.
HOST_NS = 4026531840
# The bytes of the file header of a packet capture.
PCAP_HEADER = 24
# The TCP flag bit of a SYN, and of an ACK.
SYN_FLAG = 2
ACK_FLAG = 16
# The TCP flag bits of a FIN and of a RST, which end a connection.
TERMINAL_FLAGS = 5
# The port of the guest's server in the guest view.
GUEST_PORT = 5500
# The TCP connections of each view, and of the derived flows.
CONNECTIONS = 2
# The managed capture recorders of the run.
RECORDERS = 2
# The owned minimum size of the stopped catalogue listing.
MIN_CATALOGUE_LINES = 5000
# The owned entries in the stopped marker catalogue.
MARKER_ENTRIES = 11
# The marker commands that the supplement runs.
SUPPLEMENT_COMMANDS = 12
# The catalogue record that the supplement does not read.
SKIPPED_IDENTIFIER = 11748
# The catalogue record of the category folder.
CATEGORY_IDENTIFIER = 11758
# The empty text, which a corpus field holds when it has no value.
EMPTY_TEXT = ""
# The owned units that stop after the case.
OWNED_UNITS = 5
