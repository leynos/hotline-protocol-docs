"""Name the pinned identities and the bounds that the configured-ban check compares.

verify_native_configured_ban re-exports every name below, so that a consumer of the
original module finds the same constants there.
"""

from native_wire_names import (
    TYPE_DOWNLOAD_FILE,
    TYPE_REFERENCE_CLEANUP,
    TYPE_UPLOAD_FILE,
)

# The pinned hashes of the corpus sources, its tools and its retained inputs.
SCHEMA = "native-configured-ban-01"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
CASES = "23fbb968f1d692b8d7cfeb5937d56dc1cb35d75f102efa18fa6f97173b56ccc4"
CONTROLLER = "ee9648248618269aa20572362f54af25b157fed6586265874e1964c1ebd6f13a"
STOPPED = "bd8ddf219f75118eda91cbfd0e2dd5dc133534840bd587a58b483e4e6410f499"
BANNED = "671c8164c116d26cf5bb863ba87b93174f81b1a59abb208491b57f9d41a87aa1"
ADMIN = "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3"
LOW = "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5"
PREFS = "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196"

# The lab emulator, its start time and its network namespace, as the corpus recorded.
PID = 600782
START = "5595993"
NS = "net:[4026533397]"
# The number of actions of each source plan.
PHASES = {"readiness": 18, "guard": 10, "seed": 12, "held-apply": 23}

# The bounds of the corpus inventory: its file count and its byte totals.
MAX_CORPUS_FILES = 160
MAX_SOURCE_BYTES = 24 * 1024 * 1024
MAX_PCAP_BYTES = 2 * 1024 * 1024
# The accounts that the corpus must hold before the held-apply case.
ORIGINAL_USER_COUNT = 2
# The size of a capture that holds only its global header.
EMPTY_PCAP_BYTES = 24

# The processes of the lab and its managed oracle lease, as the corpus recorded.
PRIMARY_PID = 1099659
CLIENT_PID = 1012834
DISTINCT_NAMESPACES = 3
LEASE_MAIN_PID = 599355
LEASE_LOCK_INODE = 3512552451
# The boot window: the capture deadline follows the fixed deadline by this many seconds.
CAPTURE_WINDOW_SECONDS = 5
MIN_REMAINING_SECONDS = 300

# The timing of the reviewed Save, and the recorder's action numbers around it.
MAX_TRIGGER_SECONDS = 120
MAX_SAVE_RETURN_SECONDS = 2
GATE_ACTION = 16  # the last action before the reviewed Save
SAVE_ACTION = 17  # the first action after the reviewed Save
NOTICE_ACTIONS = frozenset({17, 18})  # the actions that may deliver the first notice

# The lifetimes of the five client connections, and the ports that frame them.
SCOPED_CONNECTIONS = 5
CONTROL_PORT = 15770
GUEST_PORT = 5500
# The primary server's ports, which the fixture must not reach.
PRIMARY_PORTS = frozenset({15500, 15501})
# The TCP flag bits of a packet: FIN, SYN and RST.
TCP_FIN = 1
TCP_SYN = 2
TCP_RST = 4

# The stored sizes of the stopped fixture: the ban list, the preferences and the
# owned account's user data.
BANNED_BYTES = 49
PREFS_BYTES = 175
OWNED_USER_DATA_BYTES = 734

# The shortest hex of a sent frame that the request check reads.
MIN_REQUEST_HEX_CHARS = 40
# The request types that the fixture must not send: 110, and the full-file
# operations 202, 203 and 214.
FORBIDDEN_TYPES = frozenset({
    110,
    TYPE_DOWNLOAD_FILE,
    TYPE_UPLOAD_FILE,
    TYPE_REFERENCE_CLEANUP,
})
