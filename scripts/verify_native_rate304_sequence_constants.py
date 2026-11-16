"""Name the fixed values that the rate304 sequence verifier checks the corpus against.

Each value is the one the retained corpus was verified with. A comparison that
used a bare literal in the original verifier now names the value here, and the
name carries no meaning beyond the check it serves.
"""

SCHEMA = "native-rate304-sequence-01"
PID, START, NS, INODE = 3125063, "8100939", 4026533665, 1687370702
DEADLINE = "2026-11-14T11:50:21.652926+00:00"
PLAN = "6c0089f101ab4b99c41a6a548866d14e1460d6beaadb5f4c95ea91a5098c0d49"
CASES = "1c95329cfb361ae5322738e6644aa933d95ea6d01feed012dd629f6dca52a2c1"
RUNNER = "9c25e60bdd382c2768954547220fc1a7d5c78b118fc7d006e42bc6a5a41618f6"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EXE = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
}
PORTS = {
    "readiness": 36960,
    "observer": 59848,
    "paced": 34152,
    "burst": 38334,
    "probe": 38344,
}
TEMP_ERROR = b"You are temporarily banned on this server."
MISSING_CLIENT = b"Cannot get info for the specified client because it does not exist."

# The approved source closure lists this many modules.
CLOSURE_SIZE = 35
# The approved helper pins list this many helper modules.
HELPER_PIN_COUNT = 3
# The prewritten script set lists this many scripts.
SCRIPT_PIN_COUNT = 8
# The emulator's listening port, as the source plan and the namespace capture show.
SERVER_PORT = 15880
# The guest-side server port of the guest capture.
GUEST_PORT = 5500

# A pin line holds a digest and a name.
PIN_FIELDS = 2

# The number of raw events, actions and frames in the failed case.
EVENT_COUNT = 210
ACTION_COUNT = 133
FRAME_COUNT = 195
# The number of observed idle control requests in the as-run schedule.
IDLE_CONTROL_COUNT = 14

# The user identifiers that the dynamic roster assigns to the two subjects.
PACED_UID = 3
BURST_UID = 4
# The base request identifier of the numbered acknowledgements of each subject.
PACED_BARS = 2000
BURST_BARS = 4000
# The field whose value the update-301 replies are checked against.
UPDATE_STATUS_FIELD = 112
# The request identifier that opens the host quiet bracket.
QUIET_MARK_ID = 2025
# The request identifier of the burst terminal barrier.
BURST_BARRIER_ID = 4026
# The longest permitted host trial, in nanoseconds.
HOST_TRIAL_BOUND_NS = 20_000_000_000
# The shortest and the longest permitted host quiet bracket, in nanoseconds.
QUIET_MIN_NS = 70_000_000_000
QUIET_MAX_NS = 80_000_000_000
# The observer's final request has this type, is this long and carries no field.
FINAL_REQUEST_TYPE = 303
FINAL_REQUEST_SIZE = 22

# The packet counts of the namespace and guest captures.
NAMESPACE_PACKET_COUNT = 206
GUEST_PACKET_COUNT = 227
# The number of TCP lifetimes, one for each flow of the sequence.
FLOW_COUNT = 5
# The size of a pcap file that holds its global header and no packet.
PCAP_HEADER_SIZE = 24

# The line count of the stopped HFS image and its number of active user folders.
HFS_LINE_COUNT = 5504
ACTIVE_USER_COUNT = 2
# The number of units that the stopped unit listing reports as inactive.
INACTIVE_UNIT_COUNT = 7
# The number of drop-counter lines that the capture journal must contain.
CAPTURE_DROP_LINES = 2
