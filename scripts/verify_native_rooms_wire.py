"""Name the room numbers and limits that the room verifier compares against.

Wire numbers that native_wire_names already names are imported from there;
the rest keep a local name that says what the verifier means by them.
"""

ROOM_ID_BYTES = 4  # the width of the room identifier
OWNER_ID_BYTES = 2  # the width of a user identifier
PARTICIPANTS = 4  # the owner and the three owned roles
PAIR = 2  # the two members of a concurrent join or leave
TOPIC_LIMIT = 255  # the longest topic that the server keeps
HOST_PACKETS = 2095  # the packets of the retained host recording
ORIGINAL_ACCOUNTS = 2  # the accounts that exist before the scenarios
ORIGINAL_FILES = 41  # the entries of the original file listing
ORACLE_QUERIES = 16  # the oracle queries retained with the corpus
EMULATOR_PID = 1259319  # the emulator process of the recorded running epoch

ROOM_JOIN_NOTICE = 117  # a notification that a member joined the room
ROOM_LEAVE_NOTICE = 118  # a notification that a member left the room
ROOM_TOPIC_NOTICE = 119  # a notification that the topic of the room changed
INVITE = 113  # an invitation request, and the notification it sends
FIELD_ROOM = 114  # the room identifier
FIELD_STATUS = 112  # the status of a member in a join notification
FIELD_CHAT_OPTION = 109  # the option of a chat request
ACKLESS_REQUESTS = frozenset({105, 113, 114, 116, 120, 304})  # no success reply
