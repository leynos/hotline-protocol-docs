"""Name the values that the native child append boundary verifier compares with."""

# Article identifiers of the boundary corpus.
PARENT_ID = 1  # the parent article, posted first
FIRST_CHILD_ID = 2  # the first child; it has no previous sibling
PRE_BYPASS_ID = 101  # the child before the article that the list omits
BYPASSED_ID = 102  # omitted from the sibling list, but its identifier still reads
REPLACEMENT_ID = 103  # the last article posted; the next sibling of PRE_BYPASS_ID
ARTICLE_COUNT = 103  # every article posted: the parent and 102 children
REACHABLE_CHILD_COUNT = 102  # the children that a sibling list reaches

# Layout of the retained native cache file.
DATA_START = 512  # byte offset of the first block
BLOCK_BYTES = 256  # size of each block
WORD_BYTES = 4  # size of each big-endian word
HEADER_WORD_32 = 256  # the value that header word 32 holds in the retained cache
INDEX_MASK = 31  # an identifier's index bucket is its value masked to five bits
BUCKET_LIMIT = 4  # the most entries that one index bucket may hold
SLOT_BYTES = 8  # each index bucket and each index entry is two words
LINK_OFFSETS = (40, 44, 48, 52)  # where a stored article keeps its four links

# Article fields of a direct body reply.
LIST_FIELD = 321  # the article list that replies carry
REFERENCE_FIELD = 107  # the field of reply 80 that the later request repeats
TITLE_FIELD = 328
POSTER_FIELD = 329
FLAVOUR_FIELD = 327
DATE_FIELD = 330
BODY_FIELD = 333
NAVIGATION_FIELDS = (331, 332, 335, 336)  # the four links, in navigation's order

# Counts and identities recorded for the retained corpus.
RUNTIME_PID = 1259319  # the emulator process of the recorded run
HOST_PACKET_COUNT = 927
REPORT_COUNT = 20
CONNECTION_COUNT = 22
BASELINE_ENTRY_COUNT = 41  # the Files listing before the cases start
INITIAL_PROBE_COUNT = 6  # the records the initial cleanup probe returns
PUBLISHED_RECORD_COUNT = 10  # the records of the published catalogue
PUBLISHER_CATALOG_ID = 11634  # the catalogue ID of the separate publisher
ORACLE_QUERY_COUNT = 10
CATEGORY_AUX_COUNT = 103  # the count that the category reports, orphan included
