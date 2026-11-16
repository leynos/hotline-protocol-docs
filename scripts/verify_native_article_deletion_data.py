"""Name the expected trees, titles, error texts and counts of article deletion.

Each count is the value that the retained corpus must have. The checks in the
sibling ``verify_native_article_deletion_*`` modules compare against these names,
so a changed count is a changed expectation and must be made here, deliberately.
"""

# These expected graphs are independent of the request generator. A zero flag
# promotes the first child and reparents the other children under that child.
TREES = {
    "unchanged": ([1, 2, 3], {2: [4, 5, 6], 4: [7, 8]}),
    "promote-parent": ([1, 4, 3], {4: [7, 8, 5, 6]}),
    "recursive-parent": ([1, 3], {}),
    "leaf": ([1, 2, 3], {2: [4, 5, 6], 4: [8]}),
    "promote-middle": ([1, 2, 3], {2: [7, 5, 6], 7: [8]}),
    "recursive-middle": ([1, 2, 3], {2: [5, 6]}),
    "head": ([2, 3], {2: [4, 5, 6], 4: [7, 8]}),
    "tail": ([1, 2], {2: [4, 5, 6], 4: [7, 8]}),
}
TITLES = {1: b"L", 2: b"A", 3: b"R", 4: b"B", 5: b"C", 6: b"F", 7: b"D", 8: b"E"}
BODY_ERROR = b"Cannot get article data because an invalid category was specified."
ID_ERROR = b"Cannot delete article because an invalid category or item was specified."
CATEGORY_ERROR = (
    b"Cannot delete article because the specified category could not be found."
)
DENIED_ERROR = b"You are not allowed to delete articles."
LOW_READ_ERROR = b"You are not allowed to read articles."

# Counts of the retained corpus.
CASE_COUNT = 25  # the deletion cases, one per owned category
POSITIVE_CATEGORY_COUNT = 25  # the positive categories of the catalogue
CATALOGUE_ROWS = 27  # the records of the final native extraction
PUBLISHED_ROWS = 28  # the records after the separate publisher is added
FILES_BASELINE_ENTRIES = 41  # the root listing before any owned change
ORACLE_QUERY_COUNT = 15  # the oracle queries, one per retained address
REPORT_COUNT = 58  # the captures, initial and recovery
COMPLETED_REPORT_COUNT = 56  # the captures that completed
FAILED_REPORT_COUNT = 2  # the retained failures: the burst and the banned login
PAIRED_CONNECTION_COUNT = 60  # the host and guest connections of all captures
FULL_PREFIX_CASES = 13  # the categories below this index hold all eight articles
FULL_PREFIX_ARTICLES = 8  # the articles of a complete prefix
PARTIAL_PREFIX_INDEX = 13  # the category with a single article in its prefix
PARTIAL_PREFIX_ARTICLES = 1  # the articles of a partial prefix
EXISTING_CATEGORY_CASES = 14  # the categories below this index already exist
CACHE_BLOCK_BYTES = 256  # the block size of the stored cache

# Runtime and application identities of the recovery corpus.
INITIAL_EMULATOR_PID = 881007
RECOVERY_EMULATOR_PID = 1259319
NATIVE_EXECUTABLE_SHA256 = (
    "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
)
NATIVE_CATALOG_ID = 11183
NATIVE_RESOURCE_SHA256 = (
    "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
)

# Timing and the retained flood burst.
BOUNDED_WAIT_NS = 3_000_000_000  # the three-second pacing or quiet window
BURST_ACTIONS = 248  # the requests that the retained failed burst completed
BURST_REPLIES = 121  # the replies that the retained failed burst received
BURST_MAX_ELAPSED_NS = 60_000_000_000  # the burst must end within one minute
