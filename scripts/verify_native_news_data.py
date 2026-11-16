"""Fixture tables, field numbers, request identifiers and counts for news checks.

The records and graph describe the threaded articles that the planners in
``native_news_cases`` post. The request identifiers are named for the role each
number plays in the check that reads it, because the planners number their
exchanges independently in every case.
"""

RECORDS: dict[int, tuple[bytes, int, int, bytes | None]] = {
    1: (b"First root", 0, 0, b"first-body\r\n\0\xff"),
    2: (b"Second root", 0, 0x11223344, b"second-body"),
    3: (b"Missing body", 0, 0, None),
    4: (b"long-" + b"x" * 26, 1, 0, b"B" * 65535),
    5: (b"Second child", 1, 0, b"child-two"),
    6: (b"Grandchild", 4, 0, b"grandchild-body"),
}
GRAPH: dict[int, tuple[int, int, int, int]] = {
    1: (0, 2, 0, 4),
    2: (1, 3, 0, 0),
    4: (0, 5, 1, 6),
    5: (4, 0, 1, 0),
    6: (0, 0, 4, 0),
}
ROOT_ENTRIES: list[tuple[bytes, bool, int]] = [
    (b"bundle", True, 2),
    (b"category", False, 6),
    (b"empty", True, 0),
    (b"hi-\x9a", True, 0),
    (b"zero-articles", False, 0),
]
ORACLE_ADDRESSES = frozenset({
    "10011960",
    "100102c0",
    "10005710",
    "1002cb20",
    "1002ce00",
    "10022830",
    "1006f350",
    "10022670",
    "10010ee0",
    "10011110",
    "10010b70",
    "1002cac0",
    "10008ad0",
    "10011370",
    "100059e0",
    "10010470",
    "100229b0",
    "10022ea0",
    "10023180",
    "10025900",
    "10025a60",
    "10025c60",
    "10025d80",
    "100248a0",
    "1006f2e0",
    "10011580",
    "10005ac0",
    "100233e0",
    "10057de0",
})

EMULATOR_PID = 881007  # the emulator process recorded in runtime-check.json
RUNNING_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
HOST_PACKET_COUNT = 1246
FINAL_RECORD_COUNT = 10  # objects in the positive final catalogue
PUBLISHED_RECORD_COUNT = 11  # objects after the publish cleanup
FILES_BASELINE_COUNT = 41  # entries in Files before the news fixture runs
COMPLETED_REPORT_COUNT = 43
PAIRED_CONNECTION_COUNT = 45
ORACLE_QUERY_COUNT = 29
MODERN_VERSION = 15  # from this category-list version on, the layout is modern
LEGACY_CATEGORY_FIELD = 320
MODERN_CATEGORY_FIELD = 323
LEGACY_FOLDER_KIND = 1
LEGACY_CATEGORY_KIND = 10
FOLDER_KIND = 2
CATEGORY_KIND = 3
BLOCK_SIZE = 256  # the size of each block of a cached HLNZ article list
HLNZ_HEADER_BYTES = 512  # the offset of the first block in an HLNZ object
ARTICLE_LIST_FIELD = 321
EMPTY_ARTICLE_LIST = bytes(10)  # an article list with no articles
FIELD_FLAVOUR = 327
FIELD_TITLE = 328
FIELD_POSTER = 329
FIELD_DATE = 330
FIELD_PREVIOUS = 331
FIELD_FOLLOWING = 332
FIELD_BODY = 333
FIELD_PARENT = 335
FIELD_CHILD = 336

ROOT_LIST_ID = 10  # the root listing of preflight, files, listing and posts
EMPTY_LIST_ID = 11  # an empty category: the empty bundle, or a category before posting
BUNDLE_LIST_ID = 12  # the bundle listing
CHILD_LIST_ID = 13  # the listing of the child bundle inside the bundle
CATEGORY_LIST_ID = 20  # the article list of the category
ZERO_LIST_ID = 21  # the article list of zero-articles
NESTED_LIST_ID = 22  # the article list of bundle/nested
VALID_POST_IDS = (20, 21, 22)  # the three valid posts, each of which must succeed
MISSING_BODY_POST_ID = 23  # the post without a body, which must fail
LIST_AFTER_POST_20 = 40  # the article list read after post 20
LIST_AFTER_POST_21 = 41  # the article list read after post 21
LIST_AFTER_POST_23 = 43  # the article list read after post 23
LIVENESS_ID = 90  # the final request, which shows that control still answers
PUBLISHER_LIST_ID = 91  # the category read after the publisher is removed
