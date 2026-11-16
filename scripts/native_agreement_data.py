"""Hold the agreement phases and the agreement files that the controls share.

The agreement planner in ``native_agreement_cases`` re-exports these names, so
its consumers keep importing them from that module.
"""

PHASES = [
    "original",
    "absent",
    "empty",
    "directory",
    "text",
    "binary",
    "text-limit",
    "text-over-limit",
    "binary-over-limit",
    "binary-field-over-limit",
    "nontext",
    "nontext-over-limit",
    "nontext-field-over-limit",
    "restored",
]
TEXT = b"Agreement\r\nsecond\nline\r\nbyte:\x80\x00end"
# The longest text that the content field accepts, then the lengths just over
# the limit: the text limit, the TLV field limit and the large content limit.
LIMIT_LENGTH = 65535
OVER_LIMIT_LENGTH = 65536
LARGE_OVER_LIMIT_LENGTH = 262141
FILES = {
    "empty": (b"m-agree-empty", b"TEXT", b""),
    "text": (b"m-agree-text", b"TEXT", TEXT),
    "binary": (b"m-agree-binary", b"BINA", TEXT),
    "text-limit": (b"m-agree-t-limit", b"TEXT", b"T" * LIMIT_LENGTH),
    "text-over-limit": (b"m-agree-t-over", b"TEXT", b"T" * OVER_LIMIT_LENGTH),
    "binary-over-limit": (
        b"m-agree-b-over",
        b"BINA",
        b"B" * LARGE_OVER_LIMIT_LENGTH,
    ),
    "binary-field-over-limit": (
        b"m-agree-b-field",
        b"BINA",
        b"B" * OVER_LIMIT_LENGTH,
    ),
}
NON_TEXT_FILES = {
    # One GUI setup retyped BINA Agreement.txt as TEXT. Verify the installed type;
    # recognized BMP supplies a separate non-TEXT control with raw content.
    "nontext": (b"m-agree-nontext", b"BMP ", TEXT),
    "nontext-over-limit": (
        b"m-agree-n-over",
        b"BMP ",
        b"B" * LARGE_OVER_LIMIT_LENGTH,
    ),
    "nontext-field-over-limit": (
        b"m-agree-n-field",
        b"BMP ",
        b"B" * OVER_LIMIT_LENGTH,
    ),
}
ORIGINAL_AGREEMENT_SHA256 = (
    "52f3930366ef00471568a7de275c4b7d7e826274604c058e2fdf0bc6976cc91a"
)
