"""Characterize ``native_filp`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The module has
two public functions, ``decode`` for a flattened file and ``metadata`` for its
INFO fork. Synthetic inputs break one rule at a time and pairs of faults pin
which error is raised first. Both raise ``ValueError``.
"""

import typing as typ

import native_filp
import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CHARACTERIZES = "native_filp.py"
HEADER = b"FILP\0\1" + bytes(16) + b"\0\3"
TAGS = [b"INFO", b"DATA", b"MACR"]
NAME = b"file"
COMMENT = b"note"


def fork(tag: bytes, value: bytes) -> bytes:
    """Build one fork: tag, eight zero bytes, a four-byte size and the value.

    Returns
    -------
    bytes
        The fork's bytes.
    """
    return tag + bytes(8) + len(value).to_bytes(4, "big") + value


def flattened(values: dict[bytes, bytes] | None = None) -> bytes:
    """Build a flattened file with the three forks in order.

    Returns
    -------
    bytes
        The file.
    """
    values = values or {b"INFO": b"i", b"DATA": b"data", b"MACR": b""}
    return HEADER + b"".join(fork(tag, values[tag]) for tag in TAGS)


def info(name: bytes = NAME, comment: bytes = COMMENT) -> bytes:
    """Build an INFO fork with marked fields at their offsets.

    Returns
    -------
    bytes
        The fork's bytes.
    """
    head = bytearray(72)
    head[:4] = b"AMAC"
    head[4:8] = b"TEXT"
    head[8:12] = b"ttxt"
    head[16:20] = b"\x00\x01\x02\x03"
    head[52:60] = b"CCCCCCCC"
    head[60:68] = b"MMMMMMMM"
    head[70:72] = len(name).to_bytes(2, "big")
    return bytes(head) + name + len(comment).to_bytes(2, "big") + comment


def refused(
    call: cabc.Callable[[bytes], object], argument: bytes, message: str
) -> None:
    """Require that ``call(argument)`` raises a ``ValueError`` with this message."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        call(argument)


class DecodeTests:
    """The flattened-file grammar."""

    def test_three_forks_are_returned_by_tag_name(self) -> None:
        """Keys are the tags as text, in order; values are the fork bytes."""
        forks = native_filp.decode(flattened())
        assert list(forks) == ["INFO", "DATA", "MACR"], "expected the tags in order"
        assert forks == {"INFO": b"i", "DATA": b"data", "MACR": b""}, "values"

    def test_a_fork_value_may_be_empty_or_large(self) -> None:
        """Sizes of zero and of several kilobytes both read."""
        values = {b"INFO": b"", b"DATA": b"x" * 5000, b"MACR": b"m"}
        assert native_filp.decode(flattened(values))["DATA"] == b"x" * 5000, (
            "expected: sizes of zero and of several kilobytes both read"
        )

    @pytest.mark.parametrize(
        "data",
        [
            b"",
            HEADER[:23],
            b"FILP\0\2" + HEADER[6:] + flattened()[24:],
            HEADER[:-1] + b"\x04" + flattened()[24:],
            b"X" + HEADER[1:] + flattened()[24:],
        ],
    )
    def test_a_wrong_header_is_refused(self, data: bytes) -> None:
        """The 24-byte header must be exact."""
        refused(native_filp.decode, data, "Unexpected fresh FILP header")

    def test_a_missing_fork_header_is_refused(self) -> None:
        """Stopping after the header leaves no INFO header."""
        refused(native_filp.decode, HEADER, "Missing or unexpected fork header")

    def test_a_short_fork_header_is_refused(self) -> None:
        """A header cut short is not a header."""
        refused(
            native_filp.decode,
            HEADER + b"INFO" + bytes(8),
            "Missing or unexpected fork header",
        )

    def test_forks_in_another_order_are_refused(self) -> None:
        """INFO, DATA, MACR only."""
        data = HEADER + fork(b"DATA", b"") + fork(b"INFO", b"") + fork(b"MACR", b"")
        refused(native_filp.decode, data, "Missing or unexpected fork header")

    def test_a_missing_last_fork_is_refused(self) -> None:
        """MACR is required."""
        data = HEADER + fork(b"INFO", b"") + fork(b"DATA", b"")
        refused(native_filp.decode, data, "Missing or unexpected fork header")

    def test_nonzero_reserved_bytes_in_a_fork_header_are_refused(self) -> None:
        """Bytes four to twelve of a fork header must be zero."""
        broken = bytearray(flattened())
        broken[24 + 4] = 1
        refused(native_filp.decode, bytes(broken), "Missing or unexpected fork header")

    def test_a_fork_value_longer_than_the_file_is_truncated(self) -> None:
        """The declared size must fit in the remaining bytes."""
        data = flattened({b"INFO": b"i", b"DATA": b"data", b"MACR": b"m"})
        refused(native_filp.decode, data[:-1], "Truncated fork value")

    def test_a_declared_size_past_the_end_is_truncated(self) -> None:
        """A huge size is a truncation, not a memory error."""
        data = HEADER + b"INFO" + bytes(8) + (2**32 - 1).to_bytes(4, "big")
        refused(native_filp.decode, data, "Truncated fork value")

    def test_bytes_after_the_last_fork_are_refused(self) -> None:
        """Nothing may follow the third fork."""
        refused(
            native_filp.decode, flattened() + b"\x00", "Trailing flattened-file bytes"
        )

    def test_the_header_check_comes_before_the_fork_checks(self) -> None:
        """A bad header with bad forks is a header error."""
        refused(
            native_filp.decode,
            b"bad" + flattened()[3:][:30],
            "Unexpected fresh FILP header",
        )

    def test_a_truncated_value_comes_before_a_later_bad_header(self) -> None:
        """Forks are processed in order, so the first fault decides."""
        data = HEADER + fork(b"INFO", b"abc")[:-1]
        refused(native_filp.decode, data, "Truncated fork value")


class MetadataTests:
    """The INFO fork's layout."""

    def test_every_field_is_taken_from_its_offset(self) -> None:
        """Type, creator, flags, dates, name and comment, raw."""
        expected = {
            "type": b"TEXT",
            "creator": b"ttxt",
            "flags": b"\x00\x01\x02\x03",
            "created": b"CCCCCCCC",
            "modified": b"MMMMMMMM",
            "name": NAME,
            "comment": COMMENT,
        }
        assert native_filp.metadata(info()) == expected, "expected: the raw fields"

    def test_the_keys_come_in_a_fixed_order(self) -> None:
        """The dictionary order is part of the result."""
        keys = list(native_filp.metadata(info()))
        assert keys == [
            "type",
            "creator",
            "flags",
            "created",
            "modified",
            "name",
            "comment",
        ], "expected: the dictionary order is part of the result"

    def test_empty_name_and_comment_are_accepted(self) -> None:
        """Both lengths may be zero; the minimum INFO is 74 bytes."""
        fields = native_filp.metadata(info(b"", b""))
        assert (fields["name"], fields["comment"]) == (b"", b""), (
            "expected: both lengths may be zero; the minimum INFO is 74 bytes"
        )
        assert len(info(b"", b"")) == 74, (
            "expected: both lengths may be zero; the minimum INFO is 74 bytes"
        )

    @pytest.mark.parametrize(
        "data", [b"", b"AMAC" + bytes(69), b"XMAC" + bytes(70), b"amac" + bytes(70)]
    )
    def test_a_short_or_non_amac_info_is_refused(self, data: bytes) -> None:
        """At least 74 bytes, beginning ``AMAC``."""
        refused(native_filp.metadata, data, "Short or non-AMAC INFO")

    def test_a_name_that_runs_past_the_end_is_truncated(self) -> None:
        """The comment length word must fit after the name."""
        data = bytearray(info())
        data[70:72] = (len(data)).to_bytes(2, "big")
        refused(native_filp.metadata, bytes(data), "Truncated INFO name")

    def test_a_comment_length_that_does_not_fill_the_fork_is_refused(self) -> None:
        """The comment must end exactly at the end of the fork."""
        refused(native_filp.metadata, info() + b"x", "INFO comment length differs")
        refused(native_filp.metadata, info()[:-1], "INFO comment length differs")

    def test_the_shortness_check_comes_before_the_name_check(self) -> None:
        """A short non-AMAC fork with a huge name length is a shortness error."""
        data = bytearray(b"XMAC" + bytes(66))
        data[70:72] = b"\xff\xff"
        refused(native_filp.metadata, bytes(data), "Short or non-AMAC INFO")

    def test_the_name_check_comes_before_the_comment_check(self) -> None:
        """A truncated name is reported before the comment is looked at."""
        data = bytearray(info(b"", b""))
        data[70:72] = (500).to_bytes(2, "big")
        refused(native_filp.metadata, bytes(data), "Truncated INFO name")
