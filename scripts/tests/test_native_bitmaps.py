"""Check bounded, owned 64-bit native account bitmap plans."""

import copy
import json
import typing as typ
from pathlib import Path

import native_bitmap_cases as cases
import pytest
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_LOGIN,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_bitmaps import semantic, verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-bitmaps-01"
)
WALKING_BITS = 64  # one single-bit plan for each bit of the field-110 registry
SUITE_COUNT = 13  # the suites of the bitmap plan inventory
WALK_SUITE_COUNT = 8  # the eight walks, one per byte of the bitmap
KEY_MAX_BYTES = 31  # the longest account login the plan may use
WIDTH_LENGTHS = [None, 0, 1, 7, 8, 9]  # the widths of the width controls
FIRST_READBACK_ID = 21  # the readback of the first bit of each walk step
SECOND_READBACK_ID = 23  # the readback of the second bit of a walk


class BitmapPlanTests:
    """Check bounded, owned 64-bit native account bitmap plans."""

    def test_all_64_msb_first_single_bits(self) -> None:
        """Each of the 64 walking bits is distinct and most significant first."""
        values = [cases.walking_bit(bit) for bit in range(WALKING_BITS)]
        assert len(set(values)) == WALKING_BITS, "the walking bits are not distinct"
        assert all(len(value) == ACCESS_BITMAP_BYTES for value in values), (
            "a walking bit is not a full bitmap"
        )
        assert values[0] == bytes.fromhex("8000000000000000"), "bit 0 is not MSB"
        assert values[7] == bytes.fromhex("0100000000000000"), "bit 7 is misplaced"
        assert values[8] == bytes.fromhex("0080000000000000"), "bit 8 is misplaced"
        assert values[63] == bytes.fromhex("0000000000000001"), "bit 63 is misplaced"

    def test_width_controls_are_distinguishable(self) -> None:
        """The width controls differ in length and in their first eight bytes."""
        values = cases.WIDTHS
        assert [
            len(value) if value is not None else None for value in values.values()
        ] == WIDTH_LENGTHS, "the width controls differ in length"
        assert values["short-one"] != values["short-seven"], (
            "the short width controls are not distinguishable"
        )
        over, exact = values["over-nine"], values["exact-eight"]
        assert over is not None, "the over-nine width control is absent"
        assert exact is not None, "the exact-eight width control is absent"
        assert over[:ACCESS_BITMAP_BYTES] == exact, "the over-nine prefix differs"

    def test_one_owned_account_and_bounded_suite_inventory(self) -> None:
        """The plans use one owned account and the bounded suite inventory."""
        plans = cases.suites()
        assert len(plans) == SUITE_COUNT, "the suite inventory differs"
        assert sum(label.startswith("walk-") for label in plans) == WALK_SUITE_COUNT, (
            "the walk count differs"
        )
        assert cases.KEY.startswith(b"m-bit32-"), "the account is not the owned one"
        assert len(cases.KEY) <= KEY_MAX_BYTES, "the owned login is too long"


class BitmapEvidenceTests:
    """Reject bitmap readback, sent-bit, identity and ordering overclaims."""

    def reports(self) -> dict[str, typ.Any]:
        """Load the report of every suite in the retained corpus.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of each suite, by suite name.
        """
        return {
            name: json.loads((CORPUS / name / "report.json").read_text())
            for name in cases.suites()
        }

    def test_complete_corpus(self) -> None:
        """The retained corpus verifies all of its walking bits."""
        assert verify(CORPUS)["walking_bits_verified"] == WALKING_BITS, (
            "the verified walking-bit count differs"
        )

    def test_wrong_readback_bit_is_rejected(self) -> None:
        """A readback that shows the wrong bit is refused."""
        reports = self.reports()
        reply = next(
            f
            for f in reports["walk-04"]["frames"]
            if f["is_reply"] and f["id"] == FIRST_READBACK_ID
        )
        next(field for field in reply["fields"] if field["id"] == FIELD_ACCESS_BITMAP)[
            "hex"
        ] = "8000000000000000"
        with pytest.raises(ValueError, match="readback"):
            semantic(reports)

    def test_wrong_sent_bit_is_rejected(self) -> None:
        """A request that sends the wrong bit is refused."""
        reports = self.reports()
        event = next(
            e
            for e in reports["walk-07"]["events"]
            if e["event"] == "send" and e["hex"].startswith("00000161")
        )
        before = event["hex"]
        event["hex"] = before.replace("0000000000000080", "8000000000000000")
        assert event["hex"] != before, "the sent bit was not changed"
        with pytest.raises(ValueError, match="submitted"):
            semantic(reports)

    def test_wrong_owned_identity_is_rejected(self) -> None:
        """A readback of another account identity is refused."""
        reports = self.reports()
        reply = next(
            f
            for f in reports["walk-02"]["frames"]
            if f["is_reply"] and f["id"] == FIRST_READBACK_ID
        )
        next(field for field in reply["fields"] if field["id"] == FIELD_LOGIN)[
            "hex"
        ] = "00"
        with pytest.raises(ValueError, match="identity"):
            semantic(reports)

    def test_reordered_readbacks_are_rejected(self) -> None:
        """Readbacks that arrive out of order are refused."""
        reports = self.reports()
        frames = reports["walk-00"]["frames"]
        a = next(
            i
            for i, f in enumerate(frames)
            if f["is_reply"] and f["id"] == FIRST_READBACK_ID
        )
        b = next(
            i
            for i, f in enumerate(frames)
            if f["is_reply"] and f["id"] == SECOND_READBACK_ID
        )
        frames[a], frames[b] = frames[b], frames[a]
        with pytest.raises(ValueError, match="order"):
            semantic(reports)

    def test_ambiguous_all_ones_privilege_push_is_rejected(self) -> None:
        """A duplicated privilege push in the all-ones login is refused."""
        reports = self.reports()
        push = next(
            f
            for f in reports["all-ones"]["frames"]
            if f["connection"] == "owned" and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
        )
        reports["all-ones"]["frames"].append(copy.deepcopy(push))
        with pytest.raises(ValueError, match="effective session"):
            semantic(reports)
