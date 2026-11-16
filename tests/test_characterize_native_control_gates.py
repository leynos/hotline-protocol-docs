"""Characterize the reply gates of ``native_control_readiness`` before a refactor.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. No socket is
opened and no capture is run.
"""

import copy
import hashlib
import typing as typ

import native_control_readiness as gates
import pytest
from native_control_support import (
    captured,
    field_of,
    flip,
    home,
    reply_frame,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    from native_control_support import Report

BASELINE_DIGESTS = {
    1: "4d3a600990071d9e91b56417c1552aaac0160adf2df3f409d6eeef67e9aec898",
    109: "a500d61db6e19baaf6e165ea9c6512fa3f56262533293f0b44372df434edde59",
    348: "9728c65a33486783ab96fdc6278aa9174b88354fce04073d3981d74086fd9ebe",
    200: "e53bd64a7ea62de8f2b351e7866044dc721d4f983e217368725d638663da9936",
    206: "6dd083b4bbace332c4b475dde19338d3e5fce3527f18a66c8d93fd2bf91e2a9a",
    303: "95edd6e7ab1ef42ef9042f5a78fb96d1f88c7e965ce017cd86c709676f8b978e",
}
SAMPLE_FRAME = {"fields": [{"id": 102, "hex": "41"}, {"id": 110, "hex": "0001"}]}
SAMPLE_DIGEST = hashlib.sha256(b'[[102,"41"],[110,"0001"]]').hexdigest()


class FieldDigestTests:
    """The digest that names a frame's fields."""

    def test_the_digest_is_over_the_compact_json_of_the_pairs(self) -> None:
        """Ids and values, in order, with no spaces."""
        assert gates.field_digest(SAMPLE_FRAME) == SAMPLE_DIGEST, "expected digest"

    def test_the_baselines_are_the_recorded_digests(self) -> None:
        """The six baselines that other scripts import."""
        assert gates.BASELINE_FIELDS == BASELINE_DIGESTS, "expected the baselines"

    def test_the_retained_frames_have_the_baseline_digests(self) -> None:
        """The readiness replies of the retained corpus carry them."""
        report = captured("readiness")
        assert gates.field_digest(report["frames"][0]) == BASELINE_DIGESTS[1], "ack"
        digest = gates.field_digest(reply_frame(report, 10))
        assert digest == BASELINE_DIGESTS[348], "accounts"


def fewer(report: Report) -> None:
    """Drop the agreement frame."""
    del report["frames"][2]
    del report["frames"][2:]


def bad_ack(report: Report) -> None:
    """Give the ack an error."""
    report["frames"][0]["error"] = 1


def ack_fields(report: Report) -> None:
    """Change a field of the ack."""
    flip(report["frames"][0]["fields"][0])


def privileges(report: Report) -> None:
    """Change the bitmap."""
    flip(field_of(report["frames"][1], 110))


def agreement(report: Report) -> None:
    """Change the agreement text."""
    flip(report["frames"][2]["fields"][0])


LOGIN_FAULTS = [
    ("two-frames", fewer, "Login sequence incomplete"),
    ("ack-error", bad_ack, "Fixture admin login differs"),
    ("ack-field", ack_fields, "Fixture admin login differs"),
    ("privileges", privileges, "Fixture admin privilege bitmap differs"),
    ("agreement", agreement, "Fixture agreement bytes differ"),
]


class LoginGateTests:
    """The three login frames of the admin."""

    def test_the_retained_login_is_accepted(self) -> None:
        """No change, no refusal."""
        gates.login_gate(captured("readiness")["frames"])

    @pytest.mark.parametrize(
        ("label", "change", "message"), LOGIN_FAULTS, ids=lambda v: str(v)[:20]
    )
    def test_each_change_is_refused_with_its_message(
        self,
        label: str,
        change: cabc.Callable[[Report], None],
        message: str,
    ) -> None:
        """One change at a time."""
        del label
        report = captured("readiness")
        change(report)
        with pytest.raises(ValueError, match=f"^{message}$"):
            gates.login_gate(report["frames"])


def failed(report: Report) -> None:
    """Make the capture fail, and the login wrong as well."""
    report["status"] = "failed"
    report["frames"][0]["error"] = 1


def short(report: Report) -> None:
    """Complete one action too few."""
    report["completed_actions"] = 17


def reply_error(report: Report) -> None:
    """Make the first control reply an error."""
    reply_frame(report, 10)["error"] = 1


def accounts(report: Report) -> None:
    """Change the account enumeration."""
    flip(reply_frame(report, 10)["fields"][0])


def files(report: Report) -> None:
    """Change the file listing."""
    flip(reply_frame(report, 11)["fields"][0])


def metadata(report: Report) -> None:
    """Change the file information."""
    flip(reply_frame(report, 12)["fields"][0])


def named(report: Report) -> None:
    """Change the user-named reply."""
    flip(reply_frame(report, 14)["fields"][0])


def roster(report: Report) -> None:
    """Rename the one session in the roster, which has no baseline."""
    flip(reply_frame(report, 13)["fields"][0])


def transfer(report: Report) -> None:
    """Send a transfer request in the plan."""
    report["events"].append({"event": "send", "hex": "000000ca" + "00" * 16})


def htxf(report: Report) -> None:
    """Send the transfer magic in the plan."""
    report["events"].append({"event": "send", "hex": "48545846" + "00" * 16})


READINESS_FAULTS = [
    ("failed-before-login", failed, "Short readiness incomplete"),
    ("short", short, "Short readiness incomplete"),
    ("reply-error", reply_error, "Control reply failed"),
    ("accounts", accounts, "348 control baseline differs"),
    ("files", files, "200 control baseline differs"),
    ("metadata", metadata, "206 control baseline differs"),
    ("named", named, "303 control baseline differs"),
    ("roster", roster, "Foreign or absent session"),
    ("transfer", transfer, "Transfer request in control plan"),
    ("htxf", htxf, "Transfer request in control plan"),
]


class ReadinessTests:
    """The short readiness capture."""

    def test_the_retained_capture_is_accepted(self) -> None:
        """No change, no refusal."""
        gates.readiness(captured("readiness"))

    @pytest.mark.parametrize(
        ("label", "change", "message"), READINESS_FAULTS, ids=lambda v: str(v)[:24]
    )
    def test_each_change_is_refused_with_its_message(
        self,
        label: str,
        change: cabc.Callable[[Report], None],
        message: str,
    ) -> None:
        """One change at a time, the status and login first."""
        del label
        report = captured("readiness")
        change(report)
        with pytest.raises(ValueError, match=f"^{message}$"):
            gates.readiness(report)

    def test_a_login_fault_comes_after_the_status_and_before_the_replies(self) -> None:
        """A wrong ack and a wrong reply: the login is named."""
        report = captured("readiness")
        report["frames"][0]["error"] = 1
        flip(reply_frame(report, 10)["fields"][0])
        with pytest.raises(ValueError, match=r"^Fixture admin login differs$"):
            gates.readiness(report)

    def test_a_count_that_the_digest_would_hide_is_still_checked(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The account and file counts follow the baselines of their replies."""
        module = home(gates.readiness)
        monkeypatch.setattr(module, "enumeration", lambda _frame: [1])
        with pytest.raises(ValueError, match=r"^Original account count differs$"):
            gates.readiness(captured("readiness"))
        monkeypatch.undo()
        monkeypatch.setattr(module, "listing", lambda _frame: [1])
        with pytest.raises(ValueError, match=r"^Original Files count differs$"):
            gates.readiness(captured("readiness"))

    def test_the_user_barrier_is_the_last_reply_check(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A changed field 102 of the 303 reply, with its baseline held."""
        module = home(gates.readiness)
        report = captured("readiness")
        barrier = reply_frame(report, 14)
        real = module.fields
        monkeypatch.setattr(
            module,
            "fields",
            lambda frame: {102: b"other"} if frame is barrier else real(frame),
        )
        with pytest.raises(ValueError, match=r"^Idle admin UID barrier differs$"):
            gates.readiness(report)


class GuardedAccountTests:
    """The account guard and its seed."""

    def test_the_retained_guard_and_seed_are_accepted(self) -> None:
        """No change, no refusal."""
        gates.guarded_account(captured("guard"), absent=True)
        gates.guarded_account(captured("seed"), absent=False)

    def test_an_unfinished_capture_is_refused_before_the_login(self) -> None:
        """The status comes first."""
        report = captured("guard")
        report["status"] = "failed"
        report["frames"][0]["error"] = 1
        with pytest.raises(ValueError, match=r"^Account guard or seed incomplete$"):
            gates.guarded_account(report, absent=True)

    def test_an_account_that_exists_is_refused_by_the_guard(self) -> None:
        """A guard reply that is a success."""
        report = captured("guard")
        reply_frame(report, 30)["error"] = 0
        with pytest.raises(ValueError, match=r"^Owned key already exists$"):
            gates.guarded_account(report, absent=True)

    def test_a_changed_error_text_is_refused_by_the_guard(self) -> None:
        """The text names the key."""
        report = captured("guard")
        flip(reply_frame(report, 30)["fields"][0])
        with pytest.raises(ValueError, match=r"^Owned key already exists$"):
            gates.guarded_account(report, absent=True)

    def test_a_failed_creation_is_refused_before_the_readback(self) -> None:
        """The creation reply is checked first."""
        report = captured("seed")
        reply_frame(report, 31)["error"] = 1
        flip(reply_frame(report, 32)["fields"][0])
        with pytest.raises(ValueError, match=r"^Owned account creation failed$"):
            gates.guarded_account(report, absent=False)

    def test_a_readback_that_is_not_zero_privilege_is_refused(self) -> None:
        """The stored access bitmap."""
        report = captured("seed")
        flip(field_of(reply_frame(report, 32), 110))
        message = r"^Stored owned target is not zero privilege$"
        with pytest.raises(ValueError, match=message):
            gates.guarded_account(report, absent=False)


class TargetGateTests:
    """The admin and target sessions before the ban request."""

    def frames(self) -> list[Report]:
        """Take the frames of the ban capture.

        Returns
        -------
        list[dict[str, typing.Any]]
            The frames, in order.
        """
        return captured("ban")["frames"]

    def test_the_retained_sessions_give_the_target_uid(self) -> None:
        """Two bytes, positive."""
        uid = gates.target_gate(self.frames())
        assert len(uid) == 2, "expected a two-byte UID"
        assert int.from_bytes(uid, "big") > 0, "expected a positive UID"

    def test_a_short_target_login_is_refused_after_the_admin_login(self) -> None:
        """Two target frames."""
        frames = [f for f in self.frames() if f["connection"] != "target"]
        with pytest.raises(ValueError, match=r"^Owned target login failed$"):
            gates.target_gate(frames)

    def test_a_failed_target_login_is_refused(self) -> None:
        """The target's first frame is an error."""
        frames = self.frames()
        reply_frame({"frames": frames}, 1, "target")["error"] = 1
        with pytest.raises(ValueError, match=r"^Owned target login failed$"):
            gates.target_gate(frames)

    def test_a_target_with_access_is_refused(self) -> None:
        """The effective access is not zero."""
        frames = self.frames()
        target = [f for f in frames if f["connection"] == "target"]
        flip(target[1]["fields"][0])
        message = r"^Target effective access is not zero$"
        with pytest.raises(ValueError, match=message):
            gates.target_gate(frames)

    def test_a_missing_agreement_is_refused(self) -> None:
        """The target's third frame is not the agreement."""
        frames = self.frames()
        target = [f for f in frames if f["connection"] == "target"]
        target[2]["type"] = 0
        with pytest.raises(ValueError, match=r"^Target agreement missing$"):
            gates.target_gate(frames)

    def test_a_missing_announcement_is_refused(self) -> None:
        """No 301 on the admin's connection."""
        frames = [f for f in self.frames() if f["type"] != 301]
        with pytest.raises(ValueError, match=r"^Target announcement missing"):
            gates.target_gate(frames)

    def test_two_announcements_are_refused_as_ambiguous(self) -> None:
        """A second 301."""
        frames = self.frames()
        join = next(f for f in frames if f["type"] == 301)
        frames.append(copy.deepcopy(join))
        with pytest.raises(ValueError, match=r"^Target announcement missing or amb"):
            gates.target_gate(frames)

    def test_a_missing_roster_reply_is_refused(self) -> None:
        """No reply 32 on the admin's connection."""
        frames = [f for f in self.frames() if not (f["is_reply"] and f["id"] == 32)]
        with pytest.raises(ValueError, match=r"^Current roster reply missing"):
            gates.target_gate(frames)

    def test_a_roster_without_the_target_is_refused(self) -> None:
        """The target's row is renamed."""
        frames = self.frames()
        rows = [
            item
            for item in reply_frame({"frames": frames}, 32)["fields"]
            if item["id"] == 300
        ]
        flip(rows[1])
        with pytest.raises(ValueError, match=r"^Current roster target mismatch$"):
            gates.target_gate(frames)
