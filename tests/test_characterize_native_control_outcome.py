"""Characterize the ban outcome and probe gates of ``native_control_readiness``.

This is the state before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. No socket is
opened and no capture is run.
"""

import native_control_readiness as gates
import pytest
from native_control_support import captured, flip, reply_frame


class OutcomeTests:
    """The ban capture's notice, close and readback."""

    def test_the_retained_capture_is_accepted(self) -> None:
        """No change, no refusal."""
        gates.outcome(captured("ban"))

    def test_an_unfinished_capture_is_refused_first(self) -> None:
        """The status is the first check."""
        report = captured("ban")
        report["status"] = "failed"
        with pytest.raises(ValueError, match=r"^Ban capture incomplete$"):
            gates.outcome(report)

    def test_a_missing_ack_is_refused_after_the_close(self) -> None:
        """The admin's reply 33 is absent."""
        report = captured("ban")
        report["frames"] = [
            f for f in report["frames"] if not (f["is_reply"] and f["id"] == 33)
        ]
        with pytest.raises(ValueError, match=r"^Admin ACK missing$"):
            gates.outcome(report)

    def test_a_missing_departure_is_refused_after_the_ack(self) -> None:
        """No 302 on the admin's connection."""
        report = captured("ban")
        report["frames"] = [f for f in report["frames"] if f["type"] != 302]
        with pytest.raises(ValueError, match=r"^Departure missing$"):
            gates.outcome(report)

    def test_a_readback_fault_is_refused_last(self) -> None:
        """The readback comes after the departure."""
        report = captured("ban")
        reply_frame(report, 42)["fields"][0]["hex"] = "00"
        message = r"^Post-ban fixture metadata changed$"
        with pytest.raises(ValueError, match=message):
            gates.outcome(report)


class AfterTests:
    """The admin's readback after the ban."""

    def test_the_retained_readback_is_accepted(self) -> None:
        """No change, no refusal."""
        gates.after(captured("ban"))

    def test_a_changed_account_list_is_refused(self) -> None:
        """An account's record is changed."""
        report = captured("ban")
        flip(reply_frame(report, 40)["fields"][0])
        message = r"^Original or owned account changed after ban$"
        with pytest.raises(ValueError, match=message):
            gates.after(report)

    def test_a_changed_file_listing_is_refused(self) -> None:
        """One entry is dropped."""
        report = captured("ban")
        del reply_frame(report, 41)["fields"][0]
        with pytest.raises(ValueError, match=r"^Post-ban Files changed$"):
            gates.after(report)

    def test_a_changed_roster_is_refused_last(self) -> None:
        """The only row is dropped."""
        report = captured("ban")
        frame = reply_frame(report, 43)
        del frame["fields"][-1]
        with pytest.raises(ValueError, match=r"^Post-ban roster differs$"):
            gates.after(report)


class ProbeTests:
    """The fresh login after the ban."""

    def test_the_retained_probe_is_accepted(self) -> None:
        """No change, no refusal."""
        gates.probe(captured("probe"))

    def test_an_unfinished_probe_is_refused_first(self) -> None:
        """The status."""
        report = captured("probe")
        report["status"] = "failed"
        with pytest.raises(ValueError, match=r"^107 probe incomplete$"):
            gates.probe(report)

    def test_a_login_that_is_not_refused_is_refused(self) -> None:
        """The reply is a success."""
        report = captured("probe")
        reply_frame(report, 1)["error"] = 0
        message = r"^Permanent login rejection differs$"
        with pytest.raises(ValueError, match=message):
            gates.probe(report)

    def test_a_changed_notice_is_refused(self) -> None:
        """The text."""
        report = captured("probe")
        flip(reply_frame(report, 1)["fields"][0])
        message = r"^Permanent login rejection differs$"
        with pytest.raises(ValueError, match=message):
            gates.probe(report)

    def test_a_third_send_is_refused_as_not_a_fresh_login(self) -> None:
        """Two sends are required."""
        report = captured("probe")
        report["events"].append({"event": "send", "hex": "00"})
        with pytest.raises(ValueError, match=r"^Fresh TRTP plus Login107 absent$"):
            gates.probe(report)

    def test_a_changed_handshake_is_refused(self) -> None:
        """The first send is the handshake."""
        report = captured("probe")
        sends = [e for e in report["events"] if e["event"] == "send"]
        sends[0]["hex"] = "00"
        with pytest.raises(ValueError, match=r"^Fresh TRTP plus Login107 absent$"):
            gates.probe(report)
