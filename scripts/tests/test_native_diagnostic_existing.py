"""Offline bounds for the approved existing-fixture diagnostic load plans."""

import copy
import dataclasses as dc
import functools
import json
from pathlib import Path

import pytest
from native_diagnostic_existing_cases import CASES, NAME, build
from native_plan import packet, payload
from protocol_capture import decode_frame, validate_plan
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_diagnostic,
    check_references,
    section_witness,
)

EVIDENCE = Path(__file__).resolve().parents[2] / "evidence/gap-remediation/2026-11-13"
PREFLIGHT_REPORT = (
    EVIDENCE / "native-diagnostic-existing-preflight-01/capture/report.json"
)
LOADED_REPORT = (
    EVIDENCE / "native-diagnostic-existing-01/one-active-one-queued/report.json"
)


# the limits that the postflight plan restores, in the order of the plan's keys
LIMIT_NAMES = ("global_download_limit", "per_client_download_limit", "per_ip_limit")
RESTORED_LIMITS = (100, 10, 5)


def control_sends(plan: dict) -> list[tuple[int, int, int]]:
    """List the control requests sent on connection ``a`` by a plan.

    Parameters
    ----------
    plan : dict
        A validated plan whose steps are inspected.

    Returns
    -------
    list[tuple[int, int, int]]
        For each control send, its step index, request kind and identifier.
    """
    result = []
    for index, step in enumerate(plan["steps"]):
        if step["op"] != "send" or step["connection"] != "a":
            continue
        raw = bytes.fromhex(step["hex"][:16])
        if len(raw) < 8 or raw.startswith(b"TRTP"):
            continue
        result.append((
            index,
            int.from_bytes(raw[2:4], "big"),
            int.from_bytes(raw[4:8], "big"),
        ))
    return result


@pytest.fixture(name="plans")
def plans_fixture() -> dict[str, dict]:
    """Build every approved existing-fixture plan.

    Returns
    -------
    dict[str, dict]
        The plans keyed by case name.
    """
    return {name: build(name, {"emulator_pid": 1099659}) for name in CASES}


class PlanBoundsTests:
    """Check that the approved existing-fixture plans stay within their bounds."""

    def test_all_plans_validate_and_target_only_existing_file(
        self, plans: dict[str, dict]
    ) -> None:
        """Every plan validates and targets only the existing fixture file."""
        for plan in plans.values():
            validate_plan(plan)
            kinds = {kind for _, kind, _ in control_sends(plan)}
            assert not (kinds & {203, 204, 304, 350, 351, 352}), "forbidden kinds"
            assert not any(s["op"] == "shutdown_write" for s in plan["steps"]), (
                "shutdown write"
            )
            assert plan["expectation"]["fixture_name_hex"] == NAME.hex(), "fixture name"

    def test_two_one_has_two_refs_one_data_socket_and_cleanup(
        self, plans: dict[str, dict]
    ) -> None:
        """The two-one plan has two references, one data socket and cleanup."""
        plan = plans["one-active-one-queued"]
        sends = control_sends(plan)
        assert [ident for _, kind, ident in sends if kind == 202] == [
            11,
            12,
        ], "download references"
        assert [ident for _, kind, ident in sends if kind == 214] == [
            15,
            16,
        ], "cancel references"
        assert [ident for _, kind, ident in sends if kind == 303] == [
            13,
            14,
            17,
        ], "diagnostic references"
        assert [s["connection"] for s in plan["steps"] if s["op"] == "connect"] == [
            "a",
            "active",
        ], "connections"
        assert (
            plan["expectation"]["global_download_limit"],
            plan["expectation"]["per_client_download_limit"],
        ) == (2, 1), "download limits"

    def test_density_has_fixed_points_sixteen_refs_eight_sockets(
        self, plans: dict[str, dict]
    ) -> None:
        """The density plan has fixed points, sixteen references and eight sockets."""
        plan = plans["density"]
        sends = control_sends(plan)
        assert [ident for _, kind, ident in sends if kind == 202] == list(
            range(20, 28)
        ) + list(range(40, 48)), "download references"
        assert [ident for _, kind, ident in sends if kind == 214] == list(
            range(77, 69, -1)
        ) + list(range(87, 79, -1)), "cancel references"
        assert [ident for _, kind, ident in sends if kind == 303] == [35, 60, 61, 90], (
            "diagnostic references"
        )
        assert (
            len([
                s
                for s in plan["steps"]
                if s["op"] == "connect" and s["endpoint"] == "data"
            ])
            == 8
        ), "data sockets"
        assert not any(s["op"] == "read_eof" for s in plan["steps"]), "read_eof"
        at = {ident: index for index, kind, ident in sends if kind == 303}
        for ident, active, queued in [(35, 4, 0), (60, 8, 4), (61, 8, 8)]:
            requests = [
                number
                for index, kind, number in sends
                if kind == 202 and index < at[ident]
            ]
            assert len(requests) == active + queued, "requests before diagnostic"
        assert (
            plan["expectation"]["global_download_limit"],
            plan["expectation"]["per_client_download_limit"],
        ) == (8, 8), "download limits"

    def test_postflight_is_read_only_and_restored_limits(
        self, plans: dict[str, dict]
    ) -> None:
        """The postflight plan is read-only and restores the limits."""
        plan = plans["postflight"]
        kinds = [kind for _, kind, _ in control_sends(plan)]
        assert kinds == [107, 348, 200, 206, 300, 303], "control kinds"
        limits = tuple(plan["expectation"][name] for name in LIMIT_NAMES)
        assert limits == RESTORED_LIMITS, "restored limits"


class ReferenceWitnessTests:
    """Check the reference witness for the queued download."""

    def make_report(
        self, *, second_wait: bytes | None = b"\0\1", second_ref: bytes = b"\0\0\0\2"
    ) -> dict:
        """Build a two-reply report for the reference checks.

        Parameters
        ----------
        second_wait : bytes | None
            The queue-position field of the second reply, or ``None`` to omit it.
        second_ref : bytes
            The transfer reference of the second reply.

        Returns
        -------
        dict
            A report holding the two decoded replies.
        """
        first = [
            (108, (1_049_073).to_bytes(4, "big")),
            (207, (1_048_893).to_bytes(4, "big")),
            (107, b"\0\0\0\1"),
        ]
        second = [
            (108, (1_049_073).to_bytes(4, "big")),
            (207, (1_048_893).to_bytes(4, "big")),
            (107, second_ref),
        ]
        if second_wait is not None:
            second.append((116, second_wait))
        return {
            "frames": [
                decode_frame(bytes.fromhex(packet(0, 11, payload(first), reply=1))),
                decode_frame(bytes.fromhex(packet(0, 12, payload(second), reply=1))),
            ]
        }

    def test_positive_queue_requires_distinct_refs_and_nonzero_wait(self) -> None:
        """A queued reply needs a distinct reference and a nonzero queue position."""
        result = check_references(self.make_report(), [11], [12])
        assert result["waiting_positions"] == [1], "waiting positions"
        with pytest.raises(ValueError, match="queue position"):
            check_references(self.make_report(second_wait=None), [11], [12])
        with pytest.raises(ValueError, match="queue position"):
            check_references(self.make_report(second_wait=b"\0\0"), [11], [12])
        with pytest.raises(ValueError, match="Duplicate transfer reference"):
            check_references(self.make_report(second_ref=b"\0\0\0\1"), [11], [12])


@functools.cache
def _current_report() -> dict:
    """Load the preflight report that holds the saved current UID.

    Returns
    -------
    dict
        The parsed preflight ``report.json``, loaded once.
    """
    return json.loads(PREFLIGHT_REPORT.read_text())


class CurrentUidTests:
    """Check that the saved current UID targets exactly one row."""

    def test_saved_current_uid_targets_one_row(self) -> None:
        """The saved current UID selects the single matching row."""
        result = check_diagnostic(_current_report(), 14, b"\0\6")
        assert result["field101_bytes"] == 303, "field 101 bytes"

    def test_stale_uid_cannot_be_relabelled_current(self) -> None:
        """A stale UID in the send cannot be relabelled as the current UID."""
        report = copy.deepcopy(_current_report())
        event = next(
            e for e in report["events"] if e["event"] == "send" and e["action"] == 15
        )
        event["hex"] = event["hex"][:-4] + "ffff"
        with pytest.raises(ValueError, match="target differs"):
            check_diagnostic(report, 14, b"\0\6")


@dc.dataclass(frozen=True, slots=True)
class _WitnessInputs:
    """The saved reports and captured sections that the witness tests read.

    Attributes
    ----------
    report : dict
        The preflight report.
    idle : bytes
        The idle field 101 section from the preflight reply.
    captured : bytes
        The 350-byte field 101 section from the loaded active reply.
    """

    report: dict
    idle: bytes
    captured: bytes


@functools.cache
def _witness_inputs() -> _WitnessInputs:
    """Load the saved reports and sections used by the section witness tests.

    Returns
    -------
    _WitnessInputs
        The preflight report, the idle section and the captured section.
    """
    report = json.loads(PREFLIGHT_REPORT.read_text())
    frame = next(f for f in report["frames"] if f["is_reply"] and f["id"] == 14)
    idle = bytes.fromhex(next(f["hex"] for f in frame["fields"] if f["id"] == 101))
    loaded_report = json.loads(LOADED_REPORT.read_text())
    active_reply = next(
        f for f in loaded_report["frames"] if f["is_reply"] and f["id"] == 13
    )
    captured = bytes.fromhex(
        next(f["hex"] for f in active_reply["fields"] if f["id"] == 101)
    )
    return _WitnessInputs(report=report, idle=idle, captured=captured)


class SectionWitnessTests:
    """Check the file-download section witness against saved and synthetic text."""

    def loaded(self, active: int, waiting: int) -> bytes:
        """Build a synthetic section with the given download counts.

        Parameters
        ----------
        active : int
            The number of active download rows to insert.
        waiting : int
            The number of waiting download rows to insert.

        Returns
        -------
        bytes
            The idle section with the requested rows inserted.
        """
        text = _witness_inputs().idle
        for heading, count, row in [
            (b"-------- File Downloads ---------", active, NAME + b"  0% 1MB\r"),
            (b"------- Waiting Downloads -------", waiting, NAME + b"   (File)\r"),
        ]:
            if count:
                marker = b"\r\r" + heading + b"\r\r"
                text = text.replace(marker + b"None.", marker + row * count)
        return text

    def test_exact_captured_350_byte_native_witness(self) -> None:
        """The captured 350-byte native section is a complete witness."""
        captured = _witness_inputs().captured
        assert len(captured) == 350, "captured size"
        result = section_witness(captured, 1, 1)
        assert result["status"] == "complete", "witness status"
        assert result["observed_counts"] == {
            "active": 1,
            "waiting": 1,
        }, "observed counts"

    def test_exact_counts_and_empty_unrelated_sections(self) -> None:
        """Exact download counts are complete and empty unrelated sections pass."""
        for active, waiting in [(1, 1), (4, 0), (8, 4), (8, 8), (0, 0)]:
            assert (
                section_witness(self.loaded(active, waiting), active, waiting)["status"]
                == "complete"
            ), "exact counts"

    def test_queue_without_active_and_reduced_density_are_incomplete(self) -> None:
        """A queue without an active row and reduced density are incomplete."""
        assert section_witness(self.loaded(0, 1), 1, 1)["status"] == "incomplete", (
            "queue without active"
        )
        assert section_witness(self.loaded(7, 8), 8, 8)["status"] == "incomplete", (
            "reduced density"
        )

    def test_stale_post_cancel_row_and_truncation_are_incomplete(self) -> None:
        """A stale post-cancel row and truncated sections are incomplete."""
        assert section_witness(self.loaded(1, 0), 0, 0)["status"] == "incomplete", (
            "stale row"
        )
        assert (
            section_witness(self.loaded(8, 8)[:600], 8, 8)["status"] == "incomplete"
        ), "truncated at 600"
        assert (
            section_witness(self.loaded(8, 8)[:-2], 8, 8)["status"] == "incomplete"
        ), "truncated at end"

    def test_swapped_grammars_and_clipped_file_token_are_incomplete(self) -> None:
        """Swapped row grammars and a clipped file token are incomplete."""
        captured = _witness_inputs().captured
        active = NAME + b"   5%   1M\r"
        waiting = NAME + b"   (File)\r"
        swapped = captured.replace(active, b"TEMPORARY\r")
        swapped = swapped.replace(waiting, active).replace(b"TEMPORARY\r", waiting)
        assert section_witness(swapped, 1, 1)["status"] == "incomplete", "swapped"
        clipped = captured.replace(b"(File)\r", b"(File\r")
        assert section_witness(clipped, 1, 1)["status"] == "incomplete", "clipped"

    def test_unrelated_upload_section_is_not_idle(self) -> None:
        """An upload row in the upload section is not treated as idle."""
        marker = b"\r\r--------- File Uploads ----------\r\r"
        text = _witness_inputs().idle.replace(
            marker + b"None.", marker + NAME + b"  0% 1MB\r"
        )
        assert section_witness(text, 0, 0)["status"] == "incomplete", "upload row"

    def test_cancellation_target_matches_saved_a7_ref(self) -> None:
        """The cancellation target must match the saved A7 reference."""
        check_cancellations(_witness_inputs().report, {16: bytes.fromhex("00025b1b")})
        with pytest.raises(ValueError, match="another reference"):
            check_cancellations(
                _witness_inputs().report, {16: bytes.fromhex("00025b1c")}
            )
