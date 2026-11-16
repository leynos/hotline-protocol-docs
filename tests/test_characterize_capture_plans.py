"""Characterize the plan validation and frame decoding of ``protocol_capture``.

``protocol_capture`` is not refactored in this pass (its self-hash needs a
decision), so these tests are the continuity for a later refactor: every
expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``). Each error message of ``validate_plan`` has a
plan that breaks that rule alone, and pairs of faults pin which error is raised
first. The checks on a saved capture and the command line are in
``test_characterize_capture_verify.py``.
"""

import hashlib
import struct
import typing as typ

import protocol_capture as pc
import pytest

CHARACTERIZES = "protocol_capture.py"
ORACLE = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
LIMIT = 8 * 1024 * 1024
SECONDS_LIMIT = 3600

type Plan = dict[str, typ.Any]


def plan_with(*steps: dict[str, typ.Any], **changes: object) -> Plan:
    """Build a valid synthetic plan that connects, then runs ``steps``.

    Returns
    -------
    dict[str, typing.Any]
        The plan, with ``changes`` applied at the top level.
    """
    plan: Plan = {
        "schema_version": 1,
        "profile": "synthetic-tool-test",
        "operator": "operator",
        "gap_ids": ["GAP-001"],
        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
        "steps": [
            {"op": "connect", "connection": "main", "endpoint": "control"},
            *steps,
        ],
    }
    plan.update(changes)
    return plan


def refused(plan: Plan, message: str) -> None:
    """Require that ``validate_plan`` raises a ``ValueError`` with this message."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        pc.validate_plan(plan)


def step(**fields: object) -> dict[str, typ.Any]:
    """Build a step on the ``main`` connection.

    Returns
    -------
    dict[str, typing.Any]
        The step.
    """
    return {"connection": "main", **fields}


class PlanHeaderTests:
    """The plan's own fields are checked before its steps."""

    def test_a_valid_plan_passes(self) -> None:
        """No error, and nothing returned."""
        assert pc.validate_plan(plan_with(step(op="read", size=1))) is None, (
            "expected: no error, and nothing returned"
        )

    def test_another_schema_version_is_unsupported(self) -> None:
        """Only version one."""
        refused(plan_with(schema_version=2), "Unsupported capture schema")

    def test_a_missing_schema_version_is_unsupported(self) -> None:
        """The version is read with ``get``, so absence is the same error."""
        plan = plan_with()
        del plan["schema_version"]
        refused(plan, "Unsupported capture schema")

    def test_an_unknown_profile_is_refused_after_the_schema(self) -> None:
        """The schema check comes first."""
        refused(plan_with(profile="x"), "Unknown evidence profile")
        refused(plan_with(profile="x", schema_version=2), "Unsupported capture schema")

    @pytest.mark.parametrize("changes", [{"operator": ""}, {"gap_ids": []}])
    def test_an_operator_and_gap_ids_are_required(
        self, changes: dict[str, object]
    ) -> None:
        """Both must be present and non-empty."""
        refused(plan_with(**changes), "Operator and gap IDs are required")

    def test_the_native_profile_requires_the_recorded_oracle_hash(self) -> None:
        """A native plan with another hash is refused."""
        plan = plan_with(profile="native-mac-oracle", oracle_sha256="0" * 64)
        refused(plan, "Native profile requires the recorded Mac oracle hash")
        plan["oracle_sha256"] = ORACLE
        pc.validate_plan(plan)

    def test_a_native_plan_without_the_hash_is_a_key_error(self) -> None:
        """The hash is read by key under the native profile."""
        with pytest.raises(KeyError, match="oracle_sha256"):
            pc.validate_plan(plan_with(profile="native-mac-oracle"))

    @pytest.mark.parametrize(
        "endpoint",
        [
            {"host": 1, "port": 1},
            {"host": "h", "port": 0},
            {"host": "h", "port": 65536},
        ],
    )
    def test_an_invalid_endpoint_is_refused(self, endpoint: dict[str, object]) -> None:
        """A host that is not text, or a port outside 1 to 65535."""
        refused(plan_with(endpoints={"control": endpoint}), "Invalid endpoint")

    def test_the_boundary_ports_are_accepted(self) -> None:
        """One and 65535 are valid."""
        for port in (1, 65535):
            endpoints = {"control": {"host": "h", "port": port}}
            pc.validate_plan(plan_with(endpoints=endpoints))

    def test_the_endpoint_check_comes_before_the_steps(self) -> None:
        """A bad endpoint and a bad step is an endpoint error."""
        plan = plan_with(step(op="bogus"), endpoints={"c": {"host": 1, "port": 1}})
        refused(plan, "Invalid endpoint")


class StepTests:
    """Each rule of a step, in the order the validator applies them."""

    @pytest.mark.parametrize(
        "bad",
        [
            {"op": "connect", "connection": "main", "endpoint": "control"},
            {"op": "connect", "connection": "", "endpoint": "control"},
            {"op": "connect", "connection": "x", "endpoint": "missing"},
        ],
    )
    def test_an_invalid_connection_declaration_is_refused(
        self, bad: dict[str, str]
    ) -> None:
        """A repeated or empty name, or an unknown endpoint."""
        refused(plan_with(bad), "Invalid connection declaration")

    @pytest.mark.parametrize("seconds", [-1, 3601])
    def test_a_pause_outside_zero_to_an_hour_is_invalid(self, seconds: int) -> None:
        """The bounds are inclusive at both ends."""
        refused(plan_with(step(op="pause", seconds=seconds)), "Invalid pause")
        for ok_seconds in (0, SECONDS_LIMIT):
            pc.validate_plan(plan_with(step(op="pause", seconds=ok_seconds)))

    def test_a_pause_without_seconds_is_a_key_error(self) -> None:
        """The pause length is read by key."""
        with pytest.raises(KeyError, match="seconds"):
            pc.validate_plan(plan_with(step(op="pause")))

    @pytest.mark.parametrize("op", ["send", "read", "read_frame", "read_eof"])
    def test_an_action_on_an_undeclared_connection_is_refused(self, op: str) -> None:
        """The connection must have been declared."""
        refused(
            plan_with({"op": op, "connection": "other", "hex": "00", "size": 1}),
            "Unknown connection: other",
        )

    def test_a_closed_connection_is_unknown_again(self) -> None:
        """Closing removes the connection."""
        plan = plan_with(step(op="close"), step(op="close"))
        refused(plan, "Unknown connection: main")

    def test_a_send_after_a_write_shutdown_is_refused(self) -> None:
        """Half-closing the write side forbids further sends and a second shutdown."""
        message = "Connection write side is already closed"
        shut = step(op="shutdown_write")
        refused(plan_with(shut, step(op="send", hex="00")), message)
        refused(plan_with(shut, shut), message)

    def test_an_unknown_action_is_refused(self) -> None:
        """Only the nine operations."""
        refused(plan_with(step(op="bogus")), "Unknown action: bogus")

    @pytest.mark.parametrize("timeout", [0, -1, 3601])
    def test_an_action_timeout_outside_zero_to_an_hour_is_invalid(
        self, timeout: float
    ) -> None:
        """Positive, at most an hour."""
        refused(
            plan_with(step(op="read", size=1, timeout=timeout)),
            "Invalid action timeout",
        )

    def test_a_size_from_on_another_action_is_refused(self) -> None:
        """Only a fixed-length read takes ``size_from``."""
        refused(
            plan_with(step(op="read_eof", size_from="x")),
            "Only fixed-length reads can use size_from",
        )

    @pytest.mark.parametrize(
        "match",
        [{}, {"bogus": 1}, {"is_reply": "1"}, {"is_reply": 256}, {"type": -1}],
    )
    def test_an_invalid_frame_match_is_refused(self, match: dict[str, object]) -> None:
        """Empty, an unknown key, a non-integer or an out-of-range value."""
        plan = plan_with(step(op="read_frame", match_frame=match))
        refused(plan, "Invalid frame match")

    def test_a_frame_match_on_another_action_is_refused(self) -> None:
        """Only ``read_frame`` takes a match."""
        plan = plan_with(step(op="read", size=1, match_frame={"type": 1}))
        refused(plan, "Invalid frame match")

    def test_a_valid_frame_match_is_accepted(self) -> None:
        """Each bound is inclusive."""
        match = {"is_reply": 255, "type": 65535, "id": 0xFFFFFFFF}
        pc.validate_plan(plan_with(step(op="read_frame", match_frame=match)))

    @pytest.mark.parametrize("size", [0, LIMIT + 1])
    def test_a_read_size_outside_the_limit_is_refused(self, size: int) -> None:
        """Positive and at most eight mebibytes."""
        refused(
            plan_with(step(op="read", size=size)), "Read size exceeds capture limit"
        )
        pc.validate_plan(plan_with(step(op="read", size=LIMIT)))

    def test_a_read_size_from_an_unknown_variable_is_refused(self) -> None:
        """The variable must have been saved earlier."""
        plan = plan_with(step(op="read", size_from="never"))
        refused(plan, "Unknown or ambiguous read size")

    def test_a_read_with_both_size_and_size_from_is_ambiguous(self) -> None:
        """One or the other."""
        saved = step(op="read", size=4, save={"name": "n", "offset": 0, "size": 4})
        plan = plan_with(saved, step(op="read", size=1, size_from="n"))
        refused(plan, "Unknown or ambiguous read size")

    def test_a_send_that_names_an_unsaved_variable_is_refused(self) -> None:
        """Variables are checked in text order."""
        refused(plan_with(step(op="send", hex="{later}")), "Unknown saved bytes: later")

    def test_a_send_over_the_limit_is_refused(self) -> None:
        """The literal bytes, with variables counted as one byte, are bounded."""
        plan = plan_with(step(op="send", hex="00" * (LIMIT + 1)))
        refused(plan, "Send size exceeds capture limit")
        pc.validate_plan(plan_with(step(op="send", hex="00" * LIMIT)))

    def test_a_non_hexadecimal_expectation_is_a_value_error(self) -> None:
        """The expected bytes must parse."""
        with pytest.raises(ValueError, match="non-hexadecimal"):
            pc.validate_plan(plan_with(step(op="read", size=1, expect_hex="zz")))


class SaveTests:
    """Saved bytes and saved fields."""

    def test_only_received_bytes_can_be_saved(self) -> None:
        """A send step cannot save."""
        saved = {"name": "n", "offset": 0, "size": 1}
        refused(
            plan_with(step(op="send", hex="00", save=saved)),
            "Only received bytes can be saved",
        )

    @pytest.mark.parametrize("name", ["", "A", "1x", "a-b"])
    def test_a_saved_byte_name_must_be_lower_case_and_start_with_a_letter(
        self, name: str
    ) -> None:
        """Letters, digits and underscores, beginning with a letter."""
        saved = {"name": name, "offset": 0, "size": 1}
        refused(
            plan_with(step(op="read", size=1, save=saved)), "Invalid saved-byte name"
        )

    @pytest.mark.parametrize(
        "bounds", [{"offset": -1, "size": 1}, {"offset": 0, "size": 0}]
    )
    def test_saved_byte_bounds_are_checked(self, bounds: dict[str, int]) -> None:
        """A negative offset or an empty size."""
        saved = {"name": "n", **bounds}
        refused(
            plan_with(step(op="read", size=1, save=saved)), "Invalid saved-byte bounds"
        )

    def test_a_saved_field_must_come_from_a_frame_read(self) -> None:
        """Field selectors belong to ``read_frame``."""
        refused(
            plan_with(step(op="read", size=1, save_fields={"x": 1})),
            "Only a frame field can be saved by ID",
        )

    @pytest.mark.parametrize("field_id", [-1, 65536])
    def test_a_saved_field_id_must_fit_two_bytes(self, field_id: int) -> None:
        """Zero to 65535."""
        plan = plan_with(step(op="read_frame", save_fields={"x": field_id}))
        refused(plan, "Only a frame field can be saved by ID")

    def test_a_saved_field_name_must_be_a_valid_name(self) -> None:
        """The name rule is the one for saved bytes."""
        plan = plan_with(step(op="read_frame", save_fields={"Bad": 1}))
        refused(plan, "Invalid saved-field name")

    def test_both_selector_forms_are_merged_and_a_repeat_is_refused(self) -> None:
        """``save_field`` and ``save_fields`` may not name one variable twice."""
        both = step(
            op="read_frame",
            save_fields={"x": 1},
            save_field={"name": "x", "id": 2},
        )
        refused(plan_with(both), "Repeated saved-field variable")
        assert pc.field_saves({
            "save_fields": {"a": 1},
            "save_field": {"name": "b", "id": 2},
        }) == {"a": 1, "b": 2}, "expected the merged selectors"
        assert not pc.field_saves({}), "expected no selectors"


class FrameTests:
    """Decoding one physical frame."""

    @staticmethod
    def frame(payload: bytes, total: int | None = None) -> bytes:
        """Build a frame with a 20-byte header.

        Returns
        -------
        bytes
            The frame.
        """
        header = struct.pack(
            ">BBHIIII",
            1,
            1,
            300,
            7,
            0,
            len(payload) if total is None else total,
            len(payload),
        )
        return header + payload

    def test_a_complete_frame_lists_its_fields_and_count(self) -> None:
        """Header fields, the field list, the declared count and no remainder."""
        payload = b"\0\2" + b"\0\x65\0\2ab" + b"\0\x66\0\0"
        decoded = pc.decode_frame(self.frame(payload))
        expected = {
            "flags": 1,
            "is_reply": 1,
            "type": 300,
            "id": 7,
            "error": 0,
            "total_size": len(payload),
            "data_size": len(payload),
            "payload_hex": payload.hex(),
            "fields": [{"id": 101, "hex": "6162"}, {"id": 102, "hex": ""}],
            "declared_field_count": 2,
            "unconsumed_hex": "",
        }
        assert decoded == expected, "expected the decoded frame"

    def test_a_fragment_is_not_decoded_further(self) -> None:
        """A frame whose total exceeds its data gets a note only."""
        decoded = pc.decode_frame(self.frame(b"\0\0", total=99))
        assert decoded["decode_note"] == (
            "Physical fragment only; no logical TLV inference"
        ), "expected the note"
        assert "fields" not in decoded, "expected no fields"

    def test_a_payload_without_a_count_word_is_noted(self) -> None:
        """Fewer than two payload bytes."""
        decoded = pc.decode_frame(self.frame(b"\0"))
        assert decoded["decode_note"] == "Payload lacks a complete count word", (
            "expected: fewer than two payload bytes"
        )

    def test_a_field_that_runs_past_the_payload_stops_the_list(self) -> None:
        """The count is kept, the partial field is left unconsumed."""
        payload = b"\0\2" + b"\0\x65\0\2ab" + b"\0\x66\0\x09x"
        decoded = pc.decode_frame(self.frame(payload))
        assert decoded["fields"] == [{"id": 101, "hex": "6162"}], "expected one field"
        assert decoded["declared_field_count"] == 2, "expected the declared count"
        assert decoded["unconsumed_hex"] == b"\0\x66\0\x09x".hex(), "expected the rest"

    def test_a_short_header_is_a_struct_error(self) -> None:
        """Fewer than 20 bytes cannot be unpacked."""
        with pytest.raises(struct.error):
            pc.decode_frame(b"\0" * 19)

    def test_digest_is_the_lower_case_sha256(self) -> None:
        """The identity of exact bytes."""
        assert pc.digest(b"abc") == hashlib.sha256(b"abc").hexdigest(), (
            "expected: the identity of exact bytes"
        )
        assert pc.ORACLE_SHA256 == ORACLE, "expected the oracle hash"
