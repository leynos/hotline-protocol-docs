"""Offline guards for the unexecuted A11 near-boundary packet."""

import dataclasses as dc
import functools
import importlib.util
import json
import re
from pathlib import Path

import pytest
from native_diagnostic_existing_cases import NAME
from native_diagnostic_near_cases import build
from native_plan import packet, payload
from protocol_capture import decode_frame, validate_plan
from test_native_diagnostic_existing import control_sends
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_references,
    section_witness,
)
from verify_native_diagnostic_near import (
    expected_ids,
    near_complete,
    require_positions,
    sent_ids,
)

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(name="plan")
def plan_fixture() -> dict:
    """Build the unexecuted near-boundary plan.

    Returns
    -------
    dict
        The near-boundary plan built with the emulator PID.
    """
    return build({"emulator_pid": 1099659})


class NearPlanTests:
    """Check the exact identifiers, bounds and fixture of the near-boundary plan."""

    def test_exact_unique_ids_bounds_and_read_only_fixture(self, plan: dict) -> None:
        """The plan sends exactly the expected unique ids within its bounds."""
        validate_plan(plan)
        sends = control_sends(plan)
        assert [identifier for _, _, identifier in sends] == expected_ids(), "ids"
        assert len(expected_ids()) == len(set(expected_ids())), "unique ids"
        assert [kind for _, kind, _ in sends].count(202) == 24, "references"
        assert [kind for _, kind, _ in sends].count(214) == 24, "cancellations"
        assert [s["connection"] for s in plan["steps"] if s["op"] == "connect"] == [
            "a"
        ] + [f"active{i}" for i in range(8)], "connections"
        assert not ({203, 204, 304, 350, 351, 352} & {k for _, k, _ in sends}), (
            "forbidden kinds"
        )
        assert plan["expectation"]["maximum_references"] == 24, "reference bound"
        assert plan["expectation"]["maximum_data_sockets"] == 8, "socket bound"
        assert plan["expectation"]["fixture_name_hex"] == NAME.hex(), "fixture name"

    def test_fixed_points_and_saved_reference_placeholders(self, plan: dict) -> None:
        """The fixed points and saved reference placeholders are as planned."""
        sends = control_sends(plan)
        assert [i for _, k, i in sends if k == 303] == [140, 141, 240], "points"
        assert [i for _, k, i in sends if k == 202] == list(range(100, 108)) + list(
            range(120, 136)
        ), "references"
        by_id = {identifier: offset for offset, _, identifier in sends}
        assert sum(k == 202 and offset < by_id[140] for offset, k, _ in sends) == 16, (
            "references before 140"
        )
        assert sum(k == 202 and offset < by_id[141] for offset, k, _ in sends) == 24, (
            "references before 141"
        )
        assert [i for _, k, i in sends if k == 214] == list(range(215, 199, -1)) + list(
            range(227, 219, -1)
        ), "cancellations"
        cancel_steps = [
            s
            for s in plan["steps"]
            if (s["op"] == "send" and "{queued" in s["hex"])
            or (s["op"] == "send" and "{active" in s["hex"] and s["connection"] == "a")
        ]
        assert len(cancel_steps) == 24, "cancel steps"
        assert [s["hex"].split("{")[1].split("}")[0] for s in cancel_steps] == [
            f"queued{i}" for i in reversed(range(16))
        ] + [f"active{i}" for i in reversed(range(8))], "placeholders"


@dc.dataclass(frozen=True, slots=True)
class _NearWitness:
    """The saved and synthetic sections that the near witness tests read.

    Attributes
    ----------
    actual_8_8 : bytes
        The saved 763-byte section with eight active and eight waiting rows.
    idle : bytes
        The saved idle section.
    synthetic_8_16 : bytes
        The saved section with eight further waiting rows inserted.
    """

    actual_8_8: bytes
    idle: bytes
    synthetic_8_16: bytes


@functools.cache
def _near_witness() -> _NearWitness:
    """Load the saved density sections and derive the synthetic sixteen-row one.

    Returns
    -------
    _NearWitness
        The saved 8-8 section, the idle section and the synthetic 8-16 section.
    """
    path = (
        ROOT
        / "evidence/gap-remediation/2026-11-13/native-diagnostic-density-01"
        / "verification-density.json"
    )
    data = json.loads(path.read_text())["diagnostics"]
    actual_8_8 = bytes.fromhex(data["61"]["field101_hex"])
    idle = bytes.fromhex(data["90"]["field101_hex"])
    marker = b"\r\r------- Waiting Downloads -------\r\r"
    synthetic_8_16 = actual_8_8.replace(marker, marker + (NAME + b"   (File)\r") * 8, 1)
    return _NearWitness(actual_8_8=actual_8_8, idle=idle, synthetic_8_16=synthetic_8_16)


class NearWitnessTests:
    """Check the near-boundary section witnesses against saved and synthetic text."""

    def test_saved_eight_eight_and_predicted_sixteen_rows(self) -> None:
        """The saved 8-8 section and the predicted 8-16 section are complete."""
        witness = _near_witness()
        assert len(witness.actual_8_8) == 763, "saved 8-8 size"
        assert len(witness.synthetic_8_16) == 995, "synthetic 8-16 size"
        witnesses = {
            "140": section_witness(witness.actual_8_8, 8, 8),
            "141": section_witness(witness.synthetic_8_16, 8, 16),
            "240": section_witness(witness.idle, 0, 0),
        }
        assert near_complete(
            {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 995}},
            witnesses,
        ), "near complete"

    def test_wrong_rows_size_and_stale_idle_fail(self) -> None:
        """Wrong rows, a wrong size and a stale idle section fail."""
        witness = _near_witness()
        wrong_rows = section_witness(witness.actual_8_8, 8, 16)
        clipped = section_witness(witness.synthetic_8_16[:-3], 8, 16)
        assert wrong_rows["status"] == "incomplete", "wrong rows"
        assert clipped["status"] == "incomplete", "clipped"
        complete = {
            "140": {"status": "complete"},
            "141": {"status": "complete"},
            "240": {"status": "complete"},
        }
        assert not near_complete(
            {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 994}},
            complete,
        ), "wrong size"
        complete["240"] = section_witness(witness.actual_8_8, 0, 0)
        assert not near_complete(
            {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 995}},
            complete,
        ), "stale idle"

    def test_queue_positions_and_wrong_cancel_reference_fail(self) -> None:
        """Queue positions and the cancellation reference are checked."""

        def frame(identifier: int, ref: int, queue: int | None) -> dict:
            """Decode a reply carrying a reference and an optional queue position.

            Parameters
            ----------
            identifier : int
                The request identifier of the reply.
            ref : int
                The transfer reference.
            queue : int | None
                The queue position, or ``None`` to omit it.

            Returns
            -------
            dict
                The decoded reply.
            """
            fields = [
                (107, ref.to_bytes(4, "big")),
                (108, (1_049_073).to_bytes(4, "big")),
                (207, (1_048_893).to_bytes(4, "big")),
            ]
            if queue is not None:
                fields.append((116, queue.to_bytes(2, "big")))
            return decode_frame(
                bytes.fromhex(packet(0, identifier, payload(fields), reply=1))
            )

        report = {"frames": [frame(100, 1, None), frame(120, 2, 1)]}
        assert check_references(report, [100], [120])["waiting_positions"] == [1], (
            "waiting positions"
        )
        require_positions(list(range(1, 17)))
        with pytest.raises(ValueError, match="Queue positions differ"):
            require_positions([*list(range(1, 16)), 15])
        report["frames"][1] = frame(120, 2, 0)
        with pytest.raises(ValueError, match="queue position"):
            check_references(report, [100], [120])
        report = {
            "frames": [frame(200, 1, None)],
            "events": [
                {
                    "event": "send",
                    "connection": "a",
                    "hex": packet(214, 200, payload([(107, b"BAD!")])),
                }
            ],
        }
        with pytest.raises(ValueError, match="targeted another reference"):
            check_cancellations(report, {200: b"GOOD"})

    def test_duplicate_request_ids_are_detectable(self) -> None:
        """Duplicate request identifiers are visible in the sent ids."""
        report = {
            "events": [
                {"event": "send", "connection": "a", "hex": packet(202, 100)},
                {"event": "send", "connection": "a", "hex": packet(202, 100)},
            ]
        }
        ids = sent_ids(report)
        assert ids == [100, 100], "sent ids"
        assert len(ids) != len(set(ids)), "duplicates detectable"

    def test_guest_only_ack_tail_rejects_wrong_id_status_and_clip(self) -> None:
        """The guest-only ACK tail rejects wrong, clipped and failed tails."""
        source = (
            ROOT
            / "evidence/gap-remediation/2026-11-13/native-diagnostic-near-01"
            / "verify_partial.py"
        )
        spec = importlib.util.spec_from_file_location("a12_partial", source)
        assert spec is not None, "module spec"
        assert spec.loader is not None, "module loader"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        saved = bytes.fromhex("00010000000000cf0000000000000002000000020000")
        assert module.guest_ack_tail(saved)["frame"]["id"] == 207, "ACK id"
        malformed_tails = (
            (saved[:-1], "Guest-only control tail is not one 22-byte ACK"),
            (
                saved[:7] + b"\xce" + saved[8:],
                "Guest-only tail is not successful cancellation ACK 207",
            ),
            (
                saved[:11] + b"\x01" + saved[12:],
                "Guest-only tail is not successful cancellation ACK 207",
            ),
        )
        for malformed, message in malformed_tails:
            with pytest.raises(ValueError, match=re.escape(message)):
                module.guest_ack_tail(malformed)
