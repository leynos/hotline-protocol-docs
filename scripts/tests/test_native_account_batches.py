"""Reject atomic-batch, rename-rejection and password-sentinel assumptions."""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

import native_account_batch_cases as cases
import native_account_batch_model as model
import pytest
from native_wire_names import (
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_ATTRIBUTE_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_OFFSET,
    FIELD_NAME,
    FRAME_HEADER_BYTES,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from protocol_capture import decode_frame
from verify_native_account_batches import batch_result, catalogue, verify
from verify_native_auth import reply
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-account-batch-01"
)
PAIRED_CONNECTIONS = 75
TERMINAL_BATCH_ERRORS = 11
UNNAMED_FIELD_ID = 65000  # the unnamed outer ID and the unnamed filler field
ORDERED_FIELD_IDS = [0, UNNAMED_FIELD_ID, 0]
BATCH_REQUEST_TYPE = 349  # the batch request, which native_wire_names does not name
COLLISION_NOTICE_TYPE = 104  # the frame type of the collision notice
COLLISION_MARKER_FIELD = 109  # the marker field that the collision notice retains
NESTED_LENGTH = 512
NESTED_OVER_LENGTH = 513
FRAME_TYPE_HEX = slice(4, 8)  # the transaction type word of a frame, in hex
FRAME_HEADER_HEX = 2 * FRAME_HEADER_BYTES  # a frame header, in hex characters
BYTE_MASK = 0xFF  # complements one byte
BIT27_BYTE_OFFSET = ACCOUNT_ACCESS_OFFSET + 3  # the access byte that holds bit 27
IDENTITY_LIMIT_ERRORS = (1, 0)  # the errors of the rows before and after the limit


class AccountBatchTests:
    """Reject atomic-batch, rename-rejection and password-sentinel assumptions."""

    def _report(self, name: str) -> dict[str, typ.Any]:
        """Load the report of one retained batch case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / name / "report.json").read_text())

    def _spec(self, name: str) -> dict[str, typ.Any]:
        """Find the planned batch case called ``name``.

        Returns
        -------
        dict[str, typing.Any]
            The case record of ``specifications``.
        """
        return next(s for s in cases.specifications() if s["case"] == name)

    def _states(self, through: str) -> dict[str, model.State]:
        """Apply the modelled effects in order, up to and including ``through``.

        Returns
        -------
        dict[str, model.State]
            The account states after the effect named ``through``.

        Raises
        ------
        ValueError
            If no effect is named ``through``.
        """
        states = model.seed_states()
        for name, changes in model.effects().items():
            model.apply(states, changes)
            if name == through:
                return states
        raise ValueError(through)

    def _snapshots(self) -> dict[str, dict[str, model.State]]:
        """Build the stored-account snapshot of each native stage.

        Returns
        -------
        dict[str, dict[str, model.State]]
            The snapshot of each stage, by its name.
        """
        states = self._states("rename-collision")
        result = {
            "native-seed": model.seed_states(),
            "native-final": copy.deepcopy(states),
        }
        model.distinct_seed(states)
        result["native-distinct-seed"] = copy.deepcopy(states)
        model.distinct_effects(states)
        result["native-distinct-final"] = states
        return result

    def test_complete_paired_batch_and_stored_record_corpus(self) -> None:
        """The retained batch corpus verifies with its connections and errors."""
        result = verify(BATCH)
        assert (
            result["paired_connections"],
            result["terminal_batch_errors"],
        ) == (PAIRED_CONNECTIONS, TERMINAL_BATCH_ERRORS), (
            "the paired connections or the terminal batch errors differ"
        )

    def test_outer_ids_zero_unknown_and_repeated_are_processed_in_order(self) -> None:
        """Outer IDs zero, unknown and repeated are processed in their order."""
        plan = json.loads((BATCH / "batch-ordered-outer-ids/plan.json").read_text())
        request = next(
            decode_frame(bytes.fromhex(s["hex"]))
            for s in plan["steps"]
            if s["op"] == "send"
            and len(s["hex"]) >= FRAME_HEADER_HEX
            and int(s["hex"][FRAME_TYPE_HEX], 16) == BATCH_REQUEST_TYPE
        )
        assert [f["id"] for f in request["fields"]] == ORDERED_FIELD_IDS, (
            "the outer IDs of the ordered batch request differ"
        )
        assert (
            fields(reply(self._report("after-ordered-outer-ids"), 101))[FIELD_NAME]
            == b"Ordered done"
        ), "the renamed account record differs"
        assert reply(self._report("after-ordered-outer-ids"), 100)["error"] == 1, (
            "the reply to the first ordered row differs"
        )

    def test_collision_notice_is_not_a_terminal_error(self) -> None:
        """A collision notice in a batch reply is not a terminal ACK or error."""
        report = self._report("batch-collision-continues")
        reply(report, 10)["error"] = 1
        with pytest.raises(ValueError, match="terminal ACK/error"):
            batch_result(report, self._spec("collision-continues"))

    def test_collision_notice_retains_its_109_marker(self) -> None:
        """The collision notice without its marker field is refused."""
        report = self._report("batch-collision-continues")
        notice = next(f for f in report["frames"] if f["type"] == COLLISION_NOTICE_TYPE)
        notice["fields"] = [
            f for f in notice["fields"] if f["id"] != COLLISION_MARKER_FIELD
        ]
        with pytest.raises(ValueError, match="collision notice"):
            batch_result(report, self._spec("collision-continues"))

    def test_malformed_record_does_not_roll_back_later_create(self) -> None:
        """A malformed record does not roll back the create that follows it."""
        frame = reply(self._report("after-empty-copy-continues"), 100)
        frame["error"] = 1
        with pytest.raises(ValueError, match="Batch account state"):
            model.account_reply(
                frame, "after-empty-copy", self._states("empty-copy-continues")
            )

    def test_permission_failure_does_not_roll_back_earlier_create(self) -> None:
        """A permission failure does not roll back the create before it."""
        frame = reply(self._report("after-create-update-denied"), 100)
        frame["error"] = 1
        with pytest.raises(ValueError, match="Batch account state"):
            model.account_reply(
                frame, "created-before-deny", self._states("create-update-denied")
            )

    def test_permission_failure_skips_later_items(self) -> None:
        """A permission failure leaves the later items of the batch absent."""
        frame = reply(self._report("after-create-update-denied"), 102)
        frame["error"] = 0
        with pytest.raises(ValueError, match="absent batch"):
            model.account_reply(
                frame, "skipped-create", self._states("create-update-denied")
            )

    def test_rename_collision_does_not_preserve_destination_display_record(
        self,
    ) -> None:
        """A rename collision does not keep the destination's display record."""
        frame = reply(self._report("after-rename-collision"), 102)
        next(f for f in frame["fields"] if f["id"] == FIELD_NAME)["hex"] = (
            b"Seed28-clash-new".hex()
        )
        with pytest.raises(ValueError, match="Batch account state"):
            model.account_reply(frame, "clash-new", self._states("rename-collision"))

    def test_rename_collision_does_not_skip_following_create(self) -> None:
        """A rename collision does not skip the create that follows it."""
        frame = reply(self._report("after-rename-collision"), 103)
        frame["error"] = 1
        with pytest.raises(ValueError, match="Batch account state"):
            model.account_reply(
                frame, "clash-skipped", self._states("rename-collision")
            )

    def test_native_permission_family_is_not_generic_list_saving_error(self) -> None:
        """A permission message is not the generic list-saving error."""
        report = self._report("batch-delete-create-denied")
        reply(report, 10)["fields"][0]["hex"] = b"Error saving list of accounts.".hex()
        with pytest.raises(ValueError, match="terminal ACK/error"):
            batch_result(report, self._spec("delete-create-denied"))

    def test_per_item_subset_exemption_is_not_actor_full_access(self) -> None:
        """A per-item subset exemption is not the actor's full access."""
        report = self._report("batch-subset-exempt27")
        next(f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION)[
            "fields"
        ][0]["hex"] = "fff3cfefff800000"
        with pytest.raises(ValueError, match="role admission"):
            batch_result(report, self._spec("subset-exempt27"))

    def test_nul_create_password_is_literal_without_an_old_name(self) -> None:
        """A NUL create password is stored literally when no old name is given."""
        report = self._report("nul-password-login")
        assert reply(report, 1)["error"] == 0, "the NUL-password login was refused"
        rows = json.loads((BATCH / "native-final/extraction.json").read_text())[
            "records"
        ]
        row = next(r for r in rows if r["path"].endswith("/m-b28-nul-new/UserData"))
        data = (BATCH / "native-final" / (row["key"] + ".data")).read_bytes()
        assert (
            data[ACCOUNT_PASSWORD_LENGTH_OFFSET : ACCOUNT_PASSWORD_OFFSET + 1]
            == b"\0\1\0"
        ), "the stored NUL password record differs"

    def test_512_and_513_entries_have_distinct_captured_lengths(self) -> None:
        """The 512 and 513 nested entries keep their captured lengths."""
        for length in [NESTED_LENGTH, NESTED_OVER_LENGTH]:
            report = self._report(f"after-nested{length}")
            assert reply(report, 100)["error"] == 0, (
                f"the nested {length}-byte batch was refused"
            )
            plan = json.loads((BATCH / f"batch-nested{length}/plan.json").read_text())
            frame = next(
                decode_frame(bytes.fromhex(s["hex"]))
                for s in plan["steps"]
                if s["op"] == "send"
                and len(s["hex"]) >= FRAME_HEADER_HEX
                and int(s["hex"][FRAME_TYPE_HEX], 16) == BATCH_REQUEST_TYPE
            )
            assert len(bytes.fromhex(frame["fields"][0]["hex"])) == length, (
                f"the nested entry is not {length} bytes"
            )

    def test_identity_beyond_copied_prefix_is_not_created(self) -> None:
        """An identity beyond the copied prefix is not created."""
        report = self._report("after-identity-after-limit")
        errors = (reply(report, 100)["error"], reply(report, 101)["error"])
        assert errors == IDENTITY_LIMIT_ERRORS, (
            "the identity-after-limit replies differ"
        )

    def test_cleanup_refuses_unobserved_or_duplicate_identity(self) -> None:
        """Cleanup refuses an unobserved or a duplicated identity."""
        for labels in [["admin"], ["actor-create", "actor-create"]]:
            with pytest.raises(
                ValueError,
                match="Cleanup requires a unique observed owned inventory",
            ):
                cases.cleanup(labels)

    def _mutate_record(
        self,
        target: Path,
        label: str,
        operation: cabc.Callable[[bytearray], None],
    ) -> None:
        """Copy the retained stages to ``target`` and alter one stored record.

        The record of the owned account ``label`` in the distinct final stage is
        changed by ``operation``, and the catalogue is then run on the copy.
        """
        for name in [
            "native-seed",
            "native-final",
            "native-distinct-seed",
            "native-distinct-final",
            "native-cleanup",
            "native-published",
        ]:
            shutil.copytree(BATCH / name, target / name)
        rows = json.loads(
            (target / "native-distinct-final/extraction.json").read_text()
        )["records"]
        row = next(
            r
            for r in rows
            if r["path"] == "/Hotline19/Users/m-b28-" + label + "/UserData"
        )
        path = target / "native-distinct-final" / (row["key"] + ".data")
        data = bytearray(path.read_bytes())
        operation(data)
        path.write_bytes(data)
        catalogue(target, self._snapshots())

    def test_collision_destination_must_have_source_password(
        self, tmp_path: Path
    ) -> None:
        """A collision destination must hold the source password."""
        with pytest.raises(ValueError, match="stored account record"):
            self._mutate_record(
                tmp_path,
                "clash2-new",
                lambda data: data.__setitem__(
                    ACCOUNT_PASSWORD_OFFSET, ord("t") ^ BYTE_MASK
                ),
            )

    def test_permission_bit27_is_retained_in_created_record(
        self, tmp_path: Path
    ) -> None:
        """The permission bit 27 is retained in the created record."""
        with pytest.raises(ValueError, match="stored account record"):
            self._mutate_record(
                tmp_path,
                "grant-exempt",
                lambda data: data.__setitem__(BIT27_BYTE_OFFSET, 0),
            )

    def test_batch_sparse_defaults_do_not_keep_old_attribute(
        self, tmp_path: Path
    ) -> None:
        """Sparse defaults in a batch do not keep the old attribute."""
        with pytest.raises(ValueError, match="stored account record"):
            self._mutate_record(
                tmp_path,
                "defaults",
                lambda data: data.__setitem__(ACCOUNT_ATTRIBUTE_OFFSET, ord("s")),
            )
