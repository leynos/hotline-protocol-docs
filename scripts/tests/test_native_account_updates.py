"""Reject password-placeholder, sparse-update and native record misreadings."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_NAME,
    FIELD_PASSWORD,
)
from verify_native_account_updates import account_reply, storage, verify
from verify_native_auth import reply
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-account-update-01"
)
POSITIVE_LOGINS = 9
NEGATIVE_LOGINS = 8


class AccountUpdateTests:
    """Reject password-placeholder, sparse-update and native record misreadings."""

    def report(self, label: str) -> dict[str, typ.Any]:
        """Load the report of one retained account case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / label / "report.json").read_text())

    def test_entire_paired_account_corpus(self) -> None:
        """The retained account corpus verifies, with its nine and eight logins."""
        result = verify(BATCH)
        assert (result["positive_logins"], result["negative_logins"]) == (
            POSITIVE_LOGINS,
            NEGATIVE_LOGINS,
        ), "expected nine positive and eight negative logins"

    def test_sparse_update_clears_instead_of_preserving_access(self) -> None:
        """A sparse update that keeps the access bitmap is refused."""
        frame = reply(self.report("mutation-sparse"), 12)
        next(f for f in frame["fields"] if f["id"] == FIELD_ACCESS_BITMAP)["hex"] = (
            "2000000000000000"
        )
        with pytest.raises(ValueError, match="default/placeholder"):
            account_reply(frame, "sparse", after=True)

    def test_empty_account_display_name_is_omitted_from_retrieval(self) -> None:
        """An empty display name that is returned in retrieval is refused."""
        frame = reply(self.report("mutation-sparse"), 12)
        frame["fields"].append({"id": FIELD_NAME, "hex": ""})
        with pytest.raises(ValueError, match="retrieval"):
            account_reply(frame, "sparse", after=True)

    def test_111_is_not_returned_even_when_stored(self) -> None:
        """The opaque account attribute is refused when retrieval returns it."""
        frame = reply(self.report("mutation-attribute65"), 12)
        frame["fields"].append({
            "id": FIELD_ACCOUNT_ATTRIBUTE,
            "hex": (b"X" * 64).hex(),
        })
        with pytest.raises(ValueError, match="retrieval"):
            account_reply(frame, "attribute65", after=True)

    def test_empty_password_omits_presence_placeholder(self) -> None:
        """A presence placeholder for an empty password is refused."""
        frame = reply(self.report("mutation-absent"), 12)
        frame["fields"].append({"id": FIELD_PASSWORD, "hex": "78"})
        with pytest.raises(ValueError, match="placeholder"):
            account_reply(frame, "absent", after=True)

    def test_retrieval_never_returns_the_actual_encoded_password(self) -> None:
        """A retrieval that returns the encoded password is refused."""
        frame = reply(self.report("mutation-preserve"), 12)
        next(f for f in frame["fields"] if f["id"] == FIELD_PASSWORD)["hex"] = bytes(
            x ^ 255 for x in b"account-base-26"
        ).hex()
        with pytest.raises(ValueError, match="placeholder"):
            account_reply(frame, "preserve", after=True)

    def test_literal_x_password_and_presence_placeholder_share_bytes(self) -> None:
        """A literal x password is stored, logs in and is rejected as expected."""
        frame = reply(self.report("mutation-literal-x"), 12)
        assert fields(frame)[FIELD_PASSWORD] == b"x", "expected the x placeholder"
        assert reply(self.report("login-literal-x"), 1)["error"] == 0, (
            "expected the literal x password to log in"
        )
        assert reply(self.report("reject-literal-x"), 1)["error"] == 1, (
            "expected the literal x password to be rejected by the wrong login"
        )

    def mutate_record(
        self,
        tmp_path: Path,
        label: str,
        operation: cabc.Callable[[bytearray], object],
    ) -> None:
        """Copy the corpus, change the stored record of ``label`` and verify it."""
        target = tmp_path
        for name in [
            "native-seed",
            "native-final",
            "native-cleanup",
            "native-published",
        ]:
            shutil.copytree(BATCH / name, target / name)
        rows = json.loads((target / "native-final/extraction.json").read_text())[
            "records"
        ]
        row = next(
            r
            for r in rows
            if r["path"] == "/Hotline19/Users/m-au26-" + label + "/UserData"
        )
        path = target / "native-final" / (row["key"] + ".data")
        value = bytearray(path.read_bytes())
        operation(value)
        path.write_bytes(value)
        storage(target)

    def test_sentinel_does_not_preserve_all_32_bytes(self, tmp_path: Path) -> None:
        """A sentinel that keeps all 32 password bytes is refused."""

        def retain32(value: bytearray) -> None:
            """Store a 32-byte password in place of the sentinel."""
            value[700:702] = (32).to_bytes(2, "big")
            value[733] = ord("q") ^ 255

        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(tmp_path, "preserve32", retain32)

    def test_network_replacement_is_not_clipped_to_local_setters_31_bytes(
        self, tmp_path: Path
    ) -> None:
        """A network replacement of 32 bytes is not clipped to 31 bytes."""
        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(
                tmp_path,
                "replace32",
                lambda v: v.__setitem__(slice(700, 702), (31).to_bytes(2, "big")),
            )

    def test_attribute65_is_stored_with_length64(self, tmp_path: Path) -> None:
        """An attribute of 65 bytes is refused when the record stores 64."""
        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(
                tmp_path,
                "attribute65",
                lambda v: v.__setitem__(slice(596, 598), (65).to_bytes(2, "big")),
            )

    def test_omitted_password_cannot_preserve_old_stored_value(
        self, tmp_path: Path
    ) -> None:
        """An omitted password cannot keep the old stored value."""
        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(
                tmp_path,
                "absent",
                lambda v: v.__setitem__(slice(700, 702), (15).to_bytes(2, "big")),
            )

    def test_literal_x_is_not_the_nul_preservation_sentinel(
        self, tmp_path: Path
    ) -> None:
        """The literal x password is not read as the NUL preservation sentinel."""
        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(tmp_path, "literal-x", lambda v: v.__setitem__(702, 0))

    def test_cleared_record_does_not_retain_opaque_attribute_bytes(
        self, tmp_path: Path
    ) -> None:
        """A cleared record does not keep the opaque attribute bytes."""
        with pytest.raises(ValueError, match="734-byte account record"):
            self.mutate_record(
                tmp_path, "sparse", lambda v: v.__setitem__(598, ord("o"))
            )
