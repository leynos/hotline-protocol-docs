"""Fault controls for the retained Classic account-constructor proof."""

import copy
import typing as typ

import pytest

# The unittest form imported this as scripts.verify_classic_account_constructors.
from verify_classic_account_constructors import ROOT, load_evidence, verify

SOURCE = "evidence/hotline-server-1.9/queries/D-10015500.c"
BUILDER = "FUN_100b05d0"


@pytest.fixture(scope="module")
def original() -> dict[str, typ.Any]:
    """Load the retained reports once for the module.

    Returns
    -------
    dict[str, typing.Any]
        The parsed reports.
    """
    return load_evidence()


@pytest.fixture(scope="module")
def server() -> str:
    """Read the retained server decompilation once for the module.

    Returns
    -------
    str
        The source text.
    """
    return (ROOT / SOURCE).read_text()


class ClassicAccountConstructorsTest:
    """Reject each altered constructor, field list, branch and identity."""

    @pytest.fixture(autouse=True)
    def _load(self, original: dict[str, typ.Any], server: str) -> None:
        """Give each test its own copy of the reports and the shared server source."""
        self.original = original
        self.server = server
        self.bundle = copy.deepcopy(original)

    def query(self, batch: str, address: str) -> dict[str, typ.Any]:
        """Find the decompilation query of one function in the bundle.

        Returns
        -------
        dict[str, typing.Any]
            The query record.
        """
        if batch == "b37-followup":
            queries = self.bundle[batch]["queries"]
        else:
            queries = [q for run in self.bundle[batch]["runs"] for q in run["queries"]]
        return next(
            q
            for q in queries
            if q["tool"] == "decompile_function_by_address"
            and q["arguments"]["address"] == address
        )

    def test_retained_evidence_passes(self) -> None:
        """Verify the unchanged reports."""
        status = verify(self.bundle, self.server)["status"]
        assert status == "verified-bounded-constructor-trace", (
            'verify(self.bundle, self.server)["status"]'
        )

    def test_wrong_direct_field_rejected_for_both_constructors(self) -> None:
        """Refuse a changed direct field in each of the two constructors."""
        for batch, address, operation in (
            ("b37-followup", "1000c210", "350"),
            ("b38-report", "1000c800", "353"),
        ):
            bad = copy.deepcopy(self.original)
            self.bundle = bad
            query = self.query(batch, address)
            source = query["result"]["structuredContent"]["code"]
            query["result"]["structuredContent"]["code"] = source.replace(
                f"{BUILDER}(param_1[2],0x6e,", f"{BUILDER}(param_1[2],0x6f,", 1
            )
            with pytest.raises(ValueError, match=f"{operation} direct field list"):
                verify(bad, self.server)

    def test_wrong_nested_field_and_conditional_rejected(self) -> None:
        """Refuse a changed nested field, then a removed old-login condition."""
        query = self.query("b39-report", "1005b5b0")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            f"{BUILDER}(local_114,0x6e,", f"{BUILDER}(local_114,0x6f,", 1
        )
        with pytest.raises(ValueError, match="349 nested field list"):
            verify(self.bundle, self.server)
        query["result"]["structuredContent"]["code"] = source.replace(
            "cVar6 = FUN_1005e650(local_118);", "cVar6 = 1;", 1
        )
        with pytest.raises(ValueError, match="conditional old-login"):
            verify(self.bundle, self.server)

    def test_wrong_old_login_only_list_rejected(self) -> None:
        """Refuse a changed field in the old-login-only list."""
        query = self.query("b39-report", "1005ce30")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            f"{BUILDER}(uVar3,0x65,", f"{BUILDER}(uVar3,0x69,", 1
        )
        with pytest.raises(ValueError, match="old-login-only list"):
            verify(self.bundle, self.server)

    def test_changed_counted_tlv_builder_rejected(self) -> None:
        """Refuse a TLV builder that no longer counts its value."""
        query = self.query("b39-report", "100b05d0")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "puVar2[2] = (short)param_4", "puVar2[2] = 0", 1
        )
        with pytest.raises(ValueError, match="counted BE16 TLV append"):
            verify(self.bundle, self.server)

    def test_error_code_cannot_be_relabelled_as_field(self) -> None:
        """Refuse an error-path call relabelled as a field append."""
        query = next(
            q
            for q in self.bundle["b37-report"]["records"]
            if q["label"] == "field111-a-decompile"
        )
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "FUN_1007d7e0(8,0x6f)", f"{BUILDER}(p,0x6f,v,n)", 1
        )
        with pytest.raises(ValueError, match="not the retained error path"):
            verify(self.bundle, self.server)

    def test_identity_and_server_deletion_branch_required(self) -> None:
        """Refuse a changed program identity, then a changed deletion branch."""
        run = self.bundle["b38-report"]["runs"][0]
        run["queries"][-1]["result"]["structuredContent"]["sha256"] = "0" * 64
        with pytest.raises(ValueError, match="program identity changed"):
            verify(self.bundle, self.server)
        self.bundle = copy.deepcopy(self.original)
        altered = self.server.replace(
            "if ((local_3e0 == 0) && (local_358 == 0))", "if (false)", 1
        )
        with pytest.raises(ValueError, match="server 349 deletion branch"):
            verify(self.bundle, altered)
