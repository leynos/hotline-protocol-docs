"""Reject login-extra omission, decoding and refresh overclaims."""

import copy
import json
import typing as typ
from pathlib import Path

import pytest
from native_login_extras_cases import NAMES, configured
from native_wire_names import FIELD_SERVER_NAME, TYPE_BANNER_METADATA
from verify_native_login_extras import (
    check_configured,
    check_lifetime,
    login_ack,
    preferences,
    verify,
)

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-login-extras-01"
)
CASES = 34  # the configured login-extra cases in the retained corpus
ACCEPT_REQUEST_ID = 2  # the identifier of the acceptance request


class LoginExtraTests:
    """Reject login-extra omission, decoding and refresh overclaims."""

    def report(self, name: str) -> dict[str, typ.Any]:
        """Load the report of one retained login-extra capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / "captures" / name / "report.json").read_text())

    def agreement(self) -> bytes:
        """Load the retained original agreement, with its line endings as sent.

        Returns
        -------
        bytes
            The agreement bytes with each CRLF reduced to CR.
        """
        return (BATCH / "original-agreement.data").read_bytes().replace(b"\r\n", b"\r")

    def test_full_retained_login_extra_corpus(self) -> None:
        """The retained corpus verifies with every configured case."""
        assert verify(BATCH)["cases"] == CASES, "the retained case count differs"

    def test_absent_client_version_does_not_omit_configured_server_name(self) -> None:
        """An absent client version still reports the configured server name."""
        frame = self.report("name-a-absent-early")["frames"][0]
        frame["fields"] = [f for f in frame["fields"] if f["id"] != FIELD_SERVER_NAME]
        with pytest.raises(ValueError, match="login-extra values differ"):
            login_ack(frame, NAMES["name-a"])

    def test_native_high_byte_is_not_reencoded_as_utf8(self) -> None:
        """A high byte of the native name is not re-encoded as UTF-8."""
        frame = self.report("macroman-190-early")["frames"][0]
        next(f for f in frame["fields"] if f["id"] == FIELD_SERVER_NAME)["hex"] = (
            "mothra-ö".encode().hex()
        )
        with pytest.raises(ValueError, match="login-extra values differ"):
            login_ack(frame, NAMES["macroman"])

    def test_old_client_version_does_not_receive_configured_banner(self) -> None:
        """A client below the banner version does not receive a banner notice."""
        report = self.report("name-a-150-delayed")
        notice = next(
            f
            for f in self.report("name-a-190-delayed")["frames"]
            if f["type"] == TYPE_BANNER_METADATA
        )
        report["frames"].insert(-1, copy.deepcopy(notice))
        name = "name-a-150-delayed"
        with pytest.raises(ValueError, match="login/banner sequence differs"):
            check_configured(report, configured("name-a")[name][1], self.agreement())

    def test_acceptance_does_not_refresh_the_old_login_name(self) -> None:
        """Accepting the agreement does not refresh an existing session's name."""
        report = self.report("name-change-with-existing-sessions")
        ack = next(
            f
            for f in report["frames"]
            if f["connection"] == "waiting"
            and f["is_reply"]
            and f["id"] == ACCEPT_REQUEST_ID
        )
        ack["fields"] = [{"id": FIELD_SERVER_NAME, "hex": NAMES["name-b"].hex()}]
        with pytest.raises(ValueError, match="login extras were refreshed"):
            check_lifetime(report, self.agreement())

    def test_truncated_live_preference_snapshot_is_not_accepted(self) -> None:
        """A truncated live preference snapshot is refused."""
        with pytest.raises(ValueError, match="Truncated native Pascal content"):
            preferences(BATCH / "native-url")

    def test_required_configurations_cannot_be_removed_from_the_manifest(
        self, tmp_path: Path
    ) -> None:
        """A manifest that omits a required configuration is refused."""
        manifest = json.loads((BATCH / "manifest.json").read_text())
        del manifest["configurations"]["none"]
        (tmp_path / "manifest.json").write_text(json.dumps(manifest))
        with pytest.raises(ValueError, match="configuration inventory differs"):
            verify(tmp_path)
