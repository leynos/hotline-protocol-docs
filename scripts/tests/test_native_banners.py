"""Reject banner evidence that confuses raw payload, advertisement and completion."""

import copy
import json
import typing as typ
from pathlib import Path

import pytest
from verify_native_banners import check_case, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-banner-01"
)


def load_fixture(
    name: str,
) -> tuple[dict[str, typ.Any], dict[str, typ.Any], dict[str, typ.Any]]:
    """Load the report, plan and packet views of one retained banner case.

    Parameters
    ----------
    name : str
        The name of the case directory under ``transcripts``.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any]]
        The report, the plan and the packet views.
    """
    directory = BATCH / "transcripts" / name
    return (
        json.loads((directory / "report.json").read_text()),
        json.loads((directory / "plan.json").read_text()),
        {"banner": {"guest_server_initiated_close": False}},
    )


class BannerTests:
    """Require banner evidence to keep payload, advertisement and completion apart."""

    def test_native_banner_corpus(self) -> None:
        """The retained corpus verifies, with its changed buffer intact."""
        result = verify(BATCH)
        assert len(result["cases"]) == 24, "expected the 24 retained banner cases"
        changed = next(c for c in result["cases"] if c["case"] == "changed-buffer")
        assert (changed["advertised_bytes"], changed["delivered_bytes"]) == (
            43,
            58,
        ), "expected the changed buffer byte counts"

    def test_filp_wrapping_is_not_raw_banner_delivery(self) -> None:
        """A FILP-wrapped banner is refused as raw banner bytes."""
        report, plan, packets = load_fixture("local-a-raw")
        report["streams"]["banner"]["received_hex"] = (
            b"FILP".hex() + report["streams"]["banner"]["received_hex"]
        )
        with pytest.raises(ValueError, match="raw banner bytes differ"):
            check_case("local-a-raw", report, plan, packets)

    def test_changed_buffer_must_not_be_pinned_to_advertised_size(self) -> None:
        """A changed buffer truncated to the advertised size is refused."""
        report, plan, packets = load_fixture("changed-buffer")
        report["streams"]["banner"]["received_hex"] = report["streams"]["banner"][
            "received_hex"
        ][:86]
        with pytest.raises(ValueError, match="raw banner bytes differ"):
            check_case("changed-buffer", report, plan, packets)

    def test_early_completion_does_not_inherit_delayed_banner(self) -> None:
        """A delayed banner's metadata is refused after an early completion."""
        report, plan, packets = load_fixture("local-a-early")
        delayed, _, _ = load_fixture("local-a-metadata-190")
        report["frames"].extend(
            copy.deepcopy(f) for f in delayed["frames"] if f["type"] == 122
        )
        with pytest.raises(ValueError, match="unexpected122"):
            check_case("local-a-early", report, plan, packets)

    def test_wrong_selector_requires_the_original_reference(self) -> None:
        """A changed selector in the negative HTXF control is refused."""
        report, plan, packets = load_fixture("local-a-selector1")
        sent = report["streams"]["banner"]["sent_hex"]
        report["streams"]["banner"]["sent_hex"] = sent[:8] + "ffffffff" + sent[16:]
        packets["banner"]["guest_server_initiated_close"] = True
        with pytest.raises(ValueError, match="negative HTXF control differs"):
            check_case("local-a-selector1", report, plan, packets)

    def test_missing_banner_silence_is_not_a_successful_empty_ack(self) -> None:
        """A reply to a banner-less request is refused as an empty acknowledgement."""
        report, plan, packets = load_fixture("none-request212")
        report["frames"].append({"type": 0, "is_reply": 1, "id": 10})
        with pytest.raises(ValueError, match="unexpected212 reply"):
            check_case("none-request212", report, plan, packets)
