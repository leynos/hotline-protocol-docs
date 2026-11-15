"""Pin the order of the banner format verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys.
"""

import json
import typing as typ

import pytest
import verify_native_banner_formats
from native_banner_formats import FORMATS
from verify_native_banner_formats import CASES, verify

if typ.TYPE_CHECKING:
    from pathlib import Path


class BannerFormatCheckOrderTests:
    """Keep the inventory checks ahead of the read of the capture driver."""

    @staticmethod
    def corpus(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cases: list[str]
    ) -> Path:
        """Build a corpus directory with a manifest and no capture driver.

        Returns
        -------
        pathlib.Path
            The directory.
        """
        monkeypatch.setattr(
            verify_native_banner_formats, "read_packets", lambda _path: []
        )
        (tmp_path / "manifest.json").write_text(json.dumps({"cases": cases}))
        (tmp_path / "transcripts").mkdir()
        return tmp_path

    def test_manifest_inventory_is_refused_before_the_driver_is_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A wrong case list is reported although the driver file is missing."""
        directory = self.corpus(tmp_path, monkeypatch, [])
        with pytest.raises(ValueError, match="corpus inventory differs"):
            verify(directory)

    def test_transcript_inventory_is_refused_before_the_driver_is_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A wrong transcript list is reported although the driver file is missing."""
        cases = ["format-" + name for name in FORMATS] + sorted(CASES)
        directory = self.corpus(tmp_path, monkeypatch, cases)
        with pytest.raises(ValueError, match="Unexpected final format transcript"):
            verify(directory)
