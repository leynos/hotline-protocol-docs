"""Keep failed native catalogue/fork probes distinct from successful reads."""

import subprocess  # ruff: ignore[suspicious-subprocess-import]  # the test builds synthetic process results and runs nothing
import typing as typ
from unittest import mock

import pytest
from snapshot_native_hfs import snapshot

if typ.TYPE_CHECKING:
    from pathlib import Path


class SnapshotTests:
    """Exercise the bounded snapshot of native catalogue and fork lookups."""

    @pytest.fixture
    def image(self, tmp_path: Path) -> Path:
        """Provide a synthetic disk image.

        Returns
        -------
        pathlib.Path
            The synthetic image, which is not native evidence.
        """
        path = tmp_path / "synthetic-image"
        path.write_bytes(b"synthetic tool test, not native evidence")
        return path

    @pytest.fixture
    def tools(self, tmp_path: Path) -> Path:
        """Provide a directory with synthetic ``istat`` and ``icat`` identities.

        Returns
        -------
        pathlib.Path
            The directory that holds the two synthetic executables.
        """
        path = tmp_path / "tools"
        path.mkdir()
        for name in ["istat", "icat"]:
            (path / name).write_bytes(b"synthetic executable identity")
        return path

    def test_failed_fork_and_catalogue_reads_keep_nonzero_status(
        self, tmp_path: Path, image: Path, tools: Path
    ) -> None:
        """Failed fork and catalogue reads keep their nonzero exit status."""
        stat = (
            b"File Path: /Hotline19/Files/example\n"
            b"Type:\tFile\nResource fork size:\t0\n"
        )
        results = [
            subprocess.CompletedProcess([], 0, stat, b""),
            subprocess.CompletedProcess([], 0, b"abc", b""),
            subprocess.CompletedProcess([], 1, b"", b"Attribute 4353-1 not found"),
            subprocess.CompletedProcess([], 1, b"", b"catalogue lookup failed"),
        ]
        with mock.patch("snapshot_native_hfs.subprocess.run", side_effect=results):
            result = snapshot(
                image,
                tools,
                100,
                101,
                ["/Hotline19/Files/example"],
                tmp_path / "output",
            )
        assert len(result["records"]) == 1, "the retained record count differs"
        assert result["records"][0]["attributes"]["rsrc"]["exit_code"] == 1, (
            "the failed resource fork status is lost"
        )
        assert result["probes"][-1]["exit_code"] == 1, "the failed probe is lost"
        assert "absence" in result["method"], "the method omits its absence limit"

    def test_probe_bound_and_existing_output_are_checked_before_tool_execution(
        self, tmp_path: Path, image: Path, tools: Path
    ) -> None:
        """The probe bound and an existing output are refused before any tool runs."""
        with mock.patch("snapshot_native_hfs.subprocess.run") as run:
            with pytest.raises(ValueError, match="at most4096"):
                snapshot(
                    image,
                    tools,
                    2,
                    4098,
                    ["/example"],
                    tmp_path / "too-many",
                )
            assert not (tmp_path / "too-many").exists(), "the output was created"
            output = tmp_path / "existing"
            output.mkdir()
            marker = output / "keep.txt"
            marker.write_text("retain existing evidence")
            with pytest.raises(FileExistsError):
                snapshot(image, tools, 2, 3, ["/example"], output)
            assert marker.read_text() == "retain existing evidence", (
                "the existing evidence changed"
            )
            run.assert_not_called()
