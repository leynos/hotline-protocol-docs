"""Fault controls for the portable synthetic Classic proxy corpus."""

import hashlib
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_classic_proxy_rehearsal import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

# scripts/tests sits two levels below the repository root that holds evidence/.
SOURCE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01"
)


class ClassicProxyRehearsalTests:
    """Reject each falsified claim, timing, order and proof of the rehearsal."""

    @pytest.fixture(autouse=True)
    def _copy(self, tmp_path: Path) -> None:
        """Copy the corpus into a scratch tree that keeps its repository layout."""
        self.root = (
            tmp_path / "evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01"
        )
        self.root.parent.mkdir(parents=True)
        shutil.copytree(SOURCE, self.root)

    def rewrite_inventory(self) -> None:
        """Rewrite SHA256SUMS so that a changed file still matches its digest."""
        base = self.root.parents[3]
        files = sorted(
            path
            for path in self.root.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        )
        (self.root / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(base)}\n"
                for path in files
            )
        )

    def change_json(
        self, relative: str, mutate: cabc.Callable[[dict[str, typ.Any]], None]
    ) -> None:
        """Change one JSON file of the copy and refresh the inventory.

        Parameters
        ----------
        relative : str
            The file, relative to the corpus.
        mutate : collections.abc.Callable
            Changes the parsed value in place.
        """
        path = self.root / relative
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.rewrite_inventory()

    def test_valid_synthetic_and_zero_contact_corpus(self) -> None:
        """Verify the unchanged corpus."""
        assert verify(self.root)["status"] == "verified-synthetic-and-zero-contact", (
            'verify(self.root)["status"]'
        )

    def test_rejects_incorrect_native_evidence_claim(self) -> None:
        """Refuse a manifest that claims native peer evidence."""
        self.change_json(
            "manifest.json", lambda value: value.update(native_peer_evidence=True)
        )
        with pytest.raises(AssertionError):
            verify(self.root)

    def test_rejects_late_teardown_even_with_stale_valid_flag(self) -> None:
        """Refuse a late relay teardown, though the valid flag is stale."""

        def late(value: dict[str, typ.Any]) -> None:
            """Move the relay teardown three seconds later."""
            value["observation"]["relay_teardown_ns"] += 3_000_000_000

        self.change_json("synthetic/report.json", late)
        with pytest.raises(AssertionError):
            verify(self.root)

    def test_rejects_reordered_handshake(self) -> None:
        """Refuse a report whose first two entries are swapped."""

        def reorder(value: dict[str, typ.Any]) -> None:
            """Swap the first two audited entries."""
            value["entries"][0], value["entries"][1] = (
                value["entries"][1],
                value["entries"][0],
            )

        self.change_json("synthetic/report.json", reorder)
        with pytest.raises(AssertionError):
            verify(self.root)

    def test_rejects_undestroyed_proxy_pid_proof(self) -> None:
        """Refuse a summary that says the proxy PID is not gone."""
        self.change_json(
            "synthetic/summary.json", lambda value: value.update(proxy_pid_gone=False)
        )
        with pytest.raises(AssertionError):
            verify(self.root)
