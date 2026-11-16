"""Semantic fault controls for the retained D1 console broadcast."""

import hashlib
import json
import os
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from verify_native_console_broadcast import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

SOURCE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-console-broadcast-01"
)


class NativeConsoleBroadcastTests:
    """Semantic fault controls for the retained D1 console broadcast."""

    @pytest.fixture(autouse=True)
    def setUp(self) -> cabc.Iterator[None]:
        """Copy the retained corpus, with hard links, into a temporary state directory.

        Yields
        ------
        None
            Nothing; the copy is ``self.root`` for the length of the test.
        """
        state = SOURCE.parents[3] / "state"
        state.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=state) as temp:
            self.root = Path(temp) / "corpus"
            shutil.copytree(SOURCE, self.root, copy_function=os.link)
            yield

    def replace(self, name: str, raw: bytes) -> None:
        """Replace one corpus file and record its new hash in the manifest.

        Parameters
        ----------
        name : str
            The corpus file to replace.
        raw : bytes
            The new bytes of the file.
        """
        target = self.root / name
        target.unlink()
        target.write_bytes(raw)
        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["files"][name] = hashlib.sha256(raw).hexdigest()
        (self.root / "manifest.json").unlink()
        (self.root / "manifest.json").write_text(json.dumps(manifest))

    def test_original(self) -> None:
        """The retained corpus verifies with its postflight counts."""
        result = verify(self.root)
        assert result["status"] == "verified-finite-native-console-broadcast", (
            "Status differs"
        )
        assert result["postflight"]["files_root"] == 41, "Files root count differs"

    def test_guest_message_byte_changed_after_manifest_rehash(self) -> None:
        """A changed guest message byte is refused after its manifest rehash."""
        name = "guest-after.pcap"
        raw = (self.root / name).read_bytes()
        assert b"D1-console-message" in raw, "Console message text is missing"
        self.replace(name, raw.replace(b"D1-console-message", b"D1-console-messagf", 1))
        with pytest.raises(ValueError, match="Guest/report bytes differ"):
            verify(self.root)

    def test_host_recipient_syn_missing_after_manifest_rehash(self) -> None:
        """A missing host SYN of the refused peer is refused after rehashing."""
        name = "host.pcap"
        raw = (self.root / name).read_bytes()
        at = 24
        kept = bytearray(raw[:24])
        removed = 0
        while at < len(raw):
            size = int.from_bytes(raw[at + 8 : at + 12], "little")
            record = raw[at : at + 16 + size]
            frame = record[16:]
            # The refused peer's one SYN, 127.0.0.1:53796 -> 15500.
            is_peer_syn = frame[12:14] == b"\x08\x00" and frame[34:38] == bytes.fromhex(
                "d2243c8c"
            )
            if is_peer_syn and frame[47] == 2:
                removed += 1
            else:
                kept.extend(record)
            at += 16 + size
        assert removed == 1, "Refused peer SYN count differs"
        self.replace(name, bytes(kept))
        with pytest.raises(ValueError, match="Host missing-SYN scope differs"):
            verify(self.root)

    def test_operator_two_sends_rejected_after_manifest_rehash(self) -> None:
        """Two console sends are refused after the operator record is rehashed."""
        name = "operator-actions.json"
        actions = json.loads((self.root / name).read_text())
        actions["result"] = "Two console sends"
        self.replace(name, json.dumps(actions).encode())
        with pytest.raises(ValueError, match="Operator scope differs"):
            verify(self.root)
