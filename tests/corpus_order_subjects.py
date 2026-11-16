"""Describe the subjects of the corpus-order tests of the native verifiers.

Each verifier here reads one retained corpus whose files are hashed against the
manifest and ``SHA256SUMS``. A subject is the corpus's JSON files and a check that
runs the verifier on a faulted copy, with the digest of each changed file
refreshed. The tests replay recorded faults against these subjects; the recording
tool builds the same subjects while the pristine scripts are on ``sys.path``.
"""

import importlib
import typing as typ
from pathlib import Path

from corpus_refresh import Layout, refreshed_subject

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Subject = tuple[dict[str, typ.Any], cabc.Callable[[dict[str, typ.Any]], object]]

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence/gap-remediation"
# subject name -> (corpus below evidence/gap-remediation, verifier module)
SPECS: dict[str, tuple[str, str]] = {
    "liveness-corpus": ("2026-11-14/native-liveness-01", "verify_native_liveness"),
    "path-fields-corpus": (
        "2026-11-14/native-path-fields-01",
        "verify_native_path_fields",
    ),
    "roster-overlap": (
        "2026-11-14/native-roster-overlap-01",
        "verify_native_roster_overlap",
    ),
    "rate304-partial": (
        "2026-11-14/native-rate304-first-pair-01",
        "verify_native_rate304_partial",
    ),
    "rate304-sequence": (
        "2026-11-14/native-rate304-sequence-01",
        "verify_native_rate304_sequence",
    ),
    "console-broadcast": (
        "2026-11-13/native-console-broadcast-01",
        "verify_native_console_broadcast",
    ),
    "send-path": (
        "2026-11-13/native-download-send-path-01",
        "verify_native_download_send_path",
    ),
    "ui-focus": ("2026-11-14/native-ui-focus-01", "verify_native_ui_focus"),
    "ban-one": ("2026-11-13/native-ban-one-01", "verify_native_ban_one"),
    "ban-reload": ("2026-11-14/native-ban-reload-01", "verify_native_ban_reload"),
    "configured-ban": (
        "2026-11-14/native-configured-ban-01",
        "verify_native_configured_ban",
    ),
    "ban-expiry-first": (
        "2026-11-14/native-ban-expiry-first-01",
        "verify_native_ban_expiry_first",
    ),
    "ban-expiry-later": (
        "2026-11-14/native-ban-expiry-later-01",
        "verify_native_ban_expiry_later",
    ),
}
FIRST_EXPIRY = (
    EVIDENCE / "2026-11-14/native-ban-expiry-first-01"
)  # the later verifier's witness


# subject name -> how its corpus lists and holds its files, where that is not plain
LAYOUTS: dict[str, Layout] = {
    "path-fields-corpus": Layout(
        sums_prefix="evidence/gap-remediation/2026-11-14/native-path-fields-01/",
        manifest_line=True,
        copy_files=True,
    ),
    "rate304-sequence": Layout(
        sums_prefix="evidence/gap-remediation/2026-11-14/native-rate304-sequence-01/"
    ),
    "ban-one": Layout(in_repository=True),
    "ban-reload": Layout(in_repository=True),
}


def corpus_subject(name: str, layout: Layout | None = None) -> Subject:
    """Build the subject of one corpus verifier.

    Parameters
    ----------
    name : str
        A key of ``SPECS``.
    layout : Layout | None
        How the corpus lists and holds its files; the plain layout by default.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The corpus's JSON files and the check that runs the verifier on a copy.
    """
    corpus, module = SPECS[name]
    verify = importlib.import_module(module).verify
    if name == "ban-expiry-later":
        later = verify

        def verify(directory: Path) -> object:
            """Verify the later corpus against the retained first corpus.

            Returns
            -------
            object
                What the later verifier returned.
            """
            return later(directory, FIRST_EXPIRY)

    return refreshed_subject(
        EVIDENCE / corpus, verify, layout or LAYOUTS.get(name, Layout())
    )
