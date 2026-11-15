"""Prepare direction-specific native folder controls and per-file streams."""

from native_folder_steps import (
    FILES,
    ORDER,
    PARTIAL,
    ROOT,
    STREAM_LENGTH_BYTES,
    WORD_BYTES,
    Cases,
    control,
    control_word,
    descriptor,
    download_start,
    framed_hex,
    length_read,
    path,
    read_descriptor,
    silence_folder,
    upload_start,
    word,
)
from native_plan import Action, close, eof, send
from native_queue_cases import pump
from native_resume_cases import rflt
from native_transfer_cases import file_stream
from native_wire_names import (
    FOLDER_CONTROL_FRESH,
    FOLDER_CONTROL_NEXT,
    FOLDER_CONTROL_RESUME,
)

# verify_native_folders, prepare_native_cases, native_folder_files and
# native_htxf_cases import the names below from this module; the alias,
# agreement, banner, mkdir, move and news cases import path, descriptor, word,
# upload_start or download_start from it. The native folder upload cases and
# native_folder_timing import the shared steps from native_folder_steps.
__all__ = [
    "FILES",
    "ORDER",
    "PARTIAL",
    "ROOT",
    "descriptor",
    "download_start",
    "downloads",
    "path",
    "read_descriptor",
    "skip_all",
    "upload_fresh",
    "upload_start",
    "word",
]

SKIPPED_DESCRIPTORS = 5  # the skip-all case steps over this many items
UNKNOWN_CONTROL_WORD = 0  # a control word that no folder state defines
DELAYED_PUMPS: list[tuple[int, int]] = [(100, 35), (101, 35), (102, 30), (103, 30)]
RESUME_DATA_OFFSET = 3  # the resume offset written for the data fork
RESUME_MACR_OFFSET = 4  # the resume offset written for the resource fork
FRESH_ITEMS: list[tuple[bool, tuple[bytes, ...]]] = [
    (True, (b"empty",)),
    (True, (b"inner",)),
    (False, (b"alpha",)),
    (False, (b"zero",)),
    (False, (b"inner", b"leaf")),
]


def finish_download() -> list[Action]:
    """Plan the end of a folder download: the next-item word and the closes.

    Returns
    -------
    list[dict[str, typing.Any]]
        The control word, end of stream, and the closes of both connections.
    """
    return [control(FOLDER_CONTROL_NEXT), eof("folder"), close("folder"), close("a")]


def upload_fresh() -> Cases:
    """Plan the upload of a fresh folder with directory and file items.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one fresh-upload case.
    """
    total = sum(len(file_stream(*value)) for value in FILES.values())
    steps = upload_start(ROOT, len(FRESH_ITEMS), total)
    for index, (directory, parts) in enumerate(FRESH_ITEMS):
        steps += [send(descriptor(parts, directory).hex(), "folder")]
        if directory:
            steps += [word(FOLDER_CONTROL_NEXT)]
        else:
            body = file_stream(*FILES[parts])
            steps += [
                word(FOLDER_CONTROL_FRESH),
                send(framed_hex(body), "folder"),
            ]
            if index < len(FRESH_ITEMS) - 1:
                steps += [word(FOLDER_CONTROL_NEXT)]
    steps += [eof("folder"), close("folder"), close("a")]
    return {
        "folder-upload-fresh": (
            steps,
            {
                "kind": "folder-upload-fresh",
                "root_hex": ROOT.hex(),
                "declared_items": len(FRESH_ITEMS),
                "declared_bytes": total,
            },
        )
    }


def skip_all() -> Cases:
    """Plan a download that skips every item of the folder.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one skip-all case.
    """
    steps = download_start(ROOT)
    for index in range(SKIPPED_DESCRIPTORS):
        steps += read_descriptor(index)
    steps += finish_download()
    return {
        "folder-download-skip-all": (
            steps,
            {
                "kind": "folder-download-skip-all",
                "root_hex": ROOT.hex(),
                "descriptors": SKIPPED_DESCRIPTORS,
            },
        )
    }


def unknown_control() -> list[Action]:
    """Plan a control word that no folder state defines, then a bounded silence.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send of the word and the ``expect_quiet`` action.
    """
    return [control(UNKNOWN_CONTROL_WORD), silence_folder()]


def delayed_choice() -> list[Action]:
    """Plan the timed pumps that let the server's choice be delayed.

    Returns
    -------
    list[dict[str, typing.Any]]
        The pumps of ``DELAYED_PUMPS``, in order.
    """
    steps: list[Action] = []
    for identifier, seconds in DELAYED_PUMPS:
        steps += pump("a", identifier, seconds)
    return steps


def resumes(variant: str, parts: tuple[bytes, ...]) -> bool:
    """Name whether an item of a download variant is resumed rather than fresh.

    Returns
    -------
    bool
        True for every item of the resume variant, and for the nested file of
        the mixed variant.
    """
    return variant == "resume" or (variant == "mixed" and parts == (b"inner", b"leaf"))


def transfer_choice(variant: str, parts: tuple[bytes, ...]) -> list[Action]:
    """Plan the fresh or resume control word that answers a file item.

    Returns
    -------
    list[dict[str, typing.Any]]
        The fresh word, or the resume word with its length and descriptor.
    """
    if not resumes(variant, parts):
        return [control(FOLDER_CONTROL_FRESH)]
    empty = parts == (b"zero",)
    entries = [
        (b"DATA", 0 if empty else RESUME_DATA_OFFSET),
        (b"MACR", 0 if empty else RESUME_MACR_OFFSET),
    ]
    value = rflt(entries)
    encoded = (
        control_word(FOLDER_CONTROL_RESUME)
        + len(value).to_bytes(WORD_BYTES, "big")
        + value
    )
    return [send(encoded.hex(), "folder")]


def download_entry(
    variant: str, index: int, entry: tuple[bool, tuple[bytes, ...]]
) -> list[Action]:
    """Plan one item of a folder download, with the variant's extra steps.

    Returns
    -------
    list[dict[str, typing.Any]]
        The descriptor check, then for a file the variant's pauses, the control
        word and the stream reads. A directory, or the skipped alpha file of the
        mixed variant, ends after the descriptor check.
    """
    directory, parts = entry
    steps = read_descriptor(index)
    steps[-1]["expect_hex"] = descriptor(parts, directory)[2:].hex()
    if directory:
        return steps
    if variant == "mixed" and parts == (b"alpha",):
        return steps
    if index == 0 and variant == "unknown-control":
        steps += unknown_control()
    if index == 0 and variant == "delayed-choice":
        steps += delayed_choice()
    steps += transfer_choice(variant, parts)
    steps += length_read(f"stream{index}", STREAM_LENGTH_BYTES)
    return steps


def download_variant(variant: str) -> list[Action]:
    """Plan one folder download variant over the whole fixture order.

    Returns
    -------
    list[dict[str, typing.Any]]
        The start, the leading unknown-control probe where the variant has one,
        each item, and the end of the download.
    """
    steps = download_start(ROOT)
    if variant == "unknown-control":
        steps += unknown_control()
    for index, entry in enumerate(ORDER):
        steps += download_entry(variant, index, entry)
    return steps + finish_download()


def downloads() -> Cases:
    """Plan the folder download variants and the empty and directory-only folders.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and expectation of each download case, by name.
    """
    cases: Cases = {}
    for variant in ["full", "resume", "mixed", "unknown-control", "delayed-choice"]:
        cases["folder-download-" + variant] = (
            download_variant(variant),
            {"kind": "folder-download", "variant": variant, "root_hex": ROOT.hex()},
        )
    cases["folder-download-empty"] = (
        download_start(b"mothra-folder-empty", empty=True),
        {"kind": "folder-download-empty"},
    )
    steps = (
        download_start(b"mothra-folder-dirlast")
        + read_descriptor(0)
        + finish_download()
    )
    cases["folder-download-dir-only"] = (steps, {"kind": "folder-download-dir-only"})
    return cases
