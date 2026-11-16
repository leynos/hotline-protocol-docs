"""Planner entries for the file-related suites, from banners to folders."""

import typing as typ

from native_banner_cases import URL
from native_banner_cases import absent_restored as banner_absent_restored
from native_banner_cases import changed as banner_changed
from native_banner_cases import expired as banner_expired
from native_banner_cases import image as banner_image
from native_banner_cases import metadata as banner_metadata
from native_banner_cases import seed as banner_seed
from native_banner_formats import format_case, recovery, seed_formats
from native_cleanup_cases import downloads as cleanup_downloads
from native_cleanup_cases import seed as cleanup_seed
from native_cleanup_cases import upload_cleanup
from native_folder_cases import downloads as folder_downloads
from native_folder_cases import skip_all, upload_fresh
from native_folder_timing import uploads as folder_timed_uploads
from native_folder_upload_cases import (
    catalogue_flush,
    empty_uploads,
    partial_seed,
    resumed_uploads,
)
from native_queue_cases import queues, timer
from native_resume_cases import downloads as resume_downloads
from native_resume_cases import upload_continuations, upload_probes
from native_transfer_cases import downloads, transfers

if typ.TYPE_CHECKING:
    from prepare_native_cases_inputs import Entry


def entries() -> dict[str, Entry]:
    """Return the entry of each file suite, keyed by suite name.

    No file suite reads a command-line value, so none is taken.

    Returns
    -------
    dict[str, Entry]
        One entry per file suite, each a function of no arguments.
    """
    return {
        "banner-none": lambda: banner_metadata("none", None, None),
        "banner-format-seed": seed_formats,
        "banner-recovery": recovery,
        "banner-recovery-early": lambda: recovery(early=True),
        **{
            "banner-" + name: lambda name=name: format_case(name)
            for name in [
                "empty",
                "jpeg",
                "bmp",
                "pict",
                "fallback",
                "zero-type",
                "suffix-before-finder",
                "text-conversion",
            ]
        },
        "banner-missing": lambda: banner_metadata("missing", None, None),
        "banner-url": lambda: banner_metadata("url", b"URL ", URL),
        "banner-image": banner_image,
        "banner-changed": banner_changed,
        "banner-seed": banner_seed,
        "banner-absent-restored": banner_absent_restored,
        "banner-expired": banner_expired,
        "transfers": transfers,
        "downloads": downloads,
        "resume-downloads": resume_downloads,
        "resume-upload-probes": upload_probes,
        "resume-upload-continuations": upload_continuations,
        "queues": queues,
        "queue-timer": timer,
        "cleanup-seed": cleanup_seed,
        "cleanup-downloads": cleanup_downloads,
        "cleanup-upload": upload_cleanup,
        "folder-upload-fresh": upload_fresh,
        "folder-skip-all": skip_all,
        "folder-downloads": folder_downloads,
        "folder-empty-uploads": empty_uploads,
        "folder-partial-seed": partial_seed,
        "folder-resumed-uploads": resumed_uploads,
        "folder-flush": catalogue_flush,
        "folder-timed-uploads": folder_timed_uploads,
    }
