#!/usr/bin/env python3
"""Prepare bounded native protocol observation plans."""

import argparse
import json
from pathlib import Path

from native_agreement_cases import PHASES as AGREEMENT_PHASES
from native_agreement_cases import cleanup as agreement_cleanup
from native_agreement_cases import phase as agreement_phase
from native_agreement_cases import preflight as agreement_preflight
from native_agreement_cases import restore_stage as agreement_restore_stage
from native_agreement_cases import seed as agreement_seed
from native_agreement_cases import stages as agreement_stages
from native_auth_cases import cleanup as auth_cleanup
from native_auth_cases import guest_create as auth_guest_create
from native_auth_cases import lookup as auth_lookup
from native_auth_cases import reauthentication as auth_reauthentication
from native_auth_cases import seed as auth_seed
from native_auth_cases import states as auth_states
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
from native_correlation_cases import correlation
from native_folder_cases import downloads as folder_downloads
from native_folder_cases import skip_all, upload_fresh
from native_folder_timing import uploads as folder_timed_uploads
from native_folder_upload_cases import (
    catalogue_flush,
    empty_uploads,
    partial_seed,
    resumed_uploads,
)
from native_framing_cases import framing
from native_htxf_cases import htxf
from native_login_extras_cases import NAMES as LOGIN_EXTRA_NAMES
from native_login_extras_cases import configured as login_extras_configured
from native_login_extras_cases import downloads as login_extras_downloads
from native_login_extras_cases import lifetime as login_extras_lifetime
from native_queue_cases import queues, timer
from native_resume_cases import downloads as resume_downloads
from native_resume_cases import upload_continuations, upload_probes
from native_transfer_cases import downloads, transfers
from protocol_capture import ORACLE_SHA256, validate_plan


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "suite",
        choices=[
            "login-extras-lifetime",
            "login-extras-downloads",
            *["login-extras-" + name for name in LOGIN_EXTRA_NAMES],
            "agreement-preflight",
            "agreement-seed",
            "agreement-stages",
            "agreement-restore-stage",
            "agreement-cleanup",
            *["agreement-" + name for name in AGREEMENT_PHASES],
            "auth-seed",
            "auth-lookup",
            "auth-missing-guest",
            "auth-guest-create",
            "auth-states",
            "auth-reauthentication",
            "auth-cleanup",
            "correlation",
            "htxf",
            "framing",
            "banner-none",
            "banner-format-seed",
            "banner-recovery",
            "banner-recovery-early",
            "banner-empty",
            "banner-jpeg",
            "banner-bmp",
            "banner-pict",
            "banner-fallback",
            "banner-zero-type",
            "banner-suffix-before-finder",
            "banner-text-conversion",
            "banner-missing",
            "banner-url",
            "banner-image",
            "banner-changed",
            "banner-seed",
            "banner-absent-restored",
            "banner-expired",
            "transfers",
            "downloads",
            "resume-downloads",
            "resume-upload-probes",
            "resume-upload-continuations",
            "queues",
            "queue-timer",
            "cleanup-seed",
            "cleanup-downloads",
            "cleanup-upload",
            "folder-upload-fresh",
            "folder-skip-all",
            "folder-downloads",
            "folder-empty-uploads",
            "folder-partial-seed",
            "folder-resumed-uploads",
            "folder-flush",
            "folder-timed-uploads",
        ],
    )
    parser.add_argument("--runtime-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-agreement", type=Path)
    args = parser.parse_args()
    if args.suite == "agreement-restore-stage" and args.original_agreement is None:
        parser.error("agreement-restore-stage requires --original-agreement")
    cases = {
        "login-extras-lifetime": login_extras_lifetime,
        "login-extras-downloads": login_extras_downloads,
        **{
            "login-extras-" + name: lambda name=name: login_extras_configured(name)
            for name in LOGIN_EXTRA_NAMES
        },
        "agreement-preflight": agreement_preflight,
        "agreement-seed": agreement_seed,
        "agreement-stages": agreement_stages,
        "agreement-restore-stage": lambda: agreement_restore_stage(
            args.original_agreement.read_bytes()
        ),
        "agreement-cleanup": agreement_cleanup,
        **{
            "agreement-" + name: lambda name=name: agreement_phase(name)
            for name in AGREEMENT_PHASES
        },
        "auth-seed": auth_seed,
        "auth-lookup": auth_lookup,
        "auth-missing-guest": lambda: auth_lookup(missing_guest=True),
        "auth-guest-create": auth_guest_create,
        "auth-states": auth_states,
        "auth-reauthentication": auth_reauthentication,
        "auth-cleanup": auth_cleanup,
        "correlation": correlation,
        "htxf": htxf,
        "framing": framing,
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
    }[args.suite]()
    args.output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in cases.items():
        plan = {
            "schema_version": 1,
            "profile": "native-mac-oracle",
            "operator": "native fixture operator",
            "oracle_sha256": ORACLE_SHA256,
            "environment": json.loads(args.runtime_record.read_text()),
            "gap_ids": [
                "GAP-011",
                "GAP-012",
                "GAP-013",
                "GAP-014",
                "GAP-015",
                "GAP-017",
            ]
            if args.suite == "framing"
            else ["GAP-026", "GAP-018", "GAP-019", "GAP-084"]
            if args.suite.startswith("login-extras-")
            else ["GAP-025", "GAP-027", "GAP-019", "GAP-084"]
            if args.suite.startswith("agreement-")
            else ["GAP-023", "GAP-025", "GAP-026", "GAP-027", "GAP-084"]
            if args.suite.startswith("auth-")
            else ["GAP-004", "GAP-012", "GAP-013", "GAP-084"]
            if args.suite == "correlation"
            else ["GAP-055", "GAP-084"]
            if args.suite == "htxf"
            else ["GAP-055", "GAP-063", "GAP-084"]
            if args.suite.startswith("banner-")
            else ["GAP-058", "GAP-064"]
            if args.suite.startswith("resume-")
            else ["GAP-059", "GAP-060", "GAP-064"]
            if args.suite.startswith("folder-")
            else ["GAP-062", "GAP-064"]
            if args.suite.startswith("cleanup-")
            else ["GAP-057", "GAP-061", "GAP-062"]
            if args.suite in {"queues", "queue-timer"}
            else ["GAP-009", "GAP-055", "GAP-056", "GAP-064"],
            "endpoints": {
                "control": {"host": "127.0.0.1", "port": 15500},
                "data": {"host": "127.0.0.1", "port": 15501},
            },
            "expectation": expectation,
            "steps": steps,
        }
        validate_plan(plan)
        (args.output / (name + ".json")).write_text(json.dumps(plan, indent=2) + "\n")
    print(f"Prepared {len(cases)} {args.suite} plans")


if __name__ == "__main__":
    main()
