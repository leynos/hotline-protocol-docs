#!/usr/bin/env python3
"""Prepare bounded native protocol observation plans."""

import argparse
import json
from pathlib import Path

import native_news_boundary_cases as news_boundary
from native_agreement_cases import PHASES as AGREEMENT_PHASES
from native_agreement_cases import cleanup as agreement_cleanup
from native_agreement_cases import phase as agreement_phase
from native_agreement_cases import preflight as agreement_preflight
from native_agreement_cases import restore_stage as agreement_restore_stage
from native_agreement_cases import seed as agreement_seed
from native_agreement_cases import stages as agreement_stages
from native_alias_cases import cleanup as alias_cleanup
from native_alias_cases import create as alias_create
from native_alias_cases import damage as alias_damage
from native_alias_cases import downloads as alias_downloads
from native_alias_cases import information as alias_information
from native_alias_cases import seed as alias_seed
from native_alias_cases import supplementary as alias_supplementary
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
from native_metadata_cases import account_cleanup as metadata_account_cleanup
from native_metadata_cases import boundaries as metadata_boundaries
from native_metadata_cases import cleanup as metadata_cleanup
from native_metadata_cases import combined_empty as metadata_combined_empty
from native_metadata_cases import finalization as metadata_final
from native_metadata_cases import mutations as metadata_mutations
from native_metadata_cases import preflight as metadata_preflight
from native_metadata_cases import seed as metadata_seed
from native_mkdir_cases import cleanup as mkdir_cleanup
from native_mkdir_cases import creation as mkdir_creation
from native_mkdir_cases import empty_root as mkdir_empty_root
from native_mkdir_cases import finalization as mkdir_final
from native_mkdir_cases import seed as mkdir_seed
from native_move_cases import cleanup as move_cleanup
from native_move_cases import deletions as move_deletions
from native_move_cases import finalization as move_final
from native_move_cases import moves as move_moves
from native_move_cases import preflight as move_preflight
from native_move_cases import seed as move_seed
from native_news_cases import bodies as news_bodies
from native_news_cases import cleanup as news_cleanup
from native_news_cases import files_preflight as news_files_preflight
from native_news_cases import finalization as news_final
from native_news_cases import listings as news_listings
from native_news_cases import posts as news_posts
from native_news_cases import preflight as news_preflight
from native_news_cases import publish_cleanup as news_publish_cleanup
from native_news_cases import remove_publisher as news_remove_publisher
from native_news_cases import seed as news_seed
from native_news_cases import structures as news_structures
from native_news_cases import thread_children as news_thread_children
from native_news_cases import thread_grandchild as news_thread_grandchild
from native_news_delete_cases import cleanup as article_delete_cleanup
from native_news_delete_cases import deletions as article_delete_cases
from native_news_delete_cases import finalization as article_delete_final
from native_news_delete_cases import inspect_seed as article_delete_inspect
from native_news_delete_cases import preflight as article_delete_preflight
from native_news_delete_cases import publish_cleanup as article_delete_publish
from native_news_delete_cases import remove_publisher as article_delete_remove
from native_news_delete_cases import resume_category as article_delete_resume
from native_news_delete_cases import seed as article_delete_seed
from native_news_delete_cases import seed_categories as article_delete_categories
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
            "article-delete-preflight",
            "news-boundary-preflight",
            "news-boundary-seed",
            "news-boundary-append",
            "news-boundary-observe",
            "news-boundary-final",
            "news-boundary-cleanup",
            "news-boundary-publish",
            "news-boundary-remove",
            "article-delete-inspect",
            "article-delete-resume",
            "article-delete-categories",
            "article-delete-seed",
            "article-delete-cases",
            "article-delete-final",
            "article-delete-cleanup",
            "article-delete-publish",
            "article-delete-remove",
            "news-preflight",
            "news-publish-cleanup",
            "news-remove-publisher",
            "news-files-preflight",
            "news-bodies",
            "news-thread-children",
            "news-thread-grandchild",
            "news-posts",
            "news-seed",
            "news-listings",
            "news-structures",
            "news-final",
            "news-cleanup",
            "move-preflight",
            "move-seed",
            "move-moves",
            "move-deletions",
            "move-final",
            "move-cleanup",
            "metadata-preflight",
            "metadata-combined-empty",
            "metadata-account-cleanup",
            "metadata-boundaries",
            "metadata-final",
            "metadata-seed",
            "metadata-mutations",
            "metadata-cleanup",
            "alias-cleanup",
            "alias-supplementary",
            "alias-damage",
            "alias-seed",
            "alias-create",
            "alias-info",
            "alias-download",
            "mkdir-root-empty",
            "mkdir-final",
            "mkdir-cleanup",
            "mkdir-seed",
            "mkdir-create",
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
    parser.add_argument("--article-parent", type=int, default=0)
    parser.add_argument("--case-name")
    parser.add_argument("--completed-nodes", type=int, default=0)
    parser.add_argument("--category-exists", action="store_true")
    parser.add_argument("--first-child", type=int, default=1)
    parser.add_argument("--last-child", type=int, default=10)
    args = parser.parse_args()
    if args.suite == "agreement-restore-stage" and args.original_agreement is None:
        parser.error("agreement-restore-stage requires --original-agreement")
    if (
        args.suite.startswith("news-thread-")
        and not 0 < args.article_parent <= 0xFFFFFFFF
    ):
        parser.error(
            "news-thread suites require a positive --article-parent from a captured list"
        )
    if args.suite == "article-delete-resume" and args.case_name is None:
        parser.error(
            "article-delete-resume requires --case-name from the retained inventory"
        )
    cases = {
        "news-boundary-preflight": lambda: {"preflight": news_boundary.preflight()},
        "news-boundary-seed": lambda: {"seed": news_boundary.seed()},
        "news-boundary-append": lambda: {
            f"append-{args.first_child:03}-{args.last_child:03}": news_boundary.append(
                args.first_child, args.last_child
            )
        },
        "news-boundary-observe": lambda: {"observe": news_boundary.observe()},
        "news-boundary-final": lambda: {"final": news_boundary.finalization()},
        "news-boundary-cleanup": lambda: {"cleanup": news_boundary.cleanup()},
        "news-boundary-publish": lambda: {"publish": news_boundary.publish_cleanup()},
        "news-boundary-remove": lambda: {
            "remove-publisher": news_boundary.remove_publisher()
        },
        "article-delete-preflight": article_delete_preflight,
        "article-delete-inspect": article_delete_inspect,
        "article-delete-categories": article_delete_categories,
        "article-delete-resume": lambda: article_delete_resume(
            args.case_name, args.completed_nodes, args.category_exists
        ),
        "article-delete-seed": article_delete_seed,
        "article-delete-cases": article_delete_cases,
        "article-delete-final": article_delete_final,
        "article-delete-cleanup": article_delete_cleanup,
        "article-delete-publish": article_delete_publish,
        "article-delete-remove": article_delete_remove,
        "news-preflight": news_preflight,
        "news-publish-cleanup": news_publish_cleanup,
        "news-remove-publisher": news_remove_publisher,
        "news-files-preflight": news_files_preflight,
        "news-bodies": news_bodies,
        "news-thread-children": lambda: news_thread_children(args.article_parent),
        "news-thread-grandchild": lambda: news_thread_grandchild(args.article_parent),
        "news-posts": news_posts,
        "news-seed": news_seed,
        "news-listings": news_listings,
        "news-structures": news_structures,
        "news-final": news_final,
        "news-cleanup": news_cleanup,
        "move-preflight": move_preflight,
        "move-seed": move_seed,
        "move-moves": move_moves,
        "move-deletions": move_deletions,
        "move-final": move_final,
        "move-cleanup": move_cleanup,
        "metadata-preflight": metadata_preflight,
        "metadata-combined-empty": metadata_combined_empty,
        "metadata-account-cleanup": metadata_account_cleanup,
        "metadata-boundaries": metadata_boundaries,
        "metadata-final": metadata_final,
        "metadata-seed": metadata_seed,
        "metadata-mutations": metadata_mutations,
        "metadata-cleanup": metadata_cleanup,
        "alias-cleanup": alias_cleanup,
        "alias-supplementary": alias_supplementary,
        "alias-damage": alias_damage,
        "alias-seed": alias_seed,
        "alias-create": alias_create,
        "alias-info": alias_information,
        "alias-download": alias_downloads,
        "mkdir-root-empty": mkdir_empty_root,
        "mkdir-final": mkdir_final,
        "mkdir-cleanup": mkdir_cleanup,
        "mkdir-seed": mkdir_seed,
        "mkdir-create": mkdir_creation,
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
            else [
                "GAP-003",
                "GAP-015",
                "GAP-016",
                "GAP-021",
                "GAP-031",
                "GAP-033",
                "GAP-067",
                "GAP-069",
                "GAP-084",
            ]
            if args.suite.startswith("article-delete-")
            else ["GAP-067", "GAP-068", "GAP-084"]
            if args.suite.startswith("news-boundary-")
            else ["GAP-003", "GAP-065", "GAP-066", "GAP-070", "GAP-084"]
            if args.suite.startswith("news-")
            else ["GAP-003", "GAP-047", "GAP-050", "GAP-053", "GAP-054", "GAP-084"]
            if args.suite.startswith("move-")
            else ["GAP-016", "GAP-019", "GAP-052", "GAP-084"]
            if args.suite.startswith("metadata-")
            else ["GAP-047", "GAP-048", "GAP-049", "GAP-054", "GAP-084"]
            if args.suite.startswith("alias-")
            else ["GAP-047", "GAP-048", "GAP-051", "GAP-019", "GAP-084"]
            if args.suite.startswith("mkdir-")
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
