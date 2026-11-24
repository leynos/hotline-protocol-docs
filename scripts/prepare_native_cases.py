#!/usr/bin/env python3
"""Prepare bounded native protocol observation plans."""

import json
import sys
import typing as typ
from pathlib import Path

import native_account_batch_cases
import native_account_identity_cases
import native_account_update_cases
import native_agreement_cases
import native_alias_cases
import native_auth_cases
import native_banner_cases
import native_cleanup_cases
import native_correlation_cases
import native_folder_cases
import native_folder_upload_cases
import native_framing_cases
import native_htxf_cases
import native_live_account_cases
import native_login_extras_cases
import native_metadata_cases
import native_mkdir_cases
import native_move_cases
import native_news_boundary_cases
import native_news_cases
import native_news_delete_cases
import native_queue_cases
import native_resume_cases
import native_room_cases
import native_transfer_cases
from prepare_native_cases_gaps import gap_ids
from prepare_native_cases_help import show_help
from prepare_native_cases_inputs import Inputs
from prepare_native_cases_table import Suite, dispatch
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import UsageError, run

# tools/golden_planners.py reads the imports of this file to tell which planner
# modules it dispatches to, so the facade imports each of them, as the single
# module did, and lists them here so that they count as used.
__all__ = [
    "main",
    "native_account_batch_cases",
    "native_account_identity_cases",
    "native_account_update_cases",
    "native_agreement_cases",
    "native_alias_cases",
    "native_auth_cases",
    "native_banner_cases",
    "native_cleanup_cases",
    "native_correlation_cases",
    "native_folder_cases",
    "native_folder_upload_cases",
    "native_framing_cases",
    "native_htxf_cases",
    "native_live_account_cases",
    "native_login_extras_cases",
    "native_metadata_cases",
    "native_mkdir_cases",
    "native_move_cases",
    "native_news_boundary_cases",
    "native_news_cases",
    "native_news_delete_cases",
    "native_queue_cases",
    "native_resume_cases",
    "native_room_cases",
    "native_transfer_cases",
    "prepare",
]

# The largest article identifier, which a 32-bit field carries.
MAX_ARTICLE_PARENT = 0xFFFFFFFF

# Namespace-local server forward for the GAP-016 run, separate from the
# isolated runtime's fixed relay to host loopback at 15500.
ISOLATED_CONTROL_PORT = 16140


def refuse(message: str) -> typ.NoReturn:
    """Refuse a command line that names something that cannot be planned.

    Parameters
    ----------
    message : str
        The reason, shown to the user.

    Raises
    ------
    script_cli.UsageError
        Always, with the message.
    """
    raise UsageError(message)


def check_inputs(suite: str, inputs: Inputs) -> None:
    """Refuse a suite whose required option is missing or out of range.

    The checks run in a fixed order, and the first failing one is reported
    through :func:`refuse` as a usage error.

    Parameters
    ----------
    suite : str
        The suite name.
    inputs : Inputs
        The command-line values.
    """
    if suite == "account-batch-cleanup" and inputs.account_inventory is None:
        refuse(
            "account-batch-cleanup requires --account-inventory from final native reads"
        )
    if suite == "agreement-restore-stage" and inputs.original_agreement is None:
        refuse("agreement-restore-stage requires --original-agreement")
    needs_listed_article = suite in {
        "news-thread-children",
        "news-thread-grandchild",
        "news-read-presence",
    }
    if needs_listed_article and not 0 < inputs.article_parent <= MAX_ARTICLE_PARENT:
        refuse(f"{suite} requires a positive --article-parent from a captured list")
    if suite == "article-delete-resume" and inputs.case_name is None:
        refuse("article-delete-resume requires --case-name from the retained inventory")


def build_plan(
    suite: str,
    runtime_record: Path,
    steps: list[typ.Any],
    expectation: dict[str, typ.Any],
) -> dict[str, typ.Any]:
    """Return the plan document for one case of a suite.

    Parameters
    ----------
    suite : str
        The suite name, which selects the gap identifiers.
    runtime_record : Path
        The JSON record of the runtime environment, read for each case.
    steps : list[typ.Any]
        The actions of the case.
    expectation : dict[str, typ.Any]
        What the case expects to observe.

    Returns
    -------
    dict[str, typ.Any]
        The plan, with its keys in the order the verifier reads them.
    """
    endpoints = {
        "control": {"host": "127.0.0.1", "port": 15500},
        "data": {"host": "127.0.0.1", "port": 15501},
    }
    if suite in {
        "login-version-presence",
        "news-delete-presence",
        "news-post-presence",
        "news-read-presence",
    }:
        endpoints = {"control": {"host": "127.0.0.1", "port": ISOLATED_CONTROL_PORT}}
    return {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "native fixture operator",
        "oracle_sha256": ORACLE_SHA256,
        "environment": json.loads(runtime_record.read_text()),
        "gap_ids": gap_ids(suite),
        "endpoints": endpoints,
        "expectation": expectation,
        "steps": steps,
    }


def write_plans(suite: str, inputs: Inputs, runtime_record: Path, output: Path) -> None:
    """Write one plan file per case of a suite, then report the count.

    The cases are planned before the output directory is created, so a planner
    failure leaves no directory behind.

    Parameters
    ----------
    suite : str
        The suite name.
    inputs : Inputs
        The command-line values that the planner reads.
    runtime_record : Path
        The JSON record of the runtime environment.
    output : Path
        The directory to create; it must not exist.
    """
    cases = dispatch(inputs)[suite]()
    output.mkdir(parents=True, exist_ok=False)
    for name, (steps, expectation) in cases.items():
        plan = build_plan(suite, runtime_record, steps, expectation)
        validate_plan(plan)
        (output / (name + ".json")).write_text(json.dumps(plan, indent=2) + "\n")
    print(f"Prepared {len(cases)} {suite} plans")


def prepare(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the command line takes one parameter per argparse option, as it always has
    suite: Suite,
    *,
    runtime_record: str,
    output: str,
    original_agreement: str | None = None,
    article_parent: int = 0,
    case_name: str | None = None,
    completed_nodes: int = 0,
    category_exists: bool = False,
    account_inventory: str | None = None,
    first_child: int = 1,
    last_child: int = 10,
) -> None:
    """Prepare the plan files of one suite.

    Parameters
    ----------
    suite : Suite
        The suite to prepare.
    runtime_record : str
        The JSON record of the runtime environment.
    output : str
        The directory to create for the plans; it must not exist.
    original_agreement : str | None
        The retained original agreement, for ``agreement-restore-stage``.
    article_parent : int
        The listed article ID for news thread or read-presence fixtures.
    case_name : str | None
        The retained category name, for ``article-delete-resume``.
    completed_nodes : int
        The number of nodes already completed, for ``article-delete-resume``.
    category_exists : bool
        Whether the category already exists, for ``article-delete-resume``.
    account_inventory : str | None
        The retained account inventory, for ``account-batch-cleanup``.
    first_child : int
        The first child number, for ``news-boundary-append``.
    last_child : int
        The last child number, for ``news-boundary-append``.
    """
    inputs = Inputs(
        account_inventory=None
        if account_inventory is None
        else Path(account_inventory),
        original_agreement=None
        if original_agreement is None
        else Path(original_agreement),
        article_parent=article_parent,
        case_name=case_name,
        completed_nodes=completed_nodes,
        category_exists=category_exists,
        first_child=first_child,
        last_child=last_child,
    )
    check_inputs(suite, inputs)
    write_plans(suite, inputs, Path(runtime_record), Path(output))


def main() -> None:
    """Run the command line and prepare the plans of the named suite.

    ``--help`` is answered by the ``argparse`` layout that tools read.
    """
    if {"-h", "--help"} & set(sys.argv[1:]):
        show_help(__doc__)
    run(prepare, __doc__)


if __name__ == "__main__":
    main()
