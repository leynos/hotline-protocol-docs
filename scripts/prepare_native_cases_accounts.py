"""Planner entries for the account suites: identity, batch, live and update."""

import json
import typing as typ

import native_account_batch_cases as account_batch
import native_account_identity_cases as account_identity
import native_account_update_cases as account_update
import native_live_account_cases as live_account

if typ.TYPE_CHECKING:
    from pathlib import Path

    from prepare_native_cases_inputs import Case, Entry, Inputs


def probe(label: str, password: bytes, *, success: bool) -> Case:
    """Plan a login of an update-suite account, expecting success or failure.

    Parameters
    ----------
    label : str
        The account label.
    password : bytes
        The password to send.
    success : bool
        Whether the login is expected to succeed.

    Returns
    -------
    Case
        The steps and expectation of the login.
    """
    return account_update.probe(label, password, success)


def entries(inputs: Inputs) -> dict[str, Entry]:
    """Return the entry of each account suite, keyed by suite name.

    Parameters
    ----------
    inputs : Inputs
        The command-line values; only the account inventory is read, and only
        by ``account-batch-cleanup``.

    Returns
    -------
    dict[str, Entry]
        One entry per account suite, each a function of no arguments.
    """
    return {
        "account-identity": account_identity.suites,
        "account-batch-preflight": lambda: {"preflight": account_batch.preflight()},
        "account-batch-seed": lambda: {"seed": account_batch.seed()},
        "account-batch-mutations": lambda: {
            s["case"]: account_batch.batch(s) for s in account_batch.specifications()
        },
        "account-batch-inspections": lambda: {
            s["case"]: account_batch.inspect(s) for s in account_batch.specifications()
        },
        "account-batch-nul-login": lambda: {"nul-login": account_batch.probe_nul()},
        "account-batch-final": lambda: {"final": account_batch.finalization()},
        "account-batch-distinct-inspect": lambda: {
            "inspect": account_batch.inspect(account_batch.supplementary_spec())
        },
        "account-batch-distinct-seed": lambda: {
            "seed": account_batch.supplementary_seed()
        },
        "account-batch-distinct-case": lambda: {
            "case": account_batch.batch(account_batch.supplementary_spec())
        },
        "account-batch-distinct-logins": lambda: {
            name: account_batch.supplementary_probe(name)
            for name in ["source", "destination-source", "destination-old"]
        },
        "account-batch-distinct-final": lambda: {
            "final": account_batch.supplementary_final()
        },
        "account-batch-cleanup": lambda: {
            "cleanup": account_batch.cleanup(
                json.loads(typ.cast("Path", inputs.account_inventory).read_text())
            )
        },
        "account-batch-publish": lambda: {"publish": account_batch.publish_cleanup()},
        "account-batch-remove": lambda: {
            "remove-publisher": account_batch.remove_publisher()
        },
        "account-live-preflight": lambda: {"preflight": live_account.preflight()},
        "account-live-seed": lambda: {"seed": live_account.seed()},
        "account-live-edit": lambda: {"edit": live_account.edit()},
        "account-live-delete": lambda: {"delete": live_account.delete()},
        "account-live-probes": lambda: {
            "login-" + label: live_account.probe(label)
            for label in ["old", "intermediate", "final", "deleted"]
        },
        "account-live-final": lambda: {"final": live_account.finalize()},
        "account-live-inspect": lambda: {"inspect": live_account.inspect()},
        "account-live-stopped": lambda: {"stopped": live_account.stopped()},
        "account-live-cleanup": lambda: {"cleanup": live_account.cleanup()},
        "account-live-publish": lambda: {"publish": live_account.publish_cleanup()},
        "account-live-remove": lambda: {
            "remove-publisher": live_account.remove_publisher()
        },
        "account-update-preflight": lambda: {"preflight": account_update.preflight()},
        "account-update-seed": lambda: {"seed": account_update.seed()},
        "account-update-mutate": lambda: {
            "mutation-" + label: account_update.mutate(label)
            for label in account_update.LABELS
        },
        "account-update-logins": lambda: {
            **{
                "login-" + label: probe(
                    label, account_update.result_password(label), success=True
                )
                for label in account_update.LABELS
            },
            **{
                "reject-" + label: probe(
                    label,
                    account_update.initial_password(label)
                    if account_update.initial_password(label)
                    != account_update.result_password(label)
                    else b"wrong-account26",
                    success=False,
                )
                for label in account_update.LABELS
            },
        },
        "account-update-base32-login": lambda: {
            "base32-login": probe("preserve32", b"q" * 32, success=True)
        },
        "account-update-final": lambda: {"final": account_update.finalization()},
        "account-update-cleanup": lambda: {"cleanup": account_update.cleanup()},
        "account-update-publish": lambda: {"publish": account_update.publish_cleanup()},
        "account-update-remove": lambda: {
            "remove-publisher": account_update.remove_publisher()
        },
    }
