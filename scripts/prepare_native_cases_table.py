"""The suite names that the command line accepts, and the entry that plans each one."""

import typing as typ

import prepare_native_cases_accounts as accounts
import prepare_native_cases_files as files
import prepare_native_cases_news as news
import prepare_native_cases_records as records
from native_agreement_cases import PHASES as AGREEMENT_PHASES
from native_login_extras_cases import NAMES as LOGIN_EXTRA_NAMES

if typ.TYPE_CHECKING:
    from prepare_native_cases_inputs import Entry, Inputs

# The order is the order of the command line's help text. It is the single
# source of the accepted suite names.
SUITES = (
    "article-delete-preflight",
    "account-update-preflight",
    "account-batch-preflight",
    "account-identity",
    "rooms",
    "account-batch-seed",
    "account-batch-mutations",
    "account-batch-inspections",
    "account-batch-nul-login",
    "account-batch-final",
    "account-batch-distinct-inspect",
    "account-batch-distinct-seed",
    "account-batch-distinct-case",
    "account-batch-distinct-logins",
    "account-batch-distinct-final",
    "account-batch-cleanup",
    "account-batch-publish",
    "account-batch-remove",
    "account-live-preflight",
    "account-live-seed",
    "account-live-edit",
    "account-live-delete",
    "account-live-probes",
    "account-live-final",
    "account-live-inspect",
    "account-live-stopped",
    "account-live-cleanup",
    "account-live-publish",
    "account-live-remove",
    "account-update-seed",
    "account-update-mutate",
    "account-update-logins",
    "account-update-base32-login",
    "account-update-final",
    "account-update-cleanup",
    "account-update-publish",
    "account-update-remove",
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
    "news-delete-presence",
    "news-post-presence",
    "news-read-presence",
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
    "login-version-presence",
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
)

type Suite = typ.Literal[
    SUITES  # ty: ignore[invalid-type-form]  # read from the tuple at run time
]


def dispatch(inputs: Inputs) -> dict[str, Entry]:
    """Return the entry that plans each suite, keyed by suite name.

    Parameters
    ----------
    inputs : Inputs
        The command-line values that the entries read.

    Returns
    -------
    dict[str, Entry]
        One entry per name in ``SUITES``.
    """
    return {
        **accounts.entries(inputs),
        **news.entries(inputs),
        **records.entries(inputs),
        **files.entries(),
    }
