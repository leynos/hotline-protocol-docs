"""Gap identifiers that each suite's plan cites, by the first rule that matches."""

import collections.abc as cabc

type Test = cabc.Callable[[str], bool]

# The rules are tried in order and the first match wins. Each rule names the
# suites it covers and the gaps that the suites observe. DEFAULT_GAPS applies
# to every suite that no rule covers.
DEFAULT_GAPS = ("GAP-009", "GAP-055", "GAP-056", "GAP-064")


def is_suite(*names: str) -> Test:
    """Return a test that matches exactly one of the suite names.

    Parameters
    ----------
    *names : str
        The suite names the test accepts.

    Returns
    -------
    collections.abc.Callable[[str], bool]
        The test.
    """
    return lambda suite: suite in names


def has_prefix(prefix: str) -> Test:
    """Return a test that matches every suite name starting with the prefix.

    Parameters
    ----------
    prefix : str
        The leading text that a suite name must start with.

    Returns
    -------
    collections.abc.Callable[[str], bool]
        The test.
    """
    return lambda suite: suite.startswith(prefix)


GAP_RULES: tuple[tuple[Test, tuple[str, ...]], ...] = (
    (
        is_suite("framing"),
        ("GAP-011", "GAP-012", "GAP-013", "GAP-014", "GAP-015", "GAP-017"),
    ),
    (
        is_suite("rooms"),
        ("GAP-038", "GAP-039", "GAP-040", "GAP-041", "GAP-042", "GAP-084"),
    ),
    (
        is_suite("account-identity"),
        ("GAP-003", "GAP-021", "GAP-031", "GAP-036", "GAP-072", "GAP-074", "GAP-084"),
    ),
    (
        has_prefix("account-batch-"),
        (
            "GAP-003",
            "GAP-016",
            "GAP-017",
            "GAP-019",
            "GAP-021",
            "GAP-031",
            "GAP-071",
            "GAP-072",
            "GAP-078",
            "GAP-084",
        ),
    ),
    (
        has_prefix("account-live-"),
        ("GAP-035", "GAP-036", "GAP-071", "GAP-072", "GAP-073", "GAP-084"),
    ),
    (
        has_prefix("account-update-"),
        ("GAP-016", "GAP-019", "GAP-071", "GAP-072", "GAP-073", "GAP-084"),
    ),
    (
        has_prefix("article-delete-"),
        (
            "GAP-003",
            "GAP-015",
            "GAP-016",
            "GAP-021",
            "GAP-031",
            "GAP-033",
            "GAP-067",
            "GAP-069",
            "GAP-084",
        ),
    ),
    (is_suite("news-delete-presence", "news-delete-presence-setup"), ("GAP-016",)),
    (is_suite("news-post-presence"), ("GAP-016",)),
    (is_suite("news-read-presence"), ("GAP-016",)),
    (has_prefix("news-boundary-"), ("GAP-067", "GAP-068", "GAP-084")),
    (has_prefix("news-"), ("GAP-003", "GAP-065", "GAP-066", "GAP-070", "GAP-084")),
    (
        has_prefix("move-"),
        ("GAP-003", "GAP-047", "GAP-050", "GAP-053", "GAP-054", "GAP-084"),
    ),
    (has_prefix("metadata-"), ("GAP-016", "GAP-019", "GAP-052", "GAP-084")),
    (has_prefix("alias-"), ("GAP-047", "GAP-048", "GAP-049", "GAP-054", "GAP-084")),
    (has_prefix("mkdir-"), ("GAP-047", "GAP-048", "GAP-051", "GAP-019", "GAP-084")),
    (is_suite("login-version-presence"), ("GAP-016",)),
    (has_prefix("login-extras-"), ("GAP-026", "GAP-018", "GAP-019", "GAP-084")),
    (has_prefix("agreement-"), ("GAP-025", "GAP-027", "GAP-019", "GAP-084")),
    (has_prefix("auth-"), ("GAP-023", "GAP-025", "GAP-026", "GAP-027", "GAP-084")),
    (is_suite("correlation"), ("GAP-004", "GAP-012", "GAP-013", "GAP-084")),
    (is_suite("htxf"), ("GAP-055", "GAP-084")),
    (has_prefix("banner-"), ("GAP-055", "GAP-063", "GAP-084")),
    (has_prefix("resume-"), ("GAP-058", "GAP-064")),
    (has_prefix("folder-"), ("GAP-059", "GAP-060", "GAP-064")),
    (has_prefix("cleanup-"), ("GAP-062", "GAP-064")),
    (is_suite("queues", "queue-timer"), ("GAP-057", "GAP-061", "GAP-062")),
)


def gap_ids(suite: str) -> list[str]:
    """Return the gap identifiers that the plans of one suite cite.

    Parameters
    ----------
    suite : str
        The suite name.

    Returns
    -------
    list[str]
        A new list of gap identifiers, in the order the plan records them.
    """
    for test, gaps in GAP_RULES:
        if test(suite):
            return list(gaps)
    return list(DEFAULT_GAPS)
