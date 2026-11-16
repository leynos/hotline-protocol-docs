"""Build the expected plan of every capture in the article-deletion corpus.

The plans come from ``native_news_delete_cases``. They are built in the same
order as the original verifier built them, because the verifier reads an
inventory entry for each case while it does so.
"""

import typing as typ

import native_news_delete_cases as cases
from native_plan import Action

type Expected = dict[str, tuple[list[Action], dict[str, typ.Any]]]


def expected_plans(
    specifications: list[dict[str, typ.Any]],
    inventory: dict[str, dict[str, typ.Any]],
) -> Expected:
    """Build the expected plan of every capture, keyed by its directory.

    Parameters
    ----------
    specifications : list[dict[str, typing.Any]]
        The specifications from ``native_news_delete_cases.specs``.
    inventory : dict[str, dict[str, typing.Any]]
        The resume inventory of the corpus, keyed by category.

    Returns
    -------
    Expected
        The steps and the expectation of each capture directory.
    """
    factories = {
        "initial/preflight": cases.preflight,
        "initial/burst": cases.initial_burst_seed,
        "initial/banned-login": cases.preflight,
        "inventory-recovery": cases.inspect_seed,
        "final": cases.finalization,
        "cleanup": cases.cleanup,
        "publish": cases.publish_cleanup,
        "remove-publisher": cases.remove_publisher,
    }
    expected = {k: next(iter(f().values())) for k, f in factories.items()}
    expected.update({"deletions/" + k: v for k, v in cases.deletions().items()})
    for spec in specifications:
        name = spec["case"]
        prefix = inventory[name]
        expected["resumed/" + name] = cases.resume_category(
            name, prefix["completed"], prefix["exists"]
        )[name]
    return expected
