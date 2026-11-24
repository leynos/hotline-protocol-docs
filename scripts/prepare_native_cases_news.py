"""Planner entries for the news suites: boundary, article deletion and news."""

import typing as typ

import native_news_boundary_cases as news_boundary
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
from native_news_steps import read_presence

if typ.TYPE_CHECKING:
    from prepare_native_cases_inputs import Entry, Inputs


def entries(inputs: Inputs) -> dict[str, Entry]:
    """Return the entry of each news suite, keyed by suite name.

    Parameters
    ----------
    inputs : Inputs
        The command-line values. The case name, completed count and category
        flag feed ``article-delete-resume``; the article parent feeds the
        ``news-thread-`` suites; the child bounds feed ``news-boundary-append``.

    Returns
    -------
    dict[str, Entry]
        One entry per news suite, each a function of no arguments.
    """
    return {
        "news-boundary-preflight": lambda: {"preflight": news_boundary.preflight()},
        "news-boundary-seed": lambda: {"seed": news_boundary.seed()},
        "news-boundary-append": lambda: {
            f"append-{inputs.first_child:03}-{inputs.last_child:03}": (
                news_boundary.append(inputs.first_child, inputs.last_child)
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
            typ.cast("str", inputs.case_name),
            inputs.completed_nodes,
            inputs.category_exists,
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
        "news-read-presence": lambda: read_presence(inputs.article_parent),
        "news-bodies": news_bodies,
        "news-thread-children": lambda: news_thread_children(inputs.article_parent),
        "news-thread-grandchild": lambda: news_thread_grandchild(inputs.article_parent),
        "news-posts": news_posts,
        "news-seed": news_seed,
        "news-listings": news_listings,
        "news-structures": news_structures,
        "news-final": news_final,
        "news-cleanup": news_cleanup,
    }
