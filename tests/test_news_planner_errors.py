"""Pin the refusals of the news planners.

The boundary planner refuses a child-append range with a plain ``ValueError``
raised before any step is planned; the structured version keeps the type and the
message. Every expectation was observed on the version of the scripts before the
planners were split into ``native_news_*`` modules (commit 0b34126).
"""

import pytest
from native_news_boundary_cases import append

REFUSED = [(0, 1), (1, 11), (10, 9), (1, 100), (0, 0), (-1, 5), (1, 103)]
ACCEPTED = [(1, 1), (93, 102), (101, 102)]
STEPS_AND_EXPECTATION = 2


class PlannerRefusalTests:
    """Keep the planner's refusals, their type and their message."""

    @pytest.mark.parametrize(("first", "last"), REFUSED)
    def test_an_unbounded_or_out_of_range_batch_is_refused(
        self, first: int, last: int
    ) -> None:
        """A range that is empty, wider than ten, or outside 1..102 is refused."""
        with pytest.raises(
            ValueError, match=r"Child append must be a bounded range within 1\.\.102"
        ):
            append(first, last)

    @pytest.mark.parametrize(("first", "last"), ACCEPTED)
    def test_a_bounded_range_is_planned(self, first: int, last: int) -> None:
        """A bounded range inside 1..102 yields the steps and the expectation."""
        assert len(append(first, last)) == STEPS_AND_EXPECTATION, "not planned"
