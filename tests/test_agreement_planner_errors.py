"""Pin the refusals of the agreement planner.

The planner's three refusals are plain ``ValueError`` raises, and the structured
version raises subclasses of it with the same messages, so a caller that catches
``ValueError`` sees no change. Every expectation was observed on the version of
the scripts before the planner was split into ``native_agreement_*`` modules
(commit 0b34126).
"""

import pytest
from native_agreement_cases import phase, restore_stage, staged_file


class PlannerRefusalTests:
    """Keep the planner's refusals, their type and their messages."""

    def test_restoration_needs_the_retained_original_agreement(self) -> None:
        """Other data than the retained agreement is not restored."""
        with pytest.raises(
            ValueError, match="Restoration requires the retained original agreement"
        ):
            restore_stage(b"another agreement")

    @pytest.mark.parametrize("kind", [b"", b"TEX", b"TEXTS"])
    def test_a_finder_type_has_four_bytes(self, kind: bytes) -> None:
        """A Finder type of another length is refused before any step is planned."""
        with pytest.raises(ValueError, match="Finder type must contain four bytes"):
            staged_file(b"root", b"Agreement.txt", kind, b"data")

    def test_an_unknown_phase_is_refused(self) -> None:
        """A phase that the planner does not know is refused."""
        with pytest.raises(ValueError, match="Unknown agreement phase"):
            phase("not-a-phase")

    def test_the_phase_is_checked_before_the_overflow_branch(self) -> None:
        """A name that ends like an overflow phase is still checked against the list."""
        with pytest.raises(ValueError, match="Unknown agreement phase"):
            phase("other-field-over-limit")
