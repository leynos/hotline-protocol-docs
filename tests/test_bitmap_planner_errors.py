"""Pin the refusal of the bitmap planner.

The planner's one refusal is a plain ``ValueError`` raise, and the structured
version raises a subclass of it with the same message, so a caller that catches
``ValueError`` sees no change. Every expectation was observed on the version of
the scripts before the planner was documented and typed (commit 0b34126).
"""

import native_bitmap_cases as cases
import pytest

OUTSIDE = [-1, 64, 65, 1000]


class PlannerRefusalTests:
    """Keep the planner's refusal, its type and its message."""

    @pytest.mark.parametrize("bit", OUTSIDE)
    def test_a_bit_outside_the_registry_is_refused(self, bit: int) -> None:
        """A bit that no field-110 position holds is refused."""
        with pytest.raises(ValueError, match="Bit outside field-110 registry"):
            cases.walking_bit(bit)

    @pytest.mark.parametrize("bit", [0, 63])
    def test_the_first_and_last_bits_are_accepted(self, bit: int) -> None:
        """The edges of the registry are positions."""
        assert len(cases.walking_bit(bit)) == len(cases.ZERO), "wrong width"
