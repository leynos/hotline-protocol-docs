"""Give the path-fields run its bounded transport.

Part of the path-fields runner (``native_path_fields_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below.
"""

import typing as typ

from native_rate304_control import Wire as RateWire


class Wire(RateWire):
    """Bounded transport with path-matrix progress retained on failure."""

    request_count: int = 0
    partial: dict[str, typ.Any]
