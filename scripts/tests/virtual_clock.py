"""A clock that moves only when the code under test waits."""

import select

START = 1000.0


class VirtualClock:
    """A clock that moves only when the code under test waits."""

    def __init__(self) -> None:
        """Start at a fixed instant."""
        self.now = START
        self.real_select = select.select

    def monotonic_ns(self) -> int:
        """Read the virtual clock in nanoseconds.

        Returns
        -------
        int
            Nanoseconds.
        """
        return int(self.now * 1e9)

    def sleep(self, seconds: float) -> None:
        """Move the clock instead of waiting."""
        self.now += seconds

    def select(
        self,
        readers: list,
        writers: list,
        errors: list,
        timeout: float | None = None,
    ) -> tuple[list, list, list]:
        """Report what is ready now; if nothing is, let the timeout pass.

        Returns
        -------
        tuple[list, list, list]
            The ready sockets of each kind.
        """
        ready = self.real_select(readers, writers, errors, 0)
        if not any(ready) and timeout:
            self.now += timeout
        return ready
