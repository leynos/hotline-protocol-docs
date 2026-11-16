"""Raise the refusals of the proxy with their messages kept off the raise line."""

import typing as typ


def fail(error: type[Exception], message: str) -> typ.Never:
    """Raise one refusal of the proxy.

    Parameters
    ----------
    error : type[Exception]
        The exception class to raise.
    message : str
        The message that the exception carries, unchanged.
    """
    raise error(message)
