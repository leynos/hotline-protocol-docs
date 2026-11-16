"""Name the room fixtures: the password, the owned roles and their keys."""

PASSWORD = b"room-pass30"
ROLES = {
    "zero": bytes(8),
    "reader": bytes.fromhex("0040000000000000"),
    "speaker": bytes.fromhex("0060000000000000"),
}
UNOWNED_ROLE = "Owned room role required"


def key(label: str) -> bytes:
    """Return the login key of the owned room role ``label``.

    Parameters
    ----------
    label : str
        One of the role names in ``ROLES``.

    Returns
    -------
    bytes
        The login key of the role's account.

    Raises
    ------
    ValueError
        When ``label`` is not an owned room role.
    """
    if label not in ROLES:
        raise ValueError(UNOWNED_ROLE)
    return b"m-room30-" + label.encode()


def format_values() -> list[tuple[int | None, bytes | None]]:
    """Return the option and text pairs of the chat formatting scenario.

    Returns
    -------
    list[tuple[int | None, bytes | None]]
        Each pair is an optional chat option and an optional text; ``None``
        omits the field.
    """
    return [
        (None, b"ordinary30"),
        (0, b"zero-option30"),
        (1, b"action30"),
        (2, b"other-option30"),
        (65535, b"maximum-option30"),
        (None, b"one\rTwo\nThree\r\nFour\0End"),
        (1, b"binary30-\x80\xff\rnext"),
        (None, b""),
        (None, None),
    ]
