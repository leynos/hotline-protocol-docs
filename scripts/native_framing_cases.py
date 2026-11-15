"""Prepare bounded framing, TLV and scalar-observation cases."""

import typing as typ

from native_plan import Action, close, eof, login, packet, payload, quiet, read, send
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    MAX_FRAME_BYTES,
    TYPE_EMPTY_ACK,
    TYPE_SET_CLIENT_INFO,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]
type Variant = tuple[bytes, bytes, int]  # data, effective name, emitted icon

REQUEST_ID = 10
OTHER_ID = 11
UNMATCHED_ID = 0x50000001
UINT32_MAX = 0xFFFFFFFF
UINT16_MAX = 65535
NAME = b"abc"
DEFAULT_NAME = b"***"  # the name that a settings request with no usable name keeps
FRAGMENT_TOTAL = 4  # one empty-ACK payload (a count word) in two fragments
MAX_NAME_BYTES = 65535
EFFECTIVE_NAME_BYTES = 31  # the longest display name that the server stores
FIELD_UNKNOWN = 65000
FIELD_ZERO = 0
FIELD_NAME_LOW = FIELD_NAME & 0xFF  # the low byte of the name field ID in a header
ICON_MASK = 0xFFFF
ICON_SIGN_BIT = 0x8000
ICON_SIGN_EXTENSION = 0xFFFF0000
ICON_NARROW_BYTES = 2
LIMIT_SIZES = [1, 2, MAX_FRAME_BYTES - 1, MAX_FRAME_BYTES]
FIRST_PACKET_BYTES = 2
FIRST_PART_END = 42  # the header and the count word


def add(
    cases: Cases, name: str, data: list[Action], expectation: dict[str, typ.Any]
) -> None:
    """Add a case that logs in, runs ``data`` and closes.

    The expectation is stored as given, so the caller keeps ownership of it.
    """
    cases[name] = ([*login(), *data, close()], expectation)


def add_header_flags(cases: Cases) -> None:
    """Add the cases whose header flags, error word or ID is unusual."""
    for name, overrides in [
        ("flags-ff", {"flags": 255}),
        ("error-word-ffffffff", {"error": UINT32_MAX}),
        ("id-zero", {}),
    ]:
        identifier = 0 if name == "id-zero" else REQUEST_ID
        add(
            cases,
            name,
            [
                send(
                    packet(
                        TYPE_EMPTY_ACK,
                        identifier,
                        flags=overrides.get("flags", 0),
                        error=overrides.get("error", 0),
                    )
                ),
                read(),
            ],
            {"kind": "ack", "id": identifier},
        )
    for value in [1, 2, 255]:
        add(
            cases,
            f"unmatched-reply-{value}",
            [
                send(packet(TYPE_EMPTY_ACK, UNMATCHED_ID, reply=value)),
                quiet(),
                send(packet(TYPE_EMPTY_ACK, OTHER_ID)),
                read(),
            ],
            {"kind": "ack", "id": OTHER_ID},
        )


def add_size_limits(cases: Cases) -> None:
    """Add the cases whose total or data size is zero, at a limit or beyond it."""
    for name, total, size in [
        ("total-zero", 0, 2),
        ("data-zero", 2, 0),
        ("total-above-limit", MAX_FRAME_BYTES + 1, 2),
        ("data-above-limit", 2, MAX_FRAME_BYTES + 1),
        ("total-uint32-max", UINT32_MAX, 2),
        ("data-uint32-max", 2, UINT32_MAX),
    ]:
        add(
            cases,
            name,
            [
                send(packet(TYPE_EMPTY_ACK, REQUEST_ID, b"", total=total, size=size)),
                eof(),
            ],
            {"kind": "close", "header_only": True},
        )
    for size in LIMIT_SIZES:
        add(
            cases,
            f"complete-payload-{size}",
            [send(packet(TYPE_EMPTY_ACK, REQUEST_ID, bytes(size))), read()],
            {"kind": "ack", "id": REQUEST_ID, "physical_bytes": size},
        )


def sign_extended(raw: bytes) -> int:
    """Narrow an icon value to 16 bits and sign-extend it as the server emits it.

    Returns
    -------
    int
        The emitted icon word.
    """
    word = int.from_bytes(raw, "big") & ICON_MASK
    return word | ICON_SIGN_EXTENSION if word & ICON_SIGN_BIT else word


def tlv_variants() -> dict[str, Variant]:
    """Build the malformed and unusual field lists of the TLV cases.

    Returns
    -------
    dict[str, tuple[bytes, bytes, int]]
        The data, the effective name and the emitted icon of each variant.
    """
    ordinary = payload([(FIELD_NAME, NAME), (FIELD_ICON, b"\x12\x34")])
    name_header = bytes([0, FIELD_NAME_LOW, 0, 3])  # field 102, length 3
    variants: dict[str, Variant] = {
        "one-byte-count": (b"\0", DEFAULT_NAME, 0),
        "empty-count": (b"\0\0", DEFAULT_NAME, 0),
        "count-one-no-record": (b"\0\1", DEFAULT_NAME, 0),
        "count-zero-trailing-record": (b"\0\0" + ordinary[2:], DEFAULT_NAME, 0),
        "truncated-value": (b"\0\1" + name_header + b"ab", DEFAULT_NAME, 0),
        "count-too-low": (b"\0\1" + ordinary[2:], NAME, 0),
        "count-too-high": (b"\0\3" + ordinary[2:], NAME, 0x1234),
        "valid-trailing-garbage": (ordinary + b"\xde\xad\xbe\xef\x01", NAME, 0x1234),
        "valid-prefix-truncated-header": (
            b"\0\2" + ordinary[2:9] + b"\0\x68",
            NAME,
            0,
        ),
        "unknown-field": (
            payload([(FIELD_UNKNOWN, b"xyz"), (FIELD_NAME, NAME)]),
            NAME,
            0,
        ),
        "field-zero": (payload([(FIELD_ZERO, b"xyz"), (FIELD_NAME, NAME)]), NAME, 0),
        "maximum-name": (
            payload([(FIELD_NAME, b"x" * MAX_NAME_BYTES)]),
            b"x" * EFFECTIVE_NAME_BYTES,
            0,
        ),
    }
    variants["zero-length-unknown-prefix"] = (
        payload([(FIELD_UNKNOWN, b""), (FIELD_NAME, NAME), (FIELD_ICON, b"\x12\x34")]),
        NAME,
        0x1234,
    )
    variants["maximum-count"] = (
        payload(
            [(FIELD_ZERO, b"")] * (UINT16_MAX - 1) + [(FIELD_NAME, b"final-record")]
        ),
        b"final-record",
        0,
    )
    return variants


def add_icon_variants(variants: dict[str, Variant]) -> None:
    """Add the icon widths: sign-extended words, truncated headers and odd sizes."""
    for raw in [
        b"\x7f\xff",
        b"\x80\x00",
        b"\x80\x01",
        b"\xff\xff",
        b"\x00\x00\xff\xff",
        b"\x00\x01\x80\x00",
    ]:
        variants["icon-" + raw.hex()] = (
            payload([(FIELD_NAME, NAME), (FIELD_ICON, raw)]),
            NAME,
            sign_extended(raw),
        )
    for n in range(4):
        variants[f"truncated-header-{n}"] = (
            b"\0\1" + bytes([0, FIELD_NAME_LOW, 0, 3])[:n],
            DEFAULT_NAME,
            0,
        )
    for raw, expected in [
        (b"", 0),
        (b"\x12", 18),
        (b"\x12\x34", 0x1234),
        (b"\0\x12\x34", 0),
        (b"\0\0\x12\x34", 0x1234),
        (b"\0\0\x12\x34\xff", 0x1234),
        (b"\0\1\0\0", 0),
        (b"\xff\xff\xff\xff", UINT32_MAX),
    ]:
        variants["icon-" + (raw.hex() or "empty")] = (
            payload([(FIELD_NAME, NAME), (FIELD_ICON, raw)]),
            NAME,
            expected,
        )


def add_tlv(cases: Cases) -> None:
    """Add the settings cases that vary the field list, then the duplicate icons."""
    variants = tlv_variants()
    add_icon_variants(variants)
    for key, (data, effective_name, icon) in variants.items():
        add(
            cases,
            "tlv-" + key,
            [send(packet(TYPE_SET_CLIENT_INFO, REQUEST_ID, data)), read()],
            {"kind": "settings", "name_hex": effective_name.hex(), "icon": icon},
        )
    for values in [(1, 2), (2, 1), (1, 2, 3), (3, 2, 1)]:
        data = payload(
            [(FIELD_NAME, NAME)]
            + [(FIELD_ICON, v.to_bytes(ICON_NARROW_BYTES, "big")) for v in values]
        )
        add(
            cases,
            "duplicate-icon-" + "-".join(map(str, values)),
            [send(packet(TYPE_SET_CLIENT_INFO, REQUEST_ID, data)), read()],
            {
                "kind": "duplicate-settings",
                "allowed_icons": list(values),
                "name_hex": NAME.hex(),
            },
        )


def fragment(identifier: int, total: int) -> Action:
    """Plan sending an empty-ACK count word that claims ``total`` bytes.

    Returns
    -------
    native_plan.Action
        The send action.
    """
    return send(packet(TYPE_EMPTY_ACK, identifier, b"\0\0", total=total))


def add_fragments(cases: Cases) -> None:
    """Add the cases that split one transaction across frames."""
    ordinary = payload([(FIELD_NAME, NAME), (FIELD_ICON, b"\x12\x34")])
    add(
        cases,
        "fragment-basic",
        [fragment(10, 4), quiet(), fragment(10, 4), read()],
        {"kind": "ack", "id": 10},
    )
    add(
        cases,
        "fragment-total-overwrite",
        [fragment(10, 100), quiet(), fragment(10, 4), read()],
        {"kind": "ack", "id": 10},
    )
    add(
        cases,
        "fragment-small-overshoot",
        [fragment(10, 3), quiet(), fragment(10, 3), read()],
        {"kind": "ack", "id": 10},
    )
    add(
        cases,
        "fragment-limit-overshoot",
        [
            fragment(10, MAX_FRAME_BYTES),
            send(
                packet(
                    TYPE_EMPTY_ACK,
                    REQUEST_ID,
                    bytes(MAX_FRAME_BYTES),
                    total=MAX_FRAME_BYTES,
                )
            ),
            read(),
        ],
        {"kind": "ack", "id": 10, "aggregate_bytes": MAX_FRAME_BYTES + 2},
    )
    add(
        cases,
        "fragment-type-overwrite",
        [
            send(packet(TYPE_EMPTY_ACK, REQUEST_ID, ordinary[:2], total=len(ordinary))),
            quiet(),
            send(
                packet(
                    TYPE_SET_CLIENT_INFO,
                    REQUEST_ID,
                    ordinary[2:],
                    total=len(ordinary),
                )
            ),
            read(),
        ],
        {"kind": "settings", "name_hex": NAME.hex(), "icon": 0x1234},
    )
    add_fragment_ids(cases)


def add_fragment_ids(cases: Cases) -> None:
    """Add the cases in which fragments of different IDs interleave or are dropped."""
    add(
        cases,
        "fragment-interleaved-ids",
        [
            fragment(10, FRAGMENT_TOTAL),
            fragment(11, FRAGMENT_TOTAL),
            fragment(11, FRAGMENT_TOTAL),
            read(),
            fragment(10, FRAGMENT_TOTAL),
            read(),
        ],
        {"kind": "ack-sequence", "ids": [11, 10]},
    )
    add(
        cases,
        "fragment-abandoned-other-completes",
        [
            fragment(10, FRAGMENT_TOTAL),
            quiet(),
            send(packet(TYPE_EMPTY_ACK, OTHER_ID)),
            read(),
        ],
        {"kind": "ack", "id": 11},
    )
    add(
        cases,
        "fragment-request-reply-separate",
        [
            fragment(10, FRAGMENT_TOTAL),
            send(packet(TYPE_EMPTY_ACK, REQUEST_ID, reply=1)),
            quiet(),
            fragment(10, FRAGMENT_TOTAL),
            read(),
        ],
        {"kind": "ack", "id": 10},
    )


def add_tcp_boundaries(cases: Cases) -> None:
    """Add the cases whose TCP segments split a frame, and whose ID is reused."""
    raw = packet(TYPE_EMPTY_ACK, REQUEST_ID)
    add(
        cases,
        "partial-tcp-header-and-body",
        [
            send(raw[:FIRST_PACKET_BYTES]),
            quiet(),
            send(raw[FIRST_PACKET_BYTES:FIRST_PART_END]),
            quiet(),
            send(raw[FIRST_PART_END:]),
            read(),
        ],
        {"kind": "ack", "id": REQUEST_ID},
    )
    add(
        cases,
        "sequential-id-reuse",
        [
            send(packet(TYPE_EMPTY_ACK, REQUEST_ID)),
            read(),
            send(packet(TYPE_EMPTY_ACK, REQUEST_ID)),
            read(),
        ],
        {"kind": "ack-sequence", "ids": [REQUEST_ID, REQUEST_ID]},
    )


def framing() -> Cases:
    """Plan every framing, TLV and fragment case.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    cases: Cases = {}
    add_header_flags(cases)
    add_size_limits(cases)
    add_tlv(cases)
    add_fragments(cases)
    add_tcp_boundaries(cases)
    return cases
