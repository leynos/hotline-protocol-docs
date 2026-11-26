"""Prepare bounded framing, TLV and scalar-observation cases."""

from native_plan import close, eof, login, packet, payload, quiet, read, send


def framing() -> dict[str, tuple[list[dict], dict]]:
    """Build one plan per framing case: the malformed frames and the valid controls."""
    cases = {}

    def add(name, data, expectation):
        """Add one framing case, wrapped in a login and a close."""
        cases[name] = (login() + data + [close()], expectation)

    for name, overrides in [
        ("flags-ff", {"flags": 255}),
        ("error-word-ffffffff", {"error": 0xFFFFFFFF}),
        ("id-zero", {}),
    ]:
        identifier = 0 if name == "id-zero" else 10
        add(
            name,
            [
                send(
                    packet(
                        500,
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
            f"unmatched-reply-{value}",
            [
                send(packet(500, 0x50000001, reply=value)),
                quiet(),
                send(packet(500, 11)),
                read(),
            ],
            {"kind": "ack", "id": 11},
        )
    for name, total, size in [
        ("total-zero", 0, 2),
        ("data-zero", 2, 0),
        ("total-above-limit", 524289, 2),
        ("data-above-limit", 2, 524289),
        ("total-uint32-max", 0xFFFFFFFF, 2),
        ("data-uint32-max", 2, 0xFFFFFFFF),
    ]:
        add(
            name,
            [send(packet(500, 10, b"", total=total, size=size)), eof()],
            {"kind": "close", "header_only": True},
        )
    for size in [1, 2, 524287, 524288]:
        add(
            f"complete-payload-{size}",
            [send(packet(500, 10, bytes(size))), read()],
            {"kind": "ack", "id": 10, "physical_bytes": size},
        )
    name = b"abc"
    ordinary = payload([(102, name), (104, b"\x12\x34")])
    variants = {
        "one-byte-count": (b"\0", b"***", 0),
        "empty-count": (b"\0\0", b"***", 0),
        "count-one-no-record": (b"\0\1", b"***", 0),
        "count-zero-trailing-record": (b"\0\0" + ordinary[2:], b"***", 0),
        "truncated-value": (b"\0\1\0\x66\0\x03ab", b"***", 0),
        "count-too-low": (b"\0\1" + ordinary[2:], name, 0),
        "count-too-high": (b"\0\3" + ordinary[2:], name, 0x1234),
        "valid-trailing-garbage": (ordinary + b"\xde\xad\xbe\xef\x01", name, 0x1234),
        "valid-prefix-truncated-header": (b"\0\2" + ordinary[2:9] + b"\0\x68", name, 0),
        "unknown-field": (payload([(65000, b"xyz"), (102, name)]), name, 0),
        "field-zero": (payload([(0, b"xyz"), (102, name)]), name, 0),
        "maximum-name": (payload([(102, b"x" * 65535)]), b"x" * 31, 0),
    }
    variants["zero-length-unknown-prefix"] = (
        payload([(65000, b""), (102, name), (104, b"\x12\x34")]),
        name,
        0x1234,
    )
    variants["maximum-count"] = (
        payload([(0, b"")] * 65534 + [(102, b"final-record")]),
        b"final-record",
        0,
    )
    for raw in [
        b"\x7f\xff",
        b"\x80\x00",
        b"\x80\x01",
        b"\xff\xff",
        b"\x00\x00\xff\xff",
        b"\x00\x01\x80\x00",
    ]:
        word = int.from_bytes(raw, "big") & 65535
        emitted = word | 0xFFFF0000 if word & 0x8000 else word
        variants["icon-" + raw.hex()] = (
            payload([(102, name), (104, raw)]),
            name,
            emitted,
        )
    for n in range(4):
        variants[f"truncated-header-{n}"] = (b"\0\1" + b"\0\x66\0\x03"[:n], b"***", 0)
    for raw, expected in [
        (b"", 0),
        (b"\x12", 18),
        (b"\x12\x34", 0x1234),
        (b"\0\x12\x34", 0),
        (b"\0\0\x12\x34", 0x1234),
        (b"\0\0\x12\x34\xff", 0x1234),
        (b"\0\1\0\0", 0),
        (b"\xff\xff\xff\xff", 0xFFFFFFFF),
    ]:
        variants["icon-" + (raw.hex() or "empty")] = (
            payload([(102, name), (104, raw)]),
            name,
            expected,
        )
    for key, (data, effective_name, icon) in variants.items():
        add(
            "tlv-" + key,
            [send(packet(304, 10, data)), read()],
            {"kind": "settings", "name_hex": effective_name.hex(), "icon": icon},
        )
    for values in [(1, 2), (2, 1), (1, 2, 3), (3, 2, 1)]:
        data = payload([(102, name)] + [(104, v.to_bytes(2, "big")) for v in values])
        add(
            "duplicate-icon-" + "-".join(map(str, values)),
            [send(packet(304, 10, data)), read()],
            {
                "kind": "duplicate-settings",
                "allowed_icons": list(values),
                "name_hex": name.hex(),
            },
        )
    add(
        "fragment-basic",
        [
            send(packet(500, 10, b"\0\0", total=4)),
            quiet(),
            send(packet(500, 10, b"\0\0", total=4)),
            read(),
        ],
        {"kind": "ack", "id": 10},
    )
    add(
        "fragment-total-overwrite",
        [
            send(packet(500, 10, b"\0\0", total=100)),
            quiet(),
            send(packet(500, 10, b"\0\0", total=4)),
            read(),
        ],
        {"kind": "ack", "id": 10},
    )
    add(
        "fragment-small-overshoot",
        [
            send(packet(500, 10, b"\0\0", total=3)),
            quiet(),
            send(packet(500, 10, b"\0\0", total=3)),
            read(),
        ],
        {"kind": "ack", "id": 10},
    )
    add(
        "fragment-limit-overshoot",
        [
            send(packet(500, 10, b"\0\0", total=524288)),
            send(packet(500, 10, bytes(524288), total=524288)),
            read(),
        ],
        {"kind": "ack", "id": 10, "aggregate_bytes": 524290},
    )
    add(
        "fragment-type-overwrite",
        [
            send(packet(500, 10, ordinary[:2], total=len(ordinary))),
            quiet(),
            send(packet(304, 10, ordinary[2:], total=len(ordinary))),
            read(),
        ],
        {"kind": "settings", "name_hex": name.hex(), "icon": 0x1234},
    )
    add(
        "fragment-interleaved-ids",
        [
            send(packet(500, 10, b"\0\0", total=4)),
            send(packet(500, 11, b"\0\0", total=4)),
            send(packet(500, 11, b"\0\0", total=4)),
            read(),
            send(packet(500, 10, b"\0\0", total=4)),
            read(),
        ],
        {"kind": "ack-sequence", "ids": [11, 10]},
    )
    add(
        "fragment-abandoned-other-completes",
        [
            send(packet(500, 10, b"\0\0", total=4)),
            quiet(),
            send(packet(500, 11)),
            read(),
        ],
        {"kind": "ack", "id": 11},
    )
    add(
        "fragment-request-reply-separate",
        [
            send(packet(500, 10, b"\0\0", total=4)),
            send(packet(500, 10, reply=1)),
            quiet(),
            send(packet(500, 10, b"\0\0", total=4)),
            read(),
        ],
        {"kind": "ack", "id": 10},
    )
    raw = packet(500, 10)
    add(
        "partial-tcp-header-and-body",
        [send(raw[:2]), quiet(), send(raw[2:42]), quiet(), send(raw[42:]), read()],
        {"kind": "ack", "id": 10},
    )
    add(
        "sequential-id-reuse",
        [send(packet(500, 10)), read(), send(packet(500, 10)), read()],
        {"kind": "ack-sequence", "ids": [10, 10]},
    )
    return cases
