"""Plan the alias-creation cases from their request specifications."""

import dataclasses as dc
import typing as typ

from native_alias_steps import BASE, ROOT, Case, Steps
from native_auth_cases import authentication
from native_folder_cases import path
from native_mkdir_cases import exchange
from native_plan import close, login


@dc.dataclass(frozen=True, slots=True)
class Spec:
    """One alias request, with the view and target that the plan records.

    Attributes
    ----------
    label : str
        The case name.
    name : bytes | None
        The alias name, or ``None`` when the request omits it.
    source : tuple[bytes, ...]
        The folder path of the source, before path encoding.
    destination : bytes | None
        The destination, as the request carries it, or ``None``.
    view : tuple[bytes, ...]
        The folder path that the listing views.
    target : bytes
        The name that the listing must show afterwards.
    role : str
        ``"admin"`` or ``"low"``, the account that makes the request.
    extra : bool
        Whether the request also carries the ignored field 211.
    """

    label: str
    name: bytes | None
    source: tuple[bytes, ...]
    destination: bytes | None
    view: tuple[bytes, ...]
    target: bytes
    role: str = "admin"
    extra: bool = False

    def record(self) -> dict[str, typ.Any]:
        """Describe the request as the plan records it.

        Returns
        -------
        dict[str, typing.Any]
            The recorded fields, in their recorded key order.
        """
        return {
            "case": self.label,
            "name_hex": None if self.name is None else self.name.hex(),
            "source_hex": path(self.source).hex(),
            "destination_hex": None
            if self.destination is None
            else self.destination.hex(),
            "view_hex": path(self.view).hex(),
            "target_hex": self.target.hex(),
            "role": self.role,
            "extra211": self.extra,
        }


def placed_specs() -> list[Spec]:
    """Plan the requests whose destination is a folder of the owned tree.

    Returns
    -------
    list[Spec]
        The specifications, in case order.
    """
    result: list[Spec] = []
    for label, name, source, dest, extra in [
        ("live-file", b"file", (ROOT,), b"A", True),
        ("live-directory", b"dir", (ROOT,), b"A", False),
        ("file-alias-chain", b"file", (ROOT, b"A"), b"B", False),
        ("directory-alias-chain", b"dir", (ROOT, b"A"), b"B", False),
        ("missing-source", b"missing", (ROOT,), b"D", False),
        ("missing-destination", b"file", (ROOT,), b"missing-parent", False),
        ("destination-not-directory", b"file", (ROOT,), b"file", False),
        ("file-collision", b"same", (ROOT,), b"C", False),
        ("directory-collision", b"dir", (ROOT,), b"C", False),
        ("same-location", b"self", (ROOT,), None, False),
        ("high-byte-source", b"hi-\x9a", (ROOT,), b"D", False),
    ]:
        view = (ROOT, dest) if dest in {b"A", b"B", b"C", b"D"} else (ROOT,)
        result.append(
            Spec(
                label,
                name,
                source,
                path((ROOT, dest)) if dest is not None else BASE,
                view,
                name,
                extra=extra,
            )
        )
    result.extend([
        Spec(
            "permission-new",
            b"unknown-tags",
            (ROOT,),
            path((ROOT, b"D")),
            (ROOT, b"D"),
            b"unknown-tags",
            role="low",
        ),
        Spec(
            "permission-conflict",
            b"file",
            (ROOT,),
            path((ROOT, b"A")),
            (ROOT, b"A"),
            b"file",
            role="low",
        ),
    ])
    return result


def unplaced_specs() -> list[Spec]:
    """Plan the requests that name a destination directly, or omit the name.

    Returns
    -------
    list[Spec]
        The specifications, in case order.
    """
    result: list[Spec] = []
    for label, name, destination in [
        ("destination-absent", b"m-al20-absent", None),
        ("destination-empty", b"m-al20-empty", b""),
        ("destination-root", b"m-al20-zero", b"\0\0"),
    ]:
        result.append(Spec(label, name, (ROOT,), destination, (), name))
    for label, name, source, target in [
        ("source-name-absent", None, b"file", b"derived-link"),
        ("source-name-empty", b"", b"file", b"derived-empty"),
        ("directory-name-absent", None, b"dir", b"derived-dir"),
    ]:
        result.append(
            Spec(
                label,
                name,
                (ROOT, source),
                path((ROOT, b"D", target)),
                (ROOT, b"D"),
                target,
            )
        )
    return result


def specs() -> list[dict[str, typ.Any]]:
    """Describe every alias request, in case order.

    Returns
    -------
    list[dict[str, typing.Any]]
        The recorded fields of each request.
    """
    return [spec.record() for spec in placed_specs() + unplaced_specs()]


def create() -> dict[str, Case]:
    """Plan every alias creation, with its listing checks and liveness control.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each case.
    """
    result: dict[str, Case] = {}
    for expected in specs():
        steps: Steps = login()
        if expected["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        values = [(202, bytes.fromhex(expected["source_hex"]))]
        if expected["name_hex"] is not None:
            values.insert(0, (201, bytes.fromhex(expected["name_hex"])))
        before_source = list(values)
        if expected["destination_hex"] is not None:
            values.append((212, bytes.fromhex(expected["destination_hex"])))
        if expected["extra211"]:
            values.append((211, b"ignored-alias-name"))
        view = bytes.fromhex(expected["view_hex"])
        steps += exchange(200, 10, [(202, view)]) + exchange(206, 11, before_source)
        steps += exchange(209, 12, values)
        steps += (
            exchange(
                206, 13, [(201, bytes.fromhex(expected["target_hex"])), (202, view)]
            )
            + exchange(200, 14, [(202, view)])
            + exchange(500, 90, [])
        )
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        result[expected["case"]] = (steps, {"kind": "alias-create", **expected})
    return result
