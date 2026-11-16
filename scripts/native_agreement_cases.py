"""Prepare agreement-content controls using the observed native login paths."""

import hashlib
import typing as typ

from native_agreement_data import (
    FILES,
    NON_TEXT_FILES,
    ORIGINAL_AGREEMENT_SHA256,
    PHASES,
    TEXT,
)
from native_agreement_overflow import field_overflow
from native_auth_cases import PASSWORD, complement
from native_auth_cases import states as auth_states
from native_folder_cases import descriptor, upload_start, word
from native_plan import Action, close, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_FILE_NAME,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_GET_ACCOUNT,
    TYPE_UPLOAD_FILE,
)

# The constants and the file tables come from native_agreement_data, and
# field_overflow from native_agreement_overflow. The verifiers and the
# preparation script import these names from this module: verify_native_agreements
# imports FILES, NON_TEXT_FILES, ORIGINAL_AGREEMENT_SHA256 and phase;
# prepare_native_cases imports PHASES, cleanup, phase, preflight, restore_stage,
# seed and stages; and the agreement test imports TEXT and phase.
__all__ = [
    "FILES",
    "NON_TEXT_FILES",
    "ORIGINAL_AGREEMENT_SHA256",
    "PHASES",
    "TEXT",
    "cleanup",
    "field_overflow",
    "phase",
    "preflight",
    "restore_stage",
    "seed",
    "staged_file",
    "stages",
]

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

# The Finder type is four bytes, at offsets 44 to 47 of the uploaded body.
FINDER_TYPE_BYTES = 4
FINDER_TYPE_SLICE = slice(44, 48)
TRANSFER_TIMEOUT_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 10
SETTLE_SECONDS = 2
PAUSE_SECONDS = 3
# The identifier of the first uploaded file; the others follow it in order.
FIRST_UPLOAD_ID = 20


class RestorationError(ValueError):
    """The data offered for restoration is not the retained original agreement."""

    def __init__(self) -> None:
        """Set the message of the refusal."""
        super().__init__("Restoration requires the retained original agreement")


class FinderTypeError(ValueError):
    """The Finder type of an uploaded file is not four bytes long."""

    def __init__(self) -> None:
        """Set the message of the refusal."""
        super().__init__("Finder type must contain four bytes")


class UnknownPhaseError(ValueError):
    """The requested agreement phase is not one of the known phases."""

    def __init__(self) -> None:
        """Set the message of the refusal."""
        super().__init__("Unknown agreement phase")


def restore_stage(data: bytes) -> Cases:
    """Plan the restoration of the retained original agreement.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one restoration case, by its label.

    Raises
    ------
    RestorationError
        If ``data`` is not the retained original agreement.
    """
    if hashlib.sha256(data).hexdigest() != ORIGINAL_AGREEMENT_SHA256:
        raise RestorationError
    return {
        "stage-agreement-restored": staged_file(
            b"m-agr-restored", b"Agreement.txt", b"TEXT", data
        )
    }


def staged_file(root: bytes, filename: bytes, kind: bytes, data: bytes) -> Case:
    """Upload a correctly named child so Finder need only move/replace it.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps that upload the file into the folder, and its expectation.

    Raises
    ------
    FinderTypeError
        If the Finder type is not four bytes long.
    """
    if len(kind) != FINDER_TYPE_BYTES:
        raise FinderTypeError
    body = bytearray(file_stream(data, b""))
    body[FINDER_TYPE_SLICE] = kind
    steps = [
        *upload_start(root, 1, len(body)),
        send(descriptor((filename,), directory=False).hex(), "folder"),
        word(1),
        send((len(body).to_bytes(4, "big") + body).hex(), "folder"),
        {
            "op": "read_eof",
            "connection": "folder",
            "timeout": TRANSFER_TIMEOUT_SECONDS,
            "expect_hex": "",
        },
        close("folder"),
        {"op": "pause", "seconds": SETTLE_SECONDS},
        close("a"),
    ]
    return steps, {
        "kind": "agreement-staged-file",
        "root_hex": root.hex(),
        "filename_hex": filename.hex(),
        "finder_type_hex": kind.hex(),
        "data_hex": data.hex(),
    }


def stages() -> Cases:
    """Plan the staged agreement files and the staged directory.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The staging case of each file, then the staged directory, by label.
    """
    cases: Cases = {
        "stage-agreement-" + name: staged_file(
            b"m-agr-" + name.encode(), b"Agreement.txt", kind, data
        )
        for name, (_, kind, data) in (FILES | NON_TEXT_FILES).items()
    }
    cases["stage-agreement-directory"] = (
        [
            *upload_start(b"m-agr-directory", 1, 0),
            send(descriptor((b"Agreement.txt",), directory=True).hex(), "folder"),
            word(3),
            eof("folder"),
            close("folder"),
            close("a"),
        ],
        {"kind": "agreement-staged-directory"},
    )
    return cases


def preflight() -> Cases:
    """Plan the check that the bypass account is absent before seeding.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one preflight case, by its label.
    """
    return {
        "preflight-bypass-absence": (
            [
                *login(),
                send(
                    packet(
                        TYPE_GET_ACCOUNT,
                        10,
                        payload([(FIELD_LOGIN, b"m-auth-bypass")]),
                    )
                ),
                read(),
                close(),
            ],
            {"kind": "agreement-account-preflight"},
        )
    }


def seed() -> Cases:
    """Plan the bypass account and the upload of each agreement file.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one seeding case, by its label.
    """
    steps = [
        *login(),
        send(
            packet(
                TYPE_CREATE_ACCOUNT,
                10,
                payload([
                    (FIELD_LOGIN, complement(b"m-auth-bypass")),
                    (FIELD_PASSWORD, complement(PASSWORD)),
                    (FIELD_NAME, b"Agreement bypass"),
                    (FIELD_ACCESS_BITMAP, bytes.fromhex("0000003000000000")),
                ]),
            )
        ),
        read(),
    ]
    for identifier, (filename, kind, data) in enumerate(
        FILES.values(), FIRST_UPLOAD_ID
    ):
        body = bytearray(file_stream(data, b""))
        body[FINDER_TYPE_SLICE] = kind
        variable = f"ref{identifier}"
        steps += [
            send(
                packet(
                    TYPE_UPLOAD_FILE,
                    identifier,
                    payload([
                        (FIELD_FILE_NAME, filename),
                        (FIELD_TRANSFER_SIZE, len(body).to_bytes(4, "big")),
                    ]),
                )
            ),
            read(
                match_frame={"is_reply": 1, "id": identifier},
                save_field={"name": variable, "id": FIELD_TRANSFER_REFERENCE},
            ),
            {
                "op": "connect",
                "connection": variable,
                "endpoint": "data",
                "timeout": CONNECT_TIMEOUT_SECONDS,
            },
            {
                "op": "send",
                "connection": variable,
                "hex": HTXF_MAGIC_HEX
                + "{"
                + variable
                + "}"
                + len(body).to_bytes(4, "big").hex()
                + "00000000"
                + body.hex(),
                "timeout": TRANSFER_TIMEOUT_SECONDS,
            },
            {
                "op": "read_eof",
                "connection": variable,
                "timeout": TRANSFER_TIMEOUT_SECONDS,
                "expect_hex": "",
            },
            close(variable),
        ]
    steps += [{"op": "pause", "seconds": PAUSE_SECONDS}, close()]
    return {"seed-agreement-files": (steps, {"kind": "agreement-seed"})}


def phase(name: str) -> Cases:
    """Plan the login states of one agreement phase.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The early and delayed cases of the phase, by label.

    Raises
    ------
    UnknownPhaseError
        If ``name`` is not a known agreement phase.
    """
    if name not in PHASES:
        raise UnknownPhaseError
    if name.endswith("field-over-limit"):
        return field_overflow(name)
    return {
        name + "-" + label: (steps, {**expected, "phase": name})
        for label, (steps, expected) in auth_states().items()
        if label in {"early-admin", "delayed-admin", "early-bypass", "delayed-bypass"}
    }


def cleanup() -> Cases:
    """Plan the removal of the bypass account and its readback.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one cleanup case, by its label.
    """
    return {
        "remove-agreement-bypass-account": (
            [
                *login(),
                send(
                    packet(
                        TYPE_DELETE_ACCOUNT,
                        10,
                        payload([(FIELD_LOGIN, complement(b"m-auth-bypass"))]),
                    )
                ),
                read(),
                send(
                    packet(
                        TYPE_GET_ACCOUNT,
                        11,
                        payload([(FIELD_LOGIN, b"m-auth-bypass")]),
                    )
                ),
                read(),
                close(),
            ],
            {"kind": "agreement-account-cleanup"},
        )
    }
