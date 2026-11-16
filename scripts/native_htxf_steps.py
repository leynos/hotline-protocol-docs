"""Plan the sessions, requests and data connections that the HTXF cases share.

The header words, the low-privilege observer and the banner read are built
here; native_htxf_cases and native_htxf_banners compose the cases.
"""

import typing as typ

from native_banner_cases import GIF_B
from native_folder_cases import ROOT
from native_plan import (
    COMPLEMENT_MASK,
    Action,
    connect,
    packet,
    payload,
    read,
    send,
)
from native_queue_cases import FORK_FIXTURE, Case, session
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_VERSION,
    HTXF_MAGIC_HEX,
    SELECTOR_BANNER,
    TYPE_DOWNLOAD_BANNER,
    TYPE_DOWNLOAD_FILE,
    TYPE_DOWNLOAD_FOLDER,
    TYPE_LOGIN,
)

type Cases = dict[str, Case]

LOGIN_STEP = 3  # the login request that follows the handshake steps
REQUEST_ID = 10
FOLLOWUP_ID = 11
PUMP_ID = 90  # the empty requests that flush the owners' queues
LOW_PUMP_ID = 91
LOW_FINAL_PUMP_ID = 92
SELECTOR_ANY = 65535
RESERVED_ANY = 65535
SIZE_ANY = 0xFFFFFFFF
READ_SECONDS = 30
QUIET_SECONDS = 3
SIZE_BYTES = 4
FOLDER_SELECTORS = [0, 2, 65535]
UPLOAD_SELECTOR_PADDING = 37  # extra advertised bytes in the selector-0 upload


class HeaderOptions(typ.TypedDict, total=False):
    """The words of an HTXF header that a case may set."""

    selector: int
    size: int
    reserved: int
    reference: str
    magic: str


def low_session() -> list[Action]:
    """Plan a login of a low-privilege observer on connection ``b``.

    Returns
    -------
    list[native_plan.Action]
        The session steps with the login replaced by the observer's.
    """
    steps = session("b")
    fields = [
        (FIELD_LOGIN, bytes(v ^ COMPLEMENT_MASK for v in b"fixture-low")),
        (FIELD_PASSWORD, bytes(v ^ COMPLEMENT_MASK for v in b"next-pass")),
        (FIELD_VERSION, b"\0\xbe"),
        (FIELD_NAME, b"htxf-low"),
        (FIELD_ICON, b"\0\1"),
    ]
    steps[LOGIN_STEP] = send(packet(TYPE_LOGIN, 1, payload(fields)), "b")
    return steps


def request(kind: int = TYPE_DOWNLOAD_BANNER) -> list[Action]:
    """Plan a request for a transfer and the read of its reference and size.

    Returns
    -------
    list[native_plan.Action]
        The send of the request of type ``kind`` and the reply read.
    """
    names = {TYPE_DOWNLOAD_FILE: FORK_FIXTURE, TYPE_DOWNLOAD_FOLDER: ROOT}
    values = [(FIELD_FILE_NAME, names[kind])] if kind in names else []
    return [
        send(packet(kind, REQUEST_ID, payload(values)), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_fields={"ref": FIELD_TRANSFER_REFERENCE, "size": FIELD_TRANSFER_SIZE},
        ),
    ]


def header(**options: typ.Unpack[HeaderOptions]) -> str:
    """Encode an HTXF header as hexadecimal.

    Returns
    -------
    str
        The magic, reference, size, selector and reserved words.
    """
    magic = options.get("magic", HTXF_MAGIC_HEX)
    reference = options.get("reference", "{ref}")
    size = options.get("size", 0)
    selector = options.get("selector", SELECTOR_BANNER)
    reserved = options.get("reserved", 0)
    return magic + reference + f"{size:08x}{selector:04x}{reserved:04x}"


def attach(name: str, **options: typ.Unpack[HeaderOptions]) -> list[Action]:
    """Plan a data connection that sends an HTXF header.

    Returns
    -------
    list[native_plan.Action]
        The connect and the send of the header.
    """
    return [connect(name, "data"), send(header(**options), name)]


def data(name: str) -> list[Action]:
    """Plan reading the banner image on a data connection.

    Returns
    -------
    list[native_plan.Action]
        A read of exactly the banner bytes, which must equal them.
    """
    return [
        {
            "op": "read",
            "connection": name,
            "size": len(GIF_B),
            "expect_hex": GIF_B.hex(),
            "timeout": READ_SECONDS,
        }
    ]


def quiet(name: str) -> Action:
    """Plan a bounded silence on a data connection.

    Returns
    -------
    native_plan.Action
        The ``expect_quiet`` action.
    """
    return {"op": "expect_quiet", "connection": name, "timeout": QUIET_SECONDS}
