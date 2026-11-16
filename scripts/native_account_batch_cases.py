"""Prepare owned sequential account batches and per-item permission controls."""

from native_account_batch_data import (
    EXTRA,
    NEW,
    OWNED,
    PASSWORD,
    ROLES,
    SOURCE_PASSWORD,
    TARGET_PASSWORD,
    TARGETS,
    Plan,
    Spec,
    deletion,
    key,
    padded,
    record,
)
from native_account_batch_specs import specifications
from native_auth_cases import authentication, complement
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, quiet, read
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_DATA,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_DELETE_ACCOUNT,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_ACCOUNT,
    TYPE_LIST_FILES,
)

# Consumers, by name: prepare_native_cases uses the planners and specifications;
# verify_native_account_batches uses specifications, the planners, OWNED and EXTRA;
# the evidence script run-batches.py uses the planners, specifications, OWNED and
# EXTRA; test_native_account_batches uses specifications and cleanup. key, record,
# deletion and padded are re-exported as the planners' helpers.
__all__ = [
    "EXTRA",
    "NEW",
    "OWNED",
    "PASSWORD",
    "ROLES",
    "SOURCE_PASSWORD",
    "TARGETS",
    "TARGET_PASSWORD",
    "batch",
    "cleanup",
    "deletion",
    "finalization",
    "inspect",
    "key",
    "padded",
    "preflight",
    "probe_nul",
    "publish_cleanup",
    "record",
    "remove_publisher",
    "seed",
    "specifications",
    "supplementary_final",
    "supplementary_probe",
    "supplementary_seed",
    "supplementary_spec",
]

SEED_COUNT = 14  # the owned accounts that the seed creates
HANDSHAKE_STEPS = 3  # connect, the handshake request and its reply
LOGIN_REQUEST_STEP = 3  # the login request, which follows the handshake steps
BATCH_REQUEST_TYPE = 349  # the batch request; native_wire_names does not name it
PAUSE_SECONDS = 3  # the pause between the seed and its readback
EMPTY_PATH = b"\0\0"  # a structured path with no components: the count word alone
CLEANUP_MESSAGE = "Cleanup requires a unique observed owned inventory"


def preflight() -> Plan:
    """Plan the preflight reads of the owned accounts before the batches.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the preflight case.
    """
    steps = [
        *login(),
        *exchange(TYPE_ENUMERATE_ACCOUNTS, 10, []),
        *exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, EMPTY_PATH)]),
    ]
    for identifier, label in enumerate(OWNED, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    return [*steps, close()], {"kind": "account-batch-preflight"}


def seed() -> Plan:
    """Plan the creation of the owned accounts and the flush upload.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the seed case.
    """
    steps = login()
    for identifier, label in enumerate(OWNED[:SEED_COUNT], 100):
        access = (
            ROLES[label.removeprefix("actor-")]
            if label.startswith("actor-")
            else bytes(ACCESS_BITMAP_BYTES)
        )
        values = [
            (FIELD_LOGIN, complement(key(label))),
            (FIELD_PASSWORD, complement(PASSWORD)),
            (FIELD_NAME, b"Seed28-" + label.encode()),
            (FIELD_ACCESS_BITMAP, access),
            (FIELD_ACCOUNT_ATTRIBUTE, b"seed28"),
        ]
        steps += [
            *exchange(TYPE_CREATE_ACCOUNT, identifier, values),
            *exchange(TYPE_GET_ACCOUNT, identifier + 100, [(FIELD_LOGIN, key(label))]),
        ]
    steps += upload(80, b"m-b28-seed-flush", EMPTY_PATH)
    return [*steps, {"op": "pause", "seconds": PAUSE_SECONDS}, close()], {
        "kind": "account-batch-seed"
    }


def batch(spec: Spec) -> Plan:
    """Plan the batch request of one case, sent by the case's login role.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the batch case.
    """
    steps = login()
    if spec["role"] != "admin":
        steps[LOGIN_REQUEST_STEP] = authentication(
            key("actor-" + spec["role"]), PASSWORD
        )
    steps += [
        *exchange(BATCH_REQUEST_TYPE, 10, spec["rows"]),
        *exchange(TYPE_EMPTY_ACK, 90, []),
    ]
    return [*steps, quiet(), close()], {
        "kind": "account-batch-mutation",
        "case": spec["case"],
        "role": spec["role"],
    }


def inspect(spec: Spec) -> Plan:
    """Plan the reads of the account names that one case must leave.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the inspection.
    """
    steps = login()
    for identifier, label in enumerate(spec["names"], 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 90, [])
    return [*steps, close()], {
        "kind": "account-batch-inspect",
        "case": spec["case"],
        "names": spec["names"],
    }


def probe_nul() -> Plan:
    """Plan the login as the account whose password is a single NUL byte.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the NUL-password login.
    """
    steps = [
        *login()[:HANDSHAKE_STEPS],
        authentication(key("nul-new"), b"\xff"),
        read(),
        read(),
        read(),
        *exchange(TYPE_EMPTY_ACK, 90, []),
    ]
    return [*steps, quiet(), close()], {"kind": "account-batch-nul-login"}


def finalization() -> Plan:
    """Plan the flush upload and the final reads of the owned accounts.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the final case.
    """
    steps = [*login(), *upload(80, b"m-b28-final-flush", EMPTY_PATH)]
    for identifier, label in enumerate(OWNED, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    return [*steps, *exchange(TYPE_ENUMERATE_ACCOUNTS, 90, []), close()], {
        "kind": "account-batch-final"
    }


def cleanup(existing: list[str]) -> Plan:
    """Plan the deletion of the observed owned accounts and the flush files.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the cleanup case.

    Raises
    ------
    ValueError
        If ``existing`` repeats a label or names a label that is not owned.
    """
    if len(set(existing)) != len(existing) or not set(existing) <= set(OWNED + EXTRA):
        raise ValueError(CLEANUP_MESSAGE)
    steps = login()
    for identifier, label in enumerate(existing, 100):
        steps += exchange(
            TYPE_DELETE_ACCOUNT, identifier, [(FIELD_LOGIN, complement(key(label)))]
        )
    for identifier, name in [
        (20, b"m-b28-seed-flush"),
        (21, b"m-b28-final-flush"),
        (22, b"m-b28-supp-seed-flush"),
        (23, b"m-b28-supp-final-flush"),
    ]:
        steps += exchange(TYPE_DELETE_FILE, identifier, [(FIELD_FILE_NAME, name)])
    steps += [
        *exchange(TYPE_ENUMERATE_ACCOUNTS, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, EMPTY_PATH)]),
    ]
    return [*steps, close()], {"kind": "account-batch-cleanup", "existing": existing}


def supplementary_seed() -> Plan:
    """Plan the creation of the two accounts of the distinct-collision case.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the supplementary seed.
    """
    steps = login()
    for identifier, label in enumerate(EXTRA, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    for identifier, label, password in [
        (10, "clash2-old", SOURCE_PASSWORD),
        (11, "clash2-new", TARGET_PASSWORD),
    ]:
        steps += exchange(
            TYPE_CREATE_ACCOUNT,
            identifier,
            [
                (FIELD_LOGIN, complement(key(label))),
                (FIELD_PASSWORD, complement(password)),
                (FIELD_NAME, b"Distinct28-" + label.encode()),
                (FIELD_ACCESS_BITMAP, bytes(ACCESS_BITMAP_BYTES)),
                (FIELD_ACCOUNT_ATTRIBUTE, b"distinct28"),
            ],
        )
    steps += upload(80, b"m-b28-supp-seed-flush", EMPTY_PATH)
    return [*steps, close()], {"kind": "account-batch-distinct-seed"}


def supplementary_spec() -> Spec:
    """Name the distinct-collision case, whose rename overwrites a password.

    Returns
    -------
    dict[str, typing.Any]
        The case, with its rows and the names of the supplementary accounts.
    """
    return {
        "case": "distinct-rename-collision",
        "role": "admin",
        "rows": [
            (FIELD_DATA, record("clash2-first")),
            (
                FIELD_DATA,
                record(
                    "clash2-new",
                    old="clash2-old",
                    name=b"Distinct overwritten28",
                    password=b"\0",
                ),
            ),
            (FIELD_DATA, record("clash2-last")),
        ],
        "names": EXTRA,
    }


def supplementary_probe(label: str) -> Plan:
    """Plan a login that probes one of the distinct-collision passwords.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the probe named ``label``.
    """
    key_label, password, success = {
        "source": ("clash2-old", SOURCE_PASSWORD, True),
        "destination-source": ("clash2-new", SOURCE_PASSWORD, True),
        "destination-old": ("clash2-new", TARGET_PASSWORD, False),
    }[label]
    steps = [
        *login()[:HANDSHAKE_STEPS],
        authentication(key(key_label), password),
        read(),
    ]
    if success:
        steps += [read(), read(), *exchange(TYPE_EMPTY_ACK, 90, [])]
    return [*steps, quiet(), close()], {
        "kind": "account-batch-distinct-login",
        "case": label,
        "success": success,
    }


def supplementary_final() -> Plan:
    """Plan the flush upload and the final reads of every supplementary account.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the distinct final case.
    """
    steps = [*login(), *upload(80, b"m-b28-supp-final-flush", EMPTY_PATH)]
    for identifier, label in enumerate(OWNED + EXTRA, 100):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, key(label))])
    return [*steps, *exchange(TYPE_ENUMERATE_ACCOUNTS, 90, []), close()], {
        "kind": "account-batch-distinct-final"
    }


def publish_cleanup() -> Plan:
    """Plan the publication of the flush file that the cleanup removes later.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the publish case.
    """
    steps = [*login(), *upload(80, b"m-b28-publish", EMPTY_PATH)]
    steps += [
        *exchange(TYPE_ENUMERATE_ACCOUNTS, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, EMPTY_PATH)]),
    ]
    return [*steps, close()], {"kind": "account-batch-publish"}


def remove_publisher() -> Plan:
    """Plan the removal of the published flush file and the account listing.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]
        The steps and the expectation of the remove case.
    """
    steps = [
        *login(),
        *exchange(TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-b28-publish")]),
    ]
    steps += [
        *exchange(TYPE_ENUMERATE_ACCOUNTS, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, EMPTY_PATH)]),
    ]
    return [*steps, close()], {"kind": "account-batch-remove"}
