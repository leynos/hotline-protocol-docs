"""Check the recovered sources and decompiled oracle code of the send-path corpus.

The helpers ``require``, ``code`` and ``includes`` are defined here because the
checks need them; ``verify_native_download_send_path`` imports them, so they
stay importable from that module as before.
"""

import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path


def require(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the condition positionally
    message: str,
) -> None:
    """Raise ``ValueError`` with ``message`` unless ``ok`` holds.

    Parameters
    ----------
    ok : bool
        The condition that must hold.
    message : str
        The text of the error.

    Raises
    ------
    ValueError
        When ``ok`` is false.
    """
    if not ok:
        raise ValueError(message)


def code(report: dict[str, typ.Any], address: str) -> str:
    """Return the decompiled code of a function that the oracle reported.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed oracle report that holds the query.
    address : str
        The address of the function, which is also the query label.

    Returns
    -------
    str
        The code of the function.
    """
    query = next(q for q in report["queries"] if q["label"] == address)
    result = query["result"]
    require(not result["isError"], f"Oracle error at {address}")
    content = result["structuredContent"]
    require(
        content["function"]["address"] == address and not content["truncated"],
        f"Oracle mapping or truncation at {address}",
    )
    return content["code"]


def includes(haystack: str, needles: tuple[str, ...], label: str) -> None:
    """Require that every needle occurs in the haystack.

    Parameters
    ----------
    haystack : str
        The text to search.
    needles : tuple[str, ...]
        The fragments that must occur.
    label : str
        The name of the check, used in the error.
    """
    for needle in needles:
        require(needle in haystack, f"{label}: missing {needle}")


def read_source(corpus: Path, name: str) -> str:
    """Read one recovered source file of the corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    name : str
        The file name within the ``sources`` directory.

    Returns
    -------
    str
        The text of the file.
    """
    return (corpus / "sources" / name).read_text()


def check_sources(corpus: Path) -> None:
    """Check the recovered source files for the fragments that the findings cite.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    includes(
        read_source(corpus, "D-1000acf0.c"),
        ("uVar6 == 0xca", "FUN_100121a0"),
        "202 dispatch",
    )
    includes(
        read_source(corpus, "D-100121a0.c"),
        ("FUN_1002d470", "FUN_1002d7b0", "iVar10 + 0x1c) = 0x19000", "param_1 + 0x38"),
        "202 entry",
    )
    includes(
        read_source(corpus, "D-1000bd20.c"),
        ("FUN_1000e600", "*puVar4 = uVar2"),
        "HTXF attach",
    )
    includes(
        read_source(corpus, "B04-D-1000c200.c"),
        (
            "FUN_1006e040(iVar8)",
            "FUN_1006e1a0(iVar8)",
            "piVar1[7] = piVar1[7] + 0x19000",
            "piVar1[7] = 0x200000",
            "FUN_1006de10(iVar8,uVar4)",
            "FUN_1006e0b0(iVar8)",
            "piVar1[6] = piVar1[6] + uVar3",
        ),
        "Download worker",
    )
    includes(
        read_source(corpus, "B04-D-1002d830.c"), ("FUN_1002e300",), "FILP serializer"
    )


def check_queries(c40: dict[str, typ.Any], c41: dict[str, typ.Any]) -> None:
    """Check the decompiled code of the queried functions for the cited fragments.

    Parameters
    ----------
    c40 : dict[str, typing.Any]
        The parsed oracle report of the C40 run.
    c41 : dict[str, typing.Any]
        The parsed oracle report of the C41 run.
    """
    includes(
        code(c41, "10071650"),
        (
            "OTEnterNotifier",
            "param_1 + 0x3c",
            "puVar3[3] - puVar3[2]",
            "puVar3 = (undefined4 *)*puVar3",
        ),
        "Pending byte count",
    )
    includes(
        code(c41, "10071950"),
        ("param_1 + 0x3c) == 0", "**(int **)(param_1 + 0x3c) == 0", "uVar2 = 1"),
        "Queue readiness",
    )
    includes(
        code(c41, "10070d20"),
        (
            ".glue::OTSnd",
            "if ((int)uVar2 < 0)",
            "uVar2 = 0",
            "if (uVar2 < *(uint *)(param_2 + -4))",
            "*(uint *)(param_2 + -8) = uVar2",
            "*(int *)(param_1 + 0x3c) = param_2 + -0x10",
        ),
        "Partial send queue",
    )
    includes(
        code(c41, "10071770"),
        ("if (bVar1)", "OTAtomicClearBit", "OTAtomicSetBit", "FUN_10028dc0(0x66"),
        "Callback condition",
    )
    includes(
        code(c40, "1002e300"),
        (".glue::PBReadSync", "(short)uVar1 != -0x27", "return local_28"),
        "Fork read",
    )
