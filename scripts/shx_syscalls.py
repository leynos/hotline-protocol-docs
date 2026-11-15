"""Read complete hexadecimal strace socket I/O without guessing missing bytes."""

import re
import typing as typ
from decimal import Decimal

type Record = dict[str, typ.Any]
type Pending = dict[int, tuple[int, str]]

LINE = re.compile(r"^(\d+) (\d+\.\d+) (.*)$")
IO = re.compile(
    r"(read|write)\((\d+)<TCP:\[127\.0\.0\.1:(\d+)->127\.0\.0\.1:(\d+)\]>, "
    r'"((?:\\x[0-9a-f]{2})*)", (\d+)\) = (\d+)$'
)
RESUMED = re.compile(r"<\.\.\. (\w+) resumed>(.*)")
TCP_CALL = re.compile(r"(?:read|write|send\w*|recv\w*)\(")
UNFINISHED = "<unfinished ...>"
MICROSECONDS = 1_000_000
DEFAULT_PORTS = frozenset({15500, 15501})  # the fixture's control and data ports


def join_resumed(text: str, pid: int, pending: Pending) -> tuple[int | None, str]:
    """Join a resumed call to its unfinished beginning.

    Returns
    -------
    tuple[int | None, str]
        The time at which the call began, or ``None`` when ``text`` is not a
        resumed call, and the whole text of the call.

    Raises
    ------
    ValueError
        If the call has no beginning or the call names differ.
    """
    resumed = RESUMED.match(text)
    if not resumed:
        return None, text
    if pid not in pending:
        message = "Resumed syscall without beginning"
        raise ValueError(message)
    when, prefix = pending.pop(pid)
    if not prefix.startswith(resumed[1] + "("):
        message = "Resumed syscall name differs"
        raise ValueError(message)
    return when, prefix + resumed[2]


def socket_record(
    match: re.Match[str], when: int, server_ports: frozenset[int]
) -> Record:
    """Turn one complete TCP read or write into a record.

    Returns
    -------
    dict[str, typing.Any]
        The process, descriptor, ports, time, operation and transferred bytes.

    Raises
    ------
    ValueError
        If the endpoint is not a fixture port or the bytes are incomplete.
    """
    operation, fd, port, endpoint, raw, requested, actual = match.groups()
    if int(endpoint) not in server_ports:
        message = "Unexpected TCP fixture endpoint"
        raise ValueError(message)
    data = bytes.fromhex(raw.replace("\\x", ""))
    count = int(actual)
    if count > int(requested) or len(data) < count:
        message = "Incomplete TCP syscall bytes"
        raise ValueError(message)
    if operation == "read" and len(data) != count:
        message = "Read result and bytes differ"
        raise ValueError(message)
    return {
        "fd": int(fd),
        "client_port": int(port),
        "server_port": int(endpoint),
        "timestamp_us": when,
        "operation": operation,
        "bytes": data[:count],
    }


def split_line(line: str) -> tuple[int, int, str]:
    """Split a trace line into its process, its time in microseconds and its text.

    Returns
    -------
    tuple[int, int, str]
        The process ID, the time and the call text.

    Raises
    ------
    ValueError
        If the line has no process and time prefix.
    """
    match = LINE.fullmatch(line)
    if not match:
        message = "Unrecognized syscall trace prefix"
        raise ValueError(message)
    process, stamp, text = match.groups()
    return int(process), int(Decimal(stamp) * MICROSECONDS), text


def socket_io(
    trace: str, *, server_ports: frozenset[int] = DEFAULT_PORTS
) -> list[Record]:
    """Join per-process unfinished calls; reject truncated TCP read/write text.

    Returns
    -------
    list[dict[str, typing.Any]]
        One record for each complete TCP read or write, in trace order.

    Raises
    ------
    ValueError
        If the trace has an unrecognized line, an overlapping or unfinished
        call, or a TCP call whose bytes cannot be read completely.
    """
    pending: Pending = {}
    records = []
    for line in trace.splitlines():
        pid, when, text = split_line(line)
        if text.endswith(UNFINISHED):
            if pid in pending:
                message = "Overlapping unfinished syscall"
                raise ValueError(message)
            pending[pid] = (when, text.removesuffix(UNFINISHED))
            continue
        began, text = join_resumed(text, pid, pending)
        match = IO.fullmatch(text)
        if match:
            record = socket_record(
                match, when if began is None else began, server_ports
            )
            records.append({"pid": pid, **record})
        elif "<TCP:" in text and TCP_CALL.match(text):
            message = "Unsupported or incomplete TCP syscall"
            raise ValueError(message)
    if pending:
        message = "Unfinished syscalls remain"
        raise ValueError(message)
    return records
