"""Read complete hexadecimal strace socket I/O without guessing missing bytes."""

import re
from decimal import Decimal

LINE = re.compile(r"^(\d+) (\d+\.\d+) (.*)$")
IO = re.compile(
    r"(read|write)\((\d+)<TCP:\[127\.0\.0\.1:(\d+)->127\.0\.0\.1:(1550[01])\]>, "
    r'"((?:\\x[0-9a-f]{2})*)", (\d+)\) = (\d+)$'
)


def socket_io(trace: str) -> list[dict]:
    """Join per-process unfinished calls; reject truncated TCP read/write text."""
    pending: dict[int, tuple[int, str]] = {}
    records = []
    for line in trace.splitlines():
        match = LINE.fullmatch(line)
        if not match:
            raise ValueError("Unrecognized syscall trace prefix")
        process, stamp, text = match.groups()
        pid, when = int(process), int(Decimal(stamp) * 1_000_000)
        if text.endswith("<unfinished ...>"):
            if pid in pending:
                raise ValueError("Overlapping unfinished syscall")
            pending[pid] = (when, text.removesuffix("<unfinished ...>"))
            continue
        resumed = re.match(r"<\.\.\. (\w+) resumed>(.*)", text)
        if resumed:
            if pid not in pending:
                raise ValueError("Resumed syscall without beginning")
            when, prefix = pending.pop(pid)
            if not prefix.startswith(resumed[1] + "("):
                raise ValueError("Resumed syscall name differs")
            text = prefix + resumed[2]
        match = IO.fullmatch(text)
        if match:
            operation, fd, port, endpoint, raw, requested, actual = match.groups()
            data = bytes.fromhex(raw.replace("\\x", ""))
            count = int(actual)
            if count > int(requested) or len(data) < count:
                raise ValueError("Incomplete TCP syscall bytes")
            if operation == "read" and len(data) != count:
                raise ValueError("Read result and bytes differ")
            records.append(
                {
                    "pid": pid,
                    "fd": int(fd),
                    "client_port": int(port),
                    "server_port": int(endpoint),
                    "timestamp_us": when,
                    "operation": operation,
                    "bytes": data[:count],
                }
            )
        elif "<TCP:" in text and re.match(r"(?:read|write|send\w*|recv\w*)\(", text):
            raise ValueError("Unsupported or incomplete TCP syscall")
    if pending:
        raise ValueError("Unfinished syscalls remain")
    return records
