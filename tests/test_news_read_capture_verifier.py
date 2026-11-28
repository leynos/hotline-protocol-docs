"""Falsified copies guard the retained GAP-016 article-read verifier."""

import importlib.util
import json
import shutil
import typing as typ
from pathlib import Path
from types import ModuleType

import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-24/news-read-presence-01"
VERIFIER = SOURCE / "verify.py"
type ReplayCopy = tuple[ModuleType, Path]


@pytest.fixture
def replay_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> ReplayCopy:
    """Load the real verifier against a disposable copy of its corpus.

    Returns
    -------
    ReplayCopy
        The loaded verifier and its copied corpus.
    """
    corpus = tmp_path / "news-read-presence-01"
    shutil.copytree(SOURCE, corpus)
    spec = importlib.util.spec_from_file_location(
        "news_read_presence_verifier", VERIFIER
    )
    assert spec is not None, "the retained verifier must be loadable"
    assert spec.loader is not None, "the retained verifier needs a file loader"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", corpus)
    return module, corpus


def read_json(corpus: Path, path: str) -> dict[str, typ.Any]:
    """Read one record from the disposable corpus.

    Returns
    -------
    dict[str, typing.Any]
        The parsed record.
    """
    return json.loads((corpus / path).read_text())


def write_json(corpus: Path, path: str, value: dict[str, typ.Any]) -> None:
    """Write a falsified record only inside the disposable corpus."""
    (corpus / path).write_text(json.dumps(value, indent=2) + "\n")


def read_case(
    module: ModuleType, corpus: Path, case: str
) -> tuple[dict[str, typ.Any], dict[str, typ.Any], dict[str, typ.Any]]:
    """Load the case and listed reference needed by ``check_read``.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any]]
        The report, plan and decoded reference request.
    """
    report = read_json(corpus, f"captures/{case}/report.json")
    plan = read_json(corpus, f"captures/{case}/plan.json")
    reference_plan = read_json(corpus, "captures/334-absent/plan.json")
    reference = module.decode_frame(bytes.fromhex(reference_plan["steps"][7]["hex"]))
    return report, plan, reference


def test_retained_copy_replays_successfully(
    replay_copy: ReplayCopy, capsys: pytest.CaptureFixture[str]
) -> None:
    """The unmodified copied corpus yields the pinned success verdict."""
    module, _ = replay_copy
    module.replay()
    assert capsys.readouterr().out == (
        "Verified nine native article reads at both packet boundaries\n"
    ), "the retained corpus must yield the pinned success line"


def test_require_rejects_false_predicates(replay_copy: ReplayCopy) -> None:
    """A failed verifier predicate reports its own reason."""
    module, _ = replay_copy
    with pytest.raises(ValueError, match=r"^sample reason$"):
        module.require(ok=False, reason="sample reason")


def test_check_read_returns_retained_payload(replay_copy: ReplayCopy) -> None:
    """A valid read returns the decoded reply payload for comparison."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "326-absent")
    assert (
        module.check_read("326-absent", report, plan, reference)
        == report["frames"][3]["payload_hex"]
    ), "check_read must return the decoded reply payload"


def test_check_read_rejects_wrong_planned_byte(replay_copy: ReplayCopy) -> None:
    """The planned request must equal the sent request."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "326-absent")
    plan["steps"][7]["hex"] = "01" + plan["steps"][7]["hex"][2:]
    with pytest.raises(ValueError, match=r"^planned bytes$"):
        module.check_read("326-absent", report, plan, reference)


def test_check_read_rejects_changed_request_field(replay_copy: ReplayCopy) -> None:
    """A changed field byte is rejected after the two request views agree."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "334-absent")
    event = next(
        event
        for event in report["events"]
        if event["event"] == "send" and event["action"] == 7
    )
    wire = bytearray.fromhex(event["hex"])
    at = wire.index(b"text/plain")
    wire[at] = ord("T")
    event["hex"] = wire.hex()
    plan["steps"][7]["hex"] = wire.hex()
    with pytest.raises(ValueError, match=r"^read fields$"):
        module.check_read("334-absent", report, plan, reference)


def test_check_read_rejects_changed_article_error(replay_copy: ReplayCopy) -> None:
    """A coherent but false reply transcript cannot change the 326 error text."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "326-absent")
    events = [
        event
        for event in report["events"]
        if event["event"] == "receive" and event["action"] == 8
    ]
    sizes = [len(bytes.fromhex(event["hex"])) for event in events]
    wire = bytearray.fromhex("".join(event["hex"] for event in events))
    at = wire.index(b"Cannot get article")
    wire[at] = ord("D")
    offset = 0
    for event, size in zip(events, sizes, strict=True):
        event["hex"] = wire[offset : offset + size].hex()
        offset += size
    report["frames"][3].update(module.decode_frame(wire))
    with pytest.raises(ValueError, match=r"^article error$"):
        module.check_read("326-absent", report, plan, reference)


def test_check_read_requires_quiet_close(replay_copy: ReplayCopy) -> None:
    """The retained session must end with both quiet and close events."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "326-absent")
    report["events"][-1]["event"] = "quiet"
    with pytest.raises(ValueError, match=r"^quiet and close$"):
        module.check_read("326-absent", report, plan, reference)


def test_check_read_rejects_wrong_session_sequence(replay_copy: ReplayCopy) -> None:
    """A reordered reply sequence fails after each frame still decodes."""
    module, corpus = replay_copy
    report, plan, reference = read_case(module, corpus, "326-absent")
    report["frames"][3], report["frames"][4] = (
        report["frames"][4],
        report["frames"][3],
    )
    with pytest.raises(ValueError, match=r"^session sequence$"):
        module.check_read("326-absent", report, plan, reference)


@pytest.mark.parametrize(
    ("path", "mutate", "reason"),
    [
        (
            "manifest.json",
            lambda value: value["cases"].pop(),
            "case inventory",
        ),
        (
            "manifest.json",
            lambda value: value["installed_forks"].update({
                "native-app-4352-0": "0" * 64
            }),
            "installed forks",
        ),
        (
            "readiness.json",
            lambda value: value["326-absent-guest-gate.json"]["receipt"].update({
                "pid": 0
            }),
            "readiness identity",
        ),
    ],
)
def test_replay_rejects_false_guard_records(
    replay_copy: ReplayCopy,
    path: str,
    mutate: cabc.Callable[[dict[str, typ.Any]], object],
    reason: str,
) -> None:
    """Inventory, fork identity and readiness assertions reject false records."""
    module, corpus = replay_copy
    value = read_json(corpus, path)
    mutate(value)
    write_json(corpus, path, value)
    with pytest.raises(ValueError, match=rf"^{reason}$"):
        module.replay()


@pytest.mark.parametrize("change", ["received_sha256", "received_bytes"])
def test_replay_rejects_false_stream_comparison(
    replay_copy: ReplayCopy, change: str
) -> None:
    """A one-record stream count or digest mismatch fails packet comparison."""
    module, corpus = replay_copy
    path = corpus / "stream-comparison.jsonl"
    lines = [json.loads(line) for line in path.read_text().splitlines()]
    lines[0]["views"]["loopback"][change] = (
        "0" * 64 if change == "received_sha256" else 0
    )
    path.write_text("\n".join(json.dumps(line) for line in lines) + "\n")
    with pytest.raises(ValueError, match=r"^stream comparison$"):
        module.replay()


@pytest.mark.parametrize("boundary", ["guest", "namespace"])
def test_replay_rejects_changed_wire_byte(
    replay_copy: ReplayCopy, boundary: str
) -> None:
    """A changed packet payload byte breaks either retained stream."""
    module, corpus = replay_copy
    report = read_json(corpus, "captures/326-absent/report.json")
    request = bytes.fromhex(
        next(
            event["hex"]
            for event in report["events"]
            if event["event"] == "send" and event["action"] == 7
        )
    )
    path = corpus / f"{boundary}.pcap"
    pcap = bytearray(path.read_bytes())
    offsets = []
    start = 0
    while (at := pcap.find(request, start)) >= 0:
        offsets.append(at)
        start = at + len(request)
    assert offsets, "the retained request must occur in the guest capture"
    for at in offsets:
        pcap[at + len(request) - 1] ^= 1
    path.write_bytes(pcap)
    with pytest.raises(ValueError, match=r"^wire stream$"):
        module.replay()
