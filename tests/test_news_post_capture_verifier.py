"""Exercise retained GAP-016 post verification with falsified corpus copies."""

import importlib.util
import json
import shutil
import typing as typ
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-24/news-post-presence-01"
VERIFIER = SOURCE / "verify.py"
type Corpus = tuple[ModuleType, Path]


@pytest.fixture
def corpus(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Corpus:
    """Load the real verifier against a disposable retained corpus.

    Returns
    -------
    Corpus
        The verifier module and its input copy.
    """
    copied = tmp_path / SOURCE.name
    shutil.copytree(SOURCE, copied)
    spec = importlib.util.spec_from_file_location(
        "news_post_capture_verifier", VERIFIER
    )
    assert spec is not None, "the retained verifier must load as a module"
    assert spec.loader is not None, "the verifier module must have a loader"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "ROOT", copied)
    return module, copied


def record(copied: Path, name: str) -> dict[str, typ.Any]:
    """Read one JSON input from the disposable corpus.

    Returns
    -------
    dict[str, typing.Any]
        The parsed input.
    """
    return json.loads((copied / name).read_text())


def save(copied: Path, name: str, value: dict[str, typ.Any]) -> None:
    """Write one falsified JSON input in the disposable corpus."""
    (copied / name).write_text(json.dumps(value, indent=2) + "\n")


def events(copied: Path, case: str = "334-zero") -> list[dict[str, typ.Any]]:
    """Read the event sequence of one retained session.

    Returns
    -------
    list[dict[str, typing.Any]]
        The recorded events.
    """
    return record(copied, f"captures/{case}/report.json")["events"]


def session_inputs(
    module: ModuleType, copied: Path, case: str
) -> tuple[list[object], dict[str, typ.Any]]:
    """Read the retained packet views and comparison for one case.

    Returns
    -------
    tuple[list[object], dict[str, typing.Any]]
        The packet views and stream comparison.
    """
    views = [module.read_packets(copied / p) for p in ("namespace.pcap", "guest.pcap")]
    comparison = next(
        json.loads(line)
        for line in (copied / "stream-comparison.jsonl").read_text().splitlines()
        if json.loads(line)["case"] == case
    )
    return views, comparison


def test_retained_copy_replays(
    corpus: Corpus, capsys: pytest.CaptureFixture[str]
) -> None:
    """The complete retained corpus keeps its recorded success verdict."""
    module, _ = corpus
    module.replay()
    assert capsys.readouterr().out == (
        "Verified nine native root posts and their article body reads "
        "at both packet boundaries\n"
    ), "retained replay verdict changed"


def test_require_accepts_and_rejects(corpus: Corpus) -> None:
    """The primitive guard returns on truth and preserves a failure reason."""
    module, _ = corpus
    assert module.require(condition=True, reason="unused") is None, (
        "a true guard should return normally"
    )
    with pytest.raises(ValueError, match=r"^false invariant$"):
        module.require(condition=False, reason="false invariant")


def test_load_rejects_missing_json(corpus: Corpus) -> None:
    """Load a retained record and expose a missing input."""
    module, copied = corpus
    assert module.load("manifest.json") == record(copied, "manifest.json"), "manifest"
    with pytest.raises(FileNotFoundError, match=r"missing\.json"):
        module.load("missing.json")


@pytest.mark.parametrize("change", ["declared", "duplicate", "unconsumed"])
def test_fields_rejects_incomplete_boundaries(corpus: Corpus, change: str) -> None:
    """Field count, uniqueness and unconsumed bytes are independent guards."""
    module, copied = corpus
    frame = module.from_wire(events(copied), 7, "send")
    assert module.fields(frame), "the retained field boundary must be complete"
    match change:
        case "declared":
            frame["declared_field_count"] += 1
        case "duplicate":
            frame["fields"].append(frame["fields"][0].copy())
            frame["declared_field_count"] += 1
        case "unconsumed":
            frame["unconsumed_hex"] = "00"
    with pytest.raises(ValueError, match=r"^field boundaries$"):
        module.fields(frame)


def test_from_wire_rejects_missing_and_wrong_action(corpus: Corpus) -> None:
    """A wire action needs fragments of the requested kind and connection."""
    module, copied = corpus
    captured = events(copied)
    assert module.from_wire(captured, 7, "send")["type"] == 371, (
        "the retained send action must be a post"
    )
    with pytest.raises(ValueError, match=r"^action boundary$"):
        module.from_wire(captured, 999, "send")
    with pytest.raises(ValueError, match=r"^action boundary$"):
        module.from_wire(captured, 7, "receive")


def test_pair_rejects_wrong_transaction(corpus: Corpus) -> None:
    """The request and response must correlate to the required transaction."""
    module, copied = corpus
    request, reply = module.pair(events(copied), 7, 371)
    assert request, "the retained request must be present"
    assert reply["is_reply"], "the correlated frame must be a reply"
    with pytest.raises(ValueError, match=r"^correlated reply$"):
        module.pair(events(copied), 7, 410)


def test_pair_rejects_mismatched_reply_id(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reply identifier must match its decoded request."""
    module, copied = corpus
    captured = events(copied)
    request = module.from_wire(captured, 7, "send")
    reply = module.from_wire(captured, 8, "receive")
    replies = (request, {**reply, "id": request["id"] + 1})
    monkeypatch.setattr(module, "from_wire", mock.Mock(side_effect=replies))
    with pytest.raises(ValueError, match=r"^correlated reply$"):
        module.pair(captured, 7, 371)


@pytest.mark.parametrize("change", ["wrong_id", "extra_field"])
def test_listing_requires_single_payload_field(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    """A category listing accepts exactly field 321 on a successful reply."""
    module, copied = corpus
    captured = events(copied)
    path, payload, rows = module.listing(captured, 7)
    assert path, "the retained listing must have a path"
    assert payload, "the retained listing must have a payload"
    assert isinstance(rows, list), "the retained listing must contain rows"
    original_pair = module.pair

    def false_listing(
        items: list[dict[str, typ.Any]], action: int, transaction: int
    ) -> object:
        """Replace the retained category payload identifier.

        Returns
        -------
        object
            The request and altered reply.
        """
        request, reply = original_pair(items, action, transaction)
        altered = {**reply["fields"][0], "id": 322}
        fields = [altered]
        if change == "extra_field":
            fields.insert(0, reply["fields"][0])
        reply = {**reply, "fields": fields, "declared_field_count": len(fields)}
        assert module.fields(reply), "falsified fields must retain valid boundaries"
        return request, reply

    monkeypatch.setattr(module, "pair", false_listing)
    with pytest.raises(ValueError, match=r"^list payload$"):
        module.listing(captured, 7)


def test_check_session_rejects_missing_quiet_close(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The session must end with its recorded quiet and close events."""
    module, copied = corpus
    case = "334-zero"
    views, comparison = session_inputs(module, copied, case)
    assert module.check_session(case, views, comparison), (
        "the retained session must pass before falsification"
    )
    report = record(copied, f"captures/{case}/report.json")
    report["events"][-1]["event"] = "quiet"
    save(copied, f"captures/{case}/report.json", report)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    with pytest.raises(ValueError, match=r"^quiet interval$"):
        module.check_session(case, views, comparison)


def test_check_session_rejects_planned_send(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The planned send bytes must match the recorded send event."""
    module, copied = corpus
    case = "334-zero"
    plan_path = f"captures/{case}/plan.json"
    plan = record(copied, plan_path)
    plan["steps"][7]["hex"] = "ff" + plan["steps"][7]["hex"][2:]
    save(copied, plan_path, plan)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    views, comparison = session_inputs(module, copied, case)
    with pytest.raises(ValueError, match=r"^planned send$"):
        module.check_session(case, views, comparison)


def test_replay_rejects_false_fixture_identity(corpus: Corpus) -> None:
    """An altered planner identity is rejected before session comparisons."""
    module, copied = corpus
    manifest = record(copied, "manifest.json")
    manifest["planner_commit"] = "0" * 40
    save(copied, "manifest.json", manifest)
    with pytest.raises(ValueError, match=r"^fixture identity$"):
        module.replay()


def test_replay_rejects_false_readiness(corpus: Corpus) -> None:
    """A readiness receipt with the wrong identity fails the session gate."""
    module, copied = corpus
    readiness = record(copied, "readiness.json")
    key = next(key for key in readiness if key.endswith("-guest-gate.json"))
    readiness[key]["receipt"]["pid"] = 0
    save(copied, "readiness.json", readiness)
    with pytest.raises(ValueError, match=r"^readiness identity$"):
        module.replay()


def test_replay_rejects_wrong_post_encoding(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The first post must retain its recorded field 334 zero encoding."""
    module, copied = corpus
    case = "334-zero"
    report_path = f"captures/{case}/report.json"
    report = record(copied, report_path)
    sent = next(
        item
        for item in report["events"]
        if item["event"] == "send" and item["action"] == 9
    )
    wire = bytearray.fromhex(sent["hex"])
    marker = bytes.fromhex("014e000400000000")
    at = wire.find(marker)
    assert at >= 0, "the first retained post must contain field 334"
    wire[at + len(marker) - 1] = 1
    sent["hex"] = wire.hex()
    save(copied, report_path, report)
    original = module.check_session

    def altered_session(name: str, views: object, comparison: object) -> object:
        """Return the altered post events for one captured session.

        Returns
        -------
        object
            The selected session events.
        """
        if name == case:
            return events(copied, name)
        return original(name, views, comparison)

    monkeypatch.setattr(module, "check_session", altered_session)
    with pytest.raises(ValueError, match=r"^post encoding$"):
        module.replay()


def test_replay_rejects_dropped_existing_listing(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second post listing must still contain the first accepted row."""
    module, _ = corpus
    original = module.listing
    calls = 0

    def false_listing(items: object, action: int) -> object:
        """Drop the existing row from the second listing.

        Returns
        -------
        object
            The listing tuple with an altered row set.
        """
        nonlocal calls
        calls += 1
        path, payload, rows = original(items, action)
        if calls == 4:
            return path, payload, rows[1:]
        return path, payload, rows

    monkeypatch.setattr(module, "listing", false_listing)
    with pytest.raises(ValueError, match=r"^existing rows preserved$"):
        module.replay()


def test_replay_rejects_false_body_title(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The posted body readback must repeat the listed title."""
    module, _ = corpus
    original = module.pair

    def false_body(items: object, action: int, transaction: int) -> object:
        """Replace the posted body title in its readback.

        Returns
        -------
        object
            The request and altered reply.
        """
        request, reply = original(items, action, transaction)
        if transaction == 400:
            reply = {
                **reply,
                "fields": [
                    {**field, "hex": "00"} if field["id"] == 328 else field
                    for field in reply["fields"]
                ],
            }
        return request, reply

    monkeypatch.setattr(module, "pair", false_body)
    with pytest.raises(ValueError, match=r"^posted body readback$"):
        module.replay()


def test_pair_rejects_duplicate_request(corpus: Corpus) -> None:
    """An extra complete request leaves unconsumed bytes at the pair boundary."""
    module, copied = corpus
    captured = events(copied)
    duplicate = next(
        item for item in captured if item["event"] == "send" and item["action"] == 7
    )
    with pytest.raises(ValueError, match=r"^field boundaries$"):
        module.pair([*captured, duplicate.copy()], 7, 371)


def test_check_session_rejects_login_error(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A non-zero login reply fails the native-login guard."""
    module, copied = corpus
    case = "334-zero"
    views, comparison = session_inputs(module, copied, case)
    original = module.pair

    def false_login(items: object, action: int, transaction: int) -> object:
        """Turn the retained login reply into an error.

        Returns
        -------
        object
            The request and altered reply.
        """
        request, reply = original(items, action, transaction)
        if transaction == 107:
            reply = {**reply, "error": 1}
        return request, reply

    monkeypatch.setattr(module, "pair", false_login)
    with pytest.raises(ValueError, match=r"^native login$"):
        module.check_session(case, views, comparison)
