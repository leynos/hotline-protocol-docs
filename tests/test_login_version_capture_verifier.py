"""Exercise retained GAP-016 login verification with falsified corpus copies."""

import importlib.util
import json
import shutil
import typing as typ
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-24/login-version-presence-01"
VERIFIER = SOURCE / "verify.py"
type Corpus = tuple[ModuleType, Path]
type Mutation = tuple[str, tuple[str | int, ...], object, str]
type WireMutation = tuple[str, str, int, int, bool, str]


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
        "login_version_capture_verifier", VERIFIER
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


def comparison(copied: Path) -> list[dict[str, typ.Any]]:
    """Read the stream comparison records.

    Returns
    -------
    list[dict[str, typing.Any]]
        The parsed stream comparisons.
    """
    return [
        json.loads(line)
        for line in (copied / "stream-comparison.jsonl").read_text().splitlines()
    ]


def save_comparison(copied: Path, records: list[dict[str, typ.Any]]) -> None:
    """Write falsified stream comparisons in the disposable corpus."""
    (copied / "stream-comparison.jsonl").write_text(
        "\n".join(json.dumps(item) for item in records) + "\n"
    )


def falsify_login_wire(copied: Path, mutation: WireMutation) -> None:
    """Change one request byte in both copied report and copied plan."""
    case = mutation[0]
    report_path = f"captures/{case}/report.json"
    report = record(copied, report_path)
    sent = next(
        e for e in report["events"] if e["event"] == "send" and e["action"] == 3
    )
    wire = bytearray.fromhex(sent["hex"])
    at = wire.find(bytes.fromhex(mutation[1]))
    assert at >= 0, f"the retained request must contain marker {mutation[1]}"
    wire[at + mutation[2]] = (
        wire[at + mutation[2]] ^ mutation[3] if mutation[4] else mutation[3]
    )
    sent["hex"] = wire.hex()
    save(copied, report_path, report)
    plan = record(copied, f"captures/{case}/plan.json")
    plan["steps"][3]["hex"] = wire.hex()
    save(copied, f"captures/{case}/plan.json", plan)


def test_retained_copy_replays(
    corpus: Corpus, capsys: pytest.CaptureFixture[str]
) -> None:
    """The complete retained corpus keeps its recorded success verdict."""
    module, _ = corpus
    module.replay()
    assert capsys.readouterr().out == (
        "Verified four same-account login version cases at both packet boundaries\n"
    ), "retained replay verdict changed"


def test_require_accepts_and_rejects(corpus: Corpus) -> None:
    """The primitive guard preserves its failure message."""
    module, _ = corpus
    assert module.require(condition=True, message="unused") is None, (
        "a true guard should return normally"
    )
    with pytest.raises(ValueError, match=r"^false invariant$"):
        module.require(condition=False, message="false invariant")


def test_replay_rejects_planner_identity(corpus: Corpus) -> None:
    """The manifest must identify the captured planner commit."""
    module, copied = corpus
    manifest = record(copied, "manifest.json")
    manifest["planner_commit"] = "0" * 40
    save(copied, "manifest.json", manifest)
    with pytest.raises(ValueError, match=r"^different planner$"):
        module.replay()


def test_replay_rejects_case_inventory(corpus: Corpus) -> None:
    """The manifest must list exactly the four retained captures."""
    module, copied = corpus
    manifest = record(copied, "manifest.json")
    manifest["cases"].pop()
    save(copied, "manifest.json", manifest)
    with pytest.raises(ValueError, match=r"^case inventory$"):
        module.replay()


def test_replay_rejects_namespace_isolation(corpus: Corpus) -> None:
    """An unexpected route invalidates the isolated network receipt."""
    module, copied = corpus
    (copied / "ns-route.json").write_text('[{"dst": "default"}]\n')
    with pytest.raises(ValueError, match=r"^namespace isolation$"):
        module.replay()


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            ("plan.json", ("gap_ids",), ["GAP-011"], "case environment"),
            id="case-environment",
        ),
        pytest.param(
            ("report.json", ("status",), "failed", "capture identity"),
            id="capture-status",
        ),
        pytest.param(
            ("report.json", ("oracle_sha256",), "0" * 64, "capture identity"),
            id="oracle-identity",
        ),
        pytest.param(
            (
                "report.json",
                ("driver_identity", "dirty"),
                ["verify.py"],
                "capture identity",
            ),
            id="dirty-capture",
        ),
        pytest.param(
            ("report.json", ("frames", 0, "fields", 0, "hex"), "00bf", "reply fields"),
            id="reply-fields",
        ),
        pytest.param(
            ("report.json", ("frames", 0, "error"), 1, "reply correlation"),
            id="reply-correlation",
        ),
    ],
)
def test_replay_rejects_falsified_case_record(
    corpus: Corpus,
    monkeypatch: pytest.MonkeyPatch,
    mutation: Mutation,
) -> None:
    """Each retained case field has its own expected replay guard."""
    module, copied = corpus
    filename, keys, value, reason = mutation
    path = f"captures/version-absent/{filename}"
    changed = record(copied, path)
    target: typ.Any = changed
    for key in keys[:-1]:
        target = target[key]
    target[keys[-1]] = value
    save(copied, path, changed)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    with pytest.raises(ValueError, match=rf"^{reason}$"):
        module.replay()


def test_replay_rejects_planned_login_bytes(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A changed planned login request fails before field interpretation."""
    module, copied = corpus
    path = "captures/version-absent/plan.json"
    plan = record(copied, path)
    plan["steps"][3]["hex"] = "ff" + plan["steps"][3]["hex"][2:]
    save(copied, path, plan)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    with pytest.raises(ValueError, match=r"^planned login bytes$"):
        module.replay()


def test_replay_rejects_socket_endpoint(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A different forward port cannot certify the isolated session."""
    module, copied = corpus
    path = "captures/version-absent/report.json"
    report = record(copied, path)
    connect = next(e for e in report["events"] if e["event"] == "connect")
    connect["peer_address"][1] = 16141
    save(copied, path, report)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    with pytest.raises(ValueError, match=r"^socket endpoints$"):
        module.replay()


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("consumed", "driver read boundary"),
        ("received_bytes", "wire response stream"),
        ("received_sha256", "response differs"),
        ("unread_hex", "unread bytes"),
    ],
)
def test_replay_rejects_stream_comparison(
    corpus: Corpus, change: str, reason: str
) -> None:
    """The consumed length, response and unread tail remain pinned."""
    module, copied = corpus
    rows = comparison(copied)
    row = next(r for r in rows if r["case"] == "version-absent")
    match change:
        case "consumed":
            row["consumed"] = 41
        case "unread_hex":
            row["views"]["loopback"][change] = "00"
        case "received_bytes":
            row["views"]["loopback"][change] = 309
        case "received_sha256":
            row["views"]["loopback"][change] = "0" * 64
    save_comparison(copied, rows)
    with pytest.raises(ValueError, match=rf"^{reason}$"):
        module.replay()


def test_replay_rejects_readiness_identity(corpus: Corpus) -> None:
    """A changed guest gate process cannot match the readiness reference."""
    module, copied = corpus
    receipt = record(copied, "readiness.json")
    receipt["version-absent-guest-gate.json"]["receipt"]["pid"] = 0
    save(copied, "readiness.json", receipt)
    with pytest.raises(ValueError, match=r"^readiness identity$"):
        module.replay()


def test_replay_rejects_namespace_address(corpus: Corpus) -> None:
    """A non-loopback interface invalidates the isolated namespace."""
    module, copied = corpus
    address = json.loads((copied / "ns-addr.json").read_text())
    address[0]["ifname"] = "eth0"
    save(copied, "ns-addr.json", address)
    with pytest.raises(ValueError, match=r"^namespace isolation$"):
        module.replay()


@pytest.mark.parametrize(
    "mutation",
    [
        pytest.param(
            ("version-two-zero", "00a000020000", 5, 1, False, "version encoding"),
            id="version-encoding",
        ),
        pytest.param(
            ("version-absent", "006a0008", 1, 107, False, "credential fields"),
            id="credential-field-id",
        ),
        pytest.param(
            ("version-empty", "006a0008", 4, 1, True, "different credentials"),
            id="credential-value",
        ),
    ],
)
def test_replay_rejects_falsified_login_wire(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch, mutation: WireMutation
) -> None:
    """The planned login wire preserves version and credential identity."""
    module, copied = corpus
    falsify_login_wire(copied, mutation)
    monkeypatch.setattr(module, "verify_capture", lambda _path: None)
    with pytest.raises(ValueError, match=rf"^{mutation[5]}$"):
        module.replay()


def test_replay_rejects_wrong_unread_agreement(
    corpus: Corpus, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The unread tail must decode as the recorded field 101 agreement."""
    module, _ = corpus
    original = module.decode_frame
    calls = 0

    def false_agreement(raw: bytes) -> dict[str, typ.Any]:
        """Change only the second decoded field agreement.

        Returns
        -------
        dict[str, typing.Any]
            The decoded frame with one altered field identifier.
        """
        nonlocal calls
        calls += 1
        decoded = original(raw)
        if calls == 2:
            decoded["fields"][0]["id"] = 102
        return decoded

    monkeypatch.setattr(module, "decode_frame", false_agreement)
    with pytest.raises(ValueError, match=r"^unread agreement$"):
        module.replay()
