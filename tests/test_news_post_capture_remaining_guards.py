"""Falsify retained post-verifier guards on disposable offline inputs."""

import copy
import importlib.util
import json
import shutil
import typing as typ
from pathlib import Path
from types import ModuleType
from unittest import mock

import pytest
from test_news_post_capture_properties import retained_events, verifier

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-24/news-post-presence-01"
type Corpus = tuple[ModuleType, Path]


@pytest.fixture
def corpus(tmp_path: Path) -> Corpus:
    """Load the real verifier against a private copy of its inputs.

    Returns
    -------
    Corpus
        The verifier and its disposable corpus directory.
    """
    copied = tmp_path / SOURCE.name
    shutil.copytree(SOURCE, copied)
    spec = importlib.util.spec_from_file_location(
        "post_remaining_guards", SOURCE / "verify.py"
    )
    assert spec is not None, "retained verifier import"
    assert spec.loader is not None, "retained verifier loader"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.__dict__["ROOT"] = copied
    return module, copied


def read(path: Path) -> dict[str, typ.Any]:
    """Read one disposable JSON record.

    Returns
    -------
    dict[str, typing.Any]
        Parsed record.
    """
    return json.loads(path.read_text())


def write(path: Path, value: dict[str, typ.Any]) -> None:
    """Write one changed JSON record in the disposable corpus."""
    path.write_text(json.dumps(value, indent=2) + "\n")


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("capture", "capture identity"),
        ("environment", "case environment"),
        ("forward", "isolated forward"),
        ("frame", "reported frame bytes"),
    ],
)
def test_session_rejects_false_receipt(
    corpus: Corpus, change: str, reason: str
) -> None:
    """Each identity or decoded-frame claim is checked before success."""
    module, copied = corpus
    folder = copied / "captures/334-zero"
    report = read(folder / "report.json")
    plan = read(folder / "plan.json")
    match change:
        case "capture":
            report["status"] = "failed"
        case "environment":
            plan["gap_ids"] = []
        case "forward":
            connect = next(e for e in report["events"] if e["event"] == "connect")
            connect["peer_address"][1] = 16141
        case _:
            report["frames"][0]["error"] = 1
    write(folder / "report.json", report)
    write(folder / "plan.json", plan)
    views = [
        module.read_packets(copied / name) for name in ("namespace.pcap", "guest.pcap")
    ]
    comparison = next(
        json.loads(line)
        for line in (copied / "stream-comparison.jsonl").read_text().splitlines()
        if json.loads(line)["case"] == "334-zero"
    )
    with (
        mock.patch.object(module, "verify_capture", return_value=None),
        pytest.raises(ValueError, match=rf"^{reason}$"),
    ):
        module.check_session("334-zero", views, comparison)


def test_session_rejects_false_liveness(corpus: Corpus) -> None:
    """A liveness barrier with an error cannot validate the session."""
    module, copied = corpus
    original_pair = module.pair

    def false_pair(
        events: list[dict[str, typ.Any]], action: int, transaction: int
    ) -> object:
        """Set an error only on the liveness reply.

        Returns
        -------
        object
            The request and altered or original reply.
        """
        request, reply = original_pair(events, action, transaction)
        if transaction == 500:
            reply = {**reply, "error": 1}
        return request, reply

    views = [
        module.read_packets(copied / name) for name in ("namespace.pcap", "guest.pcap")
    ]
    comparison = next(
        json.loads(line)
        for line in (copied / "stream-comparison.jsonl").read_text().splitlines()
        if json.loads(line)["case"] == "334-zero"
    )
    with (
        mock.patch.object(module, "pair", side_effect=false_pair),
        pytest.raises(ValueError, match=r"^liveness$"),
    ):
        module.check_session("334-zero", views, comparison)


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("installed", "installed application"),
        ("retirement", "retirement"),
        ("host", "host boundary"),
        ("namespace", "isolated namespace"),
        ("inventory", "capture inventory"),
        ("historical", "historical post control"),
        ("category_fork", "stopped category data fork"),
    ],
)
def test_replay_rejects_false_environment(
    corpus: Corpus, change: str, reason: str
) -> None:
    """Fixture, inventory, and stopped-fork claims have distinct guards."""
    module, copied = corpus
    manifest_path = copied / "manifest.json"
    manifest = read(manifest_path)
    match change:
        case "installed":
            manifest["installed_forks"]["native-app-4352-0"] = "0" * 64
        case "retirement":
            manifest["disk_fuser_exit"] = 0
        case "host":
            manifest["network_statistics"]["host"]["captured"] = 1
        case "namespace":
            (copied / "ns-route.json").write_text('[{"dst": "default"}]\n')
        case "inventory":
            manifest["cases"].remove("334-zero")
        case "historical":
            historical = copied / "reference-post.json"
            record = read(historical)
            record["action"] += 1
            write(historical, record)
        case "category_fork":
            with (copied / "final-category.data").open("ab") as output:
                output.write(b"\x00")
    write(manifest_path, manifest)
    with pytest.raises(ValueError, match=rf"^{reason}$"):
        module.replay()


def test_replay_rejects_false_comparison_inventory(corpus: Corpus) -> None:
    """The configured target-shape product must match the retained order."""
    module, _ = corpus
    module.__dict__["TARGETS"] = (326,)
    with pytest.raises(ValueError, match=r"^comparison inventory$"):
        module.replay()


def test_replay_rejects_false_fixed_post_fields() -> None:
    """Changing a non-target post field fails before post-shape checking."""
    module = verifier()
    cases = retained_events()
    selected = cases["334-zero"]
    original_from_wire = module.from_wire

    def false_frame(events: list[dict[str, typ.Any]], action: int, kind: str) -> object:
        """Change the category field in one decoded post request.

        Returns
        -------
        object
            The original or altered decoded frame.
        """
        frame = original_from_wire(events, action, kind)
        if events is selected and (action, kind) == (9, "send"):
            frame = copy.deepcopy(frame)
            field = next(item for item in frame["fields"] if item["id"] == 325)
            field["hex"] = "00"
        return frame

    with (
        mock.patch.object(
            module, "check_session", side_effect=lambda case, *_: cases[case]
        ),
        mock.patch.object(module, "from_wire", side_effect=false_frame),
        pytest.raises(ValueError, match=r"^fixed post fields$"),
    ):
        module.replay()


def test_replay_rejects_unpaired_body_capture(corpus: Corpus) -> None:
    """An extra captured body without a post fails the paired inventory."""
    module, copied = corpus
    shutil.copytree(copied / "captures/body-334-zero", copied / "captures/body-extra")
    manifest_path = copied / "manifest.json"
    manifest = read(manifest_path)
    manifest["cases"].append("body-extra")
    write(manifest_path, manifest)
    comparison_path = copied / "stream-comparison.jsonl"
    comparison = [json.loads(line) for line in comparison_path.read_text().splitlines()]
    extra = {
        **next(row for row in comparison if row["case"] == "body-334-zero"),
        "case": "body-extra",
    }
    comparison_path.write_text(
        "\n".join(json.dumps(row) for row in [*comparison, extra]) + "\n"
    )
    readiness_path = copied / "readiness.json"
    readiness = read(readiness_path)
    for where in ("host", "namespace", "guest"):
        readiness[f"body-extra-{where}-gate.json"] = readiness[
            f"body-334-zero-{where}-gate.json"
        ]
    write(readiness_path, readiness)
    with pytest.raises(ValueError, match=r"^paired body inventory$"):
        module.replay()
