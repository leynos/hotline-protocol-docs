"""Check the read-only Ban tab and the recorders of the persisted-ban reload witness."""

import json
import typing as typ

from verify_native_ban_reload_core import (
    EMPTY_PCAP_BYTES,
    EMULATOR,
    INPUT,
    NS,
    PID,
    PREPARED,
    START,
    UI_ACTIONS,
    UI_IMAGE,
    read,
    require,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]


def _check_boot(ready: Report) -> None:
    """Check the identity of the read-only emulator boot.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The parsed ``ui-ready.json``.
    """
    em = ready["actual_emulator"]
    require(
        (em["pid"], em["starttime"], em["netns"]) == (PID, START, NS)
        and em["exe"].endswith(EMULATOR)
        and em["fd6"].endswith("native-eventlab-one-01/working.dsk")
        and em["fd16"].endswith("native-configured-ban-ui-c61/lab-guest.pcap")
        and em["uid"].split()[0] == "1000"
        and ready["ns_route"] == ""  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # == "" rejects a non-string value that "not" would accept
        and ready["primary_syn_pcap_bytes"] == EMPTY_PCAP_BYTES
        and ready["namespace_pcap_bytes"] == EMPTY_PCAP_BYTES
        and ready["probe_executed"] is False
        and ready["options_cancelled"] is True
        and ready["probe_prepared_sha256"] == PREPARED,
        "Read-only UI boot identity differs",
    )


def _check_recorders(root: Path, ready: Report) -> None:
    """Check that each recorder is the one that was ready before the probe.

    Parameters
    ----------
    root : pathlib.Path
        The ``c61`` directory of the corpus.
    ready : dict[str, typing.Any]
        The parsed ``ui-ready.json``.
    """
    for label in ("host", "namespace"):
        first = ready[f"{label}_recorder"]
        before = read(root / f"{label}-ready-preprobe.json")
        require(
            first["pid"] == before["pid"]
            and first["start_ticks"] == before["start_ticks"]
            and first["fd"] == before["fd"]
            and first["unit_properties"]["ActiveState"] == "active"
            and before["unit_properties"]["ActiveState"] == "active"
            and before["header24"].startswith("d4c3b2a1")
            and before["deadline_utc"] == first["deadline_utc"]
            and before["unit_properties"]["RuntimeMaxUSec"] == "15min",
            f"{label} recorder identity or deadline differs",
        )


def _check_ui(root: Path) -> None:
    """Check the read-only Ban tab observation and the recorded action log.

    Parameters
    ----------
    root : pathlib.Path
        The ``c61`` directory of the corpus.
    """
    ui = read(root / "ui-observation.json")
    tab = ui["ban_tab"]
    require(
        tab["checked_row"] == tab["ip_field"] == "10.0.2.2"
        and tab["info_field"] == ""  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # == "" rejects a non-string value that "not" would accept
        and tab["edited"] is False
        and tab["saved"] is False
        and tab["actions_taken"] == ["open Options", "select Ban tab", "Cancel"]
        and ui["resource_mapping"]["ban_control_ids"].startswith("unresolved")
        and ui["probe_executed"] is False
        and ui["no_primary_contact_before_probe"] is True
        and sha(root / "options-ban.png") == UI_IMAGE
        and all(
            sha(root / image) == digest
            for image, digest in ui["screenshots_sha256"].items()
        ),
        "Read-only Ban UI row or Cancel claim differs",
    )
    actions = [
        json.loads(line)
        for line in (root / "ui-actions.jsonl").read_text().splitlines()
    ]
    require(
        len(actions) == UI_ACTIONS
        and [(x["x"], x["y"]) for x in actions[3:6]]
        == [(936, 85), (490, 247), (583, 541)]
        and "Cancel" in actions[5]["reason"]
        and all("Save" not in x["reason"] for x in actions)
        and sha(root / "input.py") == INPUT,
        "UI action scope or input source differs",
    )


def ready_and_ui(corpus: Path) -> Report:
    """Check the read-only boot, the recorders and the Ban tab of the UI run.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``ui-ready.json``.
    """
    root = corpus / "c61"
    ready = read(root / "ui-ready.json")
    _check_boot(ready)
    _check_recorders(root, ready)
    _check_ui(root)
    return ready
