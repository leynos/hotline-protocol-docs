"""Describe the subjects of the diagnostic verifiers' order tests.

A subject is the retained evidence that a check reads, as parsed JSON, and a
function that runs the check on a possibly faulted copy of it. The tests replay
recorded faults against these subjects; the recording tool builds the same
subjects while the pristine scripts are on ``sys.path``.
"""

import contextlib
import json
import sys
import tempfile
import typing as typ
from pathlib import Path

import native_diagnostic_cases
import verify_native_diagnostic_existing
import verify_native_diagnostic_load
import verify_native_diagnostic_near
import verify_native_diagnostics
from corpus_mirror import Mirror

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

ROOT = Path(__file__).resolve().parents[1]
BATCH = ROOT / "evidence/gap-remediation/2026-11-13"
DIAGNOSTICS = BATCH / "native-diagnostics-01"
LOAD = BATCH / "native-diagnostic-load-01"
EXISTING = BATCH / "native-diagnostic-existing-01"
DENSITY = BATCH / "native-diagnostic-density-01"
NEAR = BATCH / "native-diagnostic-near-01"
PREFLIGHT = BATCH / "native-diagnostic-existing-preflight-01/capture"
DIAGNOSTIC_NAMES = ("preflight", "seed", "observe", "self", "cleanup")
HOST_PACKETS = 125  # the packets of the retained host capture of the corpus


def load(path: Path) -> dict[str, typ.Any]:
    """Parse one retained JSON file, which holds an object.

    Returns
    -------
    dict[str, typing.Any]
        The parsed content.
    """
    return json.loads(path.read_text())


def with_plan(
    report: dict[str, typ.Any], plan: object, directory: Path
) -> dict[str, typ.Any]:
    """Point a report at a copy of its plan written below ``directory``.

    Returns
    -------
    dict[str, typing.Any]
        The report with ``_plan_path`` set.
    """
    path = directory / "plan.json"
    path.write_text(json.dumps(plan))
    return {**report, "_plan_path": path}


def diagnostics_subject() -> Subject:
    """Build the subject of the 303 diagnostics semantic check.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The five reports and ``verify_native_diagnostics.semantic``.
    """
    state = {
        name: load(DIAGNOSTICS / name / "report.json") for name in DIAGNOSTIC_NAMES
    }
    return state, verify_native_diagnostics.semantic


def load_subject() -> Subject:
    """Build the subject of the load verifier's semantic check.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The three reports with their cleanup plan, and a function that runs
        ``verify_native_diagnostic_load.semantic`` on them.
    """
    state: State = {
        name: load(LOAD / name / "report.json")
        for name in verify_native_diagnostic_load.CASES
    }
    state["cleanup-plan"] = load(LOAD / "cleanup/plan.json")

    def call(changed: State) -> object:
        """Run the semantic check, with the cleanup plan on disk.

        Returns
        -------
        object
            What the check returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            reports = {
                name: changed[name] for name in verify_native_diagnostic_load.CASES
            }
            reports["cleanup"] = with_plan(
                changed["cleanup"], changed["cleanup-plan"], Path(temporary)
            )
            return verify_native_diagnostic_load.semantic(reports)

    return state, call


def existing_subject(root: Path, case: str) -> Subject:
    """Build the subject of one case of the existing-fixture semantic check.

    Parameters
    ----------
    root : pathlib.Path
        The retained corpus that holds the case.
    case : str
        The case: ``one-active-one-queued``, ``density`` or ``postflight``.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The report, its plan and the baseline, and a function that runs
        ``verify_native_diagnostic_existing.semantic`` on them.
    """
    state: State = {
        "report": load(root / case / "report.json"),
        "plan": load(root / case / "plan.json"),
        "baseline": load(PREFLIGHT / "report.json"),
    }

    def call(changed: State) -> object:
        """Run the semantic check, with the plan on disk.

        Returns
        -------
        object
            What the check returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            report = with_plan(changed["report"], changed["plan"], Path(temporary))
            return verify_native_diagnostic_existing.semantic(
                case, report, changed["baseline"]
            )

    return state, call


def near_subject() -> Subject:
    """Build the subject of the near-boundary semantic check.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The report and its plan, and a function that runs
        ``verify_native_diagnostic_near.semantic`` on them.
    """
    # The retained near-boundary capture failed before its end, so its status is
    # raised to ``completed`` here: only the checks before the first request-ID
    # comparison can then be reached, and those are the ones whose order is held.
    state: State = {
        "report": {**load(NEAR / "near/report.json"), "status": "completed"},
        "plan": load(NEAR / "near/plan.json"),
    }

    def call(changed: State) -> object:
        """Run the semantic check, with the plan on disk.

        Returns
        -------
        object
            What the check returned.
        """
        with tempfile.TemporaryDirectory() as temporary:
            report = with_plan(changed["report"], changed["plan"], Path(temporary))
            return verify_native_diagnostic_near.semantic(report)

    return state, call


def stale_subject() -> Subject:
    """Build the subject of the plan builder for a stale UID.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The stale UID as hex, and a function that builds the observe plan.
    """

    def call(changed: State) -> object:
        """Build the plans for the faulted UID.

        Returns
        -------
        object
            The suites of the planner.
        """
        return native_diagnostic_cases.suites(bytes.fromhex(changed["uid"]))

    return {"uid": "008d"}, call


@contextlib.contextmanager
def stubs(prefix: str, **replacements: object) -> cabc.Iterator[None]:
    """Replace names in every loaded module whose name starts with ``prefix``.

    The replaced names are restored on leaving the block.

    Yields
    ------
    None
        Control, while the stand-ins are in place.
    """
    patched = []
    for module_name, module in list(sys.modules.items()):
        if module_name.startswith(prefix):
            for attribute, stand_in in replacements.items():
                if hasattr(module, attribute):
                    patched.append((module, attribute, getattr(module, attribute)))
                    setattr(module, attribute, stand_in)
    try:
        yield
    finally:
        for module, attribute, original in patched:
            setattr(module, attribute, original)


def mirrored(
    corpus: Path, files: list[str], verify: cabc.Callable[[Path], object]
) -> Subject:
    """Describe a corpus as the JSON of some files and a check that runs on a mirror.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The parsed files, and a function that mirrors the corpus with the files
        that differ written back and runs ``verify`` on it.
    """
    original: State = {name: load(corpus / name) for name in files}

    def call(changed: State) -> object:
        """Run ``verify`` on a mirror that holds the changed files.

        Returns
        -------
        object
            What ``verify`` returned, without the directory it was given.
        """
        with tempfile.TemporaryDirectory() as temporary:
            mirror = Mirror(corpus, Path(temporary))
            for name, value in changed.items():
                if value != original[name]:
                    mirror.write_json(name, value)
            result = verify(mirror.root)
        if isinstance(result, dict):
            return {k: v for k, v in result.items() if k != "directory"}
        return result

    return original, call


def read_report(directory: Path) -> dict[str, typ.Any]:
    """Stand in for the capture replay.

    Returns
    -------
    dict[str, typing.Any]
        The retained report of the capture in ``directory``.
    """
    return load(directory / "report.json")


def no_packets(_path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the retained host capture holds.
    """
    return [None] * HOST_PACKETS


def paired(report: dict[str, typ.Any], *_args: object, **_kwargs: object) -> list[None]:
    """Stand in for the packet reconciliation.

    Returns
    -------
    list[None]
        One observation for each connection of the report.
    """
    return [None] * len(report["streams"])


def diagnostics_corpus_subject() -> Subject:
    """Build the subject of the whole diagnostics corpus check.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The corpus's small files, reports and plans, and a function that runs
        ``verify_native_diagnostics.verify`` on a mirror that holds them, with the
        packet readers and the capture replay replaced.
    """
    files = ["manifest.json", "runtime.json", "unread-tails.json"]
    for name in DIAGNOSTIC_NAMES:
        files += [f"{name}/plan.json", f"{name}/report.json"]
    state, mirror_call = mirrored(DIAGNOSTICS, files, verify_native_diagnostics.verify)

    def call(changed: State) -> object:
        """Run the corpus check with the readers replaced.

        Returns
        -------
        object
            What the check returned.
        """
        with stubs(
            "verify_native_diagnostics",
            read_packets=no_packets,
            reconcile=paired,
            verify_capture=read_report,
        ):
            return mirror_call(changed)

    return state, call


def load_corpus_subject() -> Subject:
    """Build the subject of the load corpus check, from its manifest and runtime.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The two small files of the corpus and a function that runs
        ``verify_native_diagnostic_load.verify`` on a mirror that holds them.
    """
    return mirrored(
        LOAD, ["manifest.json", "runtime.json"], verify_native_diagnostic_load.verify
    )


def subjects() -> dict[str, Subject]:
    """Build every subject, by name.

    Returns
    -------
    dict[str, tuple[dict, collections.abc.Callable]]
        The evidence and the check of each subject.
    """
    found = {
        "diagnostics-semantic": diagnostics_subject(),
        "load-semantic": load_subject(),
        "near-semantic": near_subject(),
        "stale-suites": stale_subject(),
        "diagnostics-corpus": diagnostics_corpus_subject(),
        "load-corpus": load_corpus_subject(),
    }
    for root, cases in (
        (EXISTING, ("one-active-one-queued", "postflight")),
        (DENSITY, ("density",)),
    ):
        for case in cases:
            found[f"existing-{case}"] = existing_subject(root, case)
    return found
