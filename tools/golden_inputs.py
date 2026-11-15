"""The inputs of the planner oracle: which retained records each planner runs on.

Each entry names the planner file, the retained runtime record (and baseline
plan, where the planner pins one) that it is run against, and any option the
record does not supply. Everything here is a fact about the inherited scripts
as they stand; the oracle reads it and runs nothing from this module.
"""

import dataclasses as dc

E = "evidence/gap-remediation/"
OUT = "{out}"
CASE = "{case}"
DISPATCHER = "prepare_native_cases.py"
# Runtime record handed to every dispatcher suite. It is only embedded in plans.
SYNTHETIC_RUNTIME = {"golden": "INV-SCRIPT synthetic runtime record"}
BATCH = E + "2026-11-13/native-account-batch-01/"
AGREEMENT = E + "2026-11-13/native-agreement-01/"
# Suites that need an input beyond the runtime record, with the input used.
SUITE_EXTRAS: dict[str, tuple[str, ...]] = {
    "account-batch-cleanup": ("--account-inventory", BATCH + "cleanup-inventory.json"),
    "agreement-restore-stage": (
        "--original-agreement",
        AGREEMENT + "original-agreement.data",
    ),
    "news-thread-children": ("--article-parent", "7"),
    "news-thread-grandchild": ("--article-parent", "7"),
    "article-delete-resume": ("--case-name", "parent-absent"),
}
SKIPPED = {
    "native_diagnostic_load_cases.py cleanup": (
        "needs the recorded Mac oracle binary and a live baseline report, and"
        " stamps recorded_at_utc from the wall clock"
    ),
}
# No retained runtime record carries the 30-minute window; add its two keys.
POSITIVE_WINDOW = (
    ("capture_window_profile", "native-missing-alias-ui-30m-v1"),
    ("capture_window_purpose", "native-missing-alias-positive"),
)
# The interpreter code that calls a library's ``write_plans`` the way its runner
# does: ``-c DRIVER MODULE.py RUNTIME PORT OUTPUT``.
DRIVER = (
    "import json,sys,pathlib,importlib;sys.path.insert(0,'scripts');"
    "m=importlib.import_module(sys.argv[1][:-3]);"
    "r=json.loads(pathlib.Path(sys.argv[2]).read_text());"
    "m.write_plans(pathlib.Path(sys.argv[4]),r,int(sys.argv[3]))"
)


@dc.dataclass(frozen=True, slots=True)
class Direct:
    """A planner with its own command line, and the retained inputs it runs on.

    Attributes
    ----------
    file : str
        The script name under ``scripts/``.
    runtime : str
        A retained runtime record, relative to the repository root.
    flag : str
        The option that names the runtime record.
    baseline : str
        A retained baseline plan, for planners that pin one.
    cases : bool
        Whether the planner takes a positional case, read from its ``--help``.
    port : str
        The control port, for planners that take one.
    label : str
        Distinguishes two runs of one planner.
    overlay : tuple[tuple[str, str], ...]
        Keys added to the runtime record for an input no retained record has.
    """

    file: str
    runtime: str
    flag: str = "--runtime"
    baseline: str = ""
    cases: bool = False
    port: str = ""
    label: str = ""
    overlay: tuple[tuple[str, str], ...] = ()

    def args(self, runtime: str) -> list[str]:
        """Build the arguments, naming ``runtime`` as the runtime record.

        Returns
        -------
        list[str]
            The command line after the script name; ``{out}`` is the output.
        """
        found = [CASE] if self.cases else []
        found += [self.flag, runtime]
        found += ["--baseline-plan", self.baseline] if self.baseline else []
        found += ["--port", self.port] if self.port else []
        return [*found, "--output", OUT]


def _rt(corpus: str, name: str = "runtime.json") -> str:
    """Return the path of a retained file in a corpus.

    Returns
    -------
    str
        The path below ``evidence/gap-remediation``, from the repository root.
    """
    return E + corpus + "/" + name


def direct_specs() -> list[Direct]:
    """List the planners that run from their own command line.

    Returns
    -------
    list[Direct]
        One entry per run; a positional case is expanded later.
    """
    d121 = "2026-11-14/native-121-defaults-01"
    pm = "2026-11-13/native-pm-01"
    trans = "2026-11-13/native-settings-transitions-01"
    diag = _rt("2026-11-13/native-diagnostics-01")
    alias = _rt("2026-11-14/native-alias-prestage-01/raw/epoch")
    rec, planner = "--runtime-record", "native_{}_cases.py".format
    return [
        Direct(
            planner("121_default"), _rt(d121), rec, _rt(d121, "preflight/plan.json")
        ),
        Direct(
            planner("ban_expiry"),
            _rt("2026-11-14/native-ban-expiry-first-01/raw", "runtime-asrun.json"),
        ),
        Direct(planner("bitmap"), _rt("2026-11-13/native-bitmaps-01"), rec),
        Direct(planner("board"), _rt("2026-11-14/native-board-01/raw")),
        Direct(planner("diagnostic"), diag, rec),
        Direct(planner("diagnostic_existing"), diag, rec, cases=True),
        Direct(
            planner("diagnostic_load"),
            _rt("2026-11-13/native-diagnostic-load-01"),
            rec,
            cases=True,
        ),
        Direct(planner("diagnostic_near"), diag, rec),
        Direct(planner("liveness"), _rt("2026-11-14/native-liveness-01/raw")),
        Direct(planner("missing_alias"), alias, label="default-window"),
        Direct(
            planner("missing_alias"),
            alias,
            label="positive-window",
            overlay=POSITIVE_WINDOW,
        ),
        Direct(
            planner("path_fields"), _rt("2026-11-14/native-path-fields-01/raw/epoch")
        ),
        Direct(planner("pm"), _rt(pm), rec, _rt(pm, "preflight/plan.json")),
        Direct(
            planner("rate304"),
            _rt("2026-11-14/native-rate304-sequence-01/raw/epoch"),
            label="sequence",
        ),
        Direct(
            planner("rate304"),
            _rt("2026-11-14/native-rate304-first-pair-01/raw"),
            label="first-pair",
        ),
        Direct(
            planner("roster_overlap"),
            _rt("2026-11-14/native-roster-overlap-01/raw", "runtime-asrun.json"),
        ),
        Direct(
            planner("settings"),
            _rt("2026-11-13/native-settings-01/raw", "runtime-current.json"),
            rec,
        ),
        Direct(
            planner("settings_persistence"),
            _rt("2026-11-14/native-settings-persistence-01/phase1"),
            port="15760",
        ),
        Direct(
            planner("settings_transition"),
            _rt(trans),
            rec,
            _rt(trans, "preflight/plan.json"),
        ),
    ]


# Libraries with no command line, called in-process the way their runners do:
# the runtime record and the control port that their corpora used.
IN_PROCESS = {
    "native_ban_control_cases.py": (
        _rt("2026-11-14/native-ban-control-01/case-c56", "runtime-asrun.json"),
        "15750",
    ),
    "native_configured_ban_cases.py": (
        _rt(
            "2026-11-14/native-configured-ban-01/native-configured-apply-c66",
            "runtime-asrun.json",
        ),
        "15770",
    ),
}
