"""Check every relative link and fragment in the repository's Markdown.

Every tracked Markdown file outside ``evidence/`` is read. Inline links and
reference definitions outside code are resolved against the file's directory;
a fragment must match a heading anchor (the renderer's slug rule) or an
explicit ``<a id>``, and must not be ambiguous. Links into a sibling mothra
checkout are resolved against ``--mothra``. With ``--forbid-relative-mothra``
those links fail, and every ``github.com/leynos/mothra`` link must be a commit
permalink whose path exists at that commit in the clone.

When ``docs/contents.md`` exists the reachability rule of
:mod:`check_reach` is applied as well. The last line of output is
``N documents, M links, K failures``. Exit codes: 0 success, 1 findings,
2 missing inputs.
"""

import collections as col
import dataclasses as dc
import sys
import urllib.parse as urlparse
from pathlib import Path

import cyclopts
import markdown_model as mm
from check_reach import check_reach
from mothra_links import is_mothra_url, judge_github_link
from repo_files import repo_files
from tool_support import MissingInputError, Report, invoke

EVIDENCE = "evidence"
EXTERNAL = ("http://", "https://", "mailto:")
MOTHRA_DIRECTORY = "mothra"

app = cyclopts.App(result_action="return_value")


@dc.dataclass(frozen=True, slots=True)
class Options:
    """How a run treats links into mothra.

    Attributes
    ----------
    mothra : pathlib.Path | None
        The sibling mothra checkout.
    forbid : bool
        Whether relative mothra links fail and GitHub links must be permalinks.
    """

    mothra: Path | None = None
    forbid: bool = False


@dc.dataclass(slots=True)
class Anchors:
    """The fragments that a Markdown file can be linked to.

    Attributes
    ----------
    names : set[str]
        Heading slugs and explicit anchors.
    ambiguous : set[str]
        Heading slugs that more than one heading earns and no explicit anchor
        claims.
    """

    names: set[str]
    ambiguous: set[str]


def anchors_of(text: str) -> Anchors:
    """Work out which fragments ``text`` offers.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    Anchors
        The usable and the ambiguous fragments.
    """
    explicit = mm.explicit_anchors(text)
    counts = col.Counter(section["anchor"] for section in mm.section_inventory(text))
    return Anchors(
        names=set(counts) | explicit,
        ambiguous={name for name, n in counts.items() if n > 1} - explicit,
    )


def is_markdown_file(path: Path) -> bool:
    """Say whether ``path`` is an existing Markdown file.

    Parameters
    ----------
    path : pathlib.Path
        The path to test.

    Returns
    -------
    bool
        ``True`` for a file whose suffix is ``.md``.
    """
    return path.suffix == ".md" and path.is_file()


class Checker:
    """Checks the links of many documents, caching anchors per target."""

    def __init__(self, root: Path, options: Options, report: Report) -> None:
        """Bind a checker to a repository root and a report.

        Parameters
        ----------
        root : pathlib.Path
            The repository root.
        options : Options
            The mothra link policy.
        report : Report
            Receives the counts and failures.
        """
        self.root = root
        self.options = options
        self.report = report
        self._anchors: dict[Path, Anchors] = {}

    def fail(self, source: Path, link: mm.Link, reason: str) -> None:
        """Record a failure that names the document, line and link.

        Parameters
        ----------
        source : pathlib.Path
            The linking document.
        link : mm.Link
            The offending link.
        reason : str
            Why it fails.
        """
        where = f"{source.as_posix()}:{link.line}"
        self.report.failures.append(f"{where}: {reason}: {link.target}")

    def anchors(self, target: Path) -> Anchors:
        """Return the cached anchors of a Markdown file.

        Parameters
        ----------
        target : pathlib.Path
            An existing Markdown file.

        Returns
        -------
        Anchors
            Its heading and explicit anchors.
        """
        if target not in self._anchors:
            self._anchors[target] = anchors_of(target.read_text(encoding="utf-8"))
        return self._anchors[target]

    def locate(self, source: Path, link: mm.Link, path: str) -> Path | None:
        """Map a link path to a file-system path, or record why it cannot be.

        Parameters
        ----------
        source : pathlib.Path
            The linking document, relative to the root.
        link : mm.Link
            The link being checked.
        path : str
            The link path, without a fragment (empty for a same-file link).

        Returns
        -------
        pathlib.Path | None
            The absolute path to test, or ``None`` after a failure was recorded.

        """
        if not path:
            return self.root / source
        escapes, parts = mm.lexical_target(source, path)
        if escapes == 0:
            return self.root.joinpath(*parts)
        if escapes == 1 and parts[:1] == (MOTHRA_DIRECTORY,):
            return self._mothra_path(source, link, parts[1:])
        self.fail(source, link, "link leaves the repository")
        return None

    def _mothra_path(
        self, source: Path, link: mm.Link, rest: tuple[str, ...]
    ) -> Path | None:
        """Handle a relative link into the sibling mothra checkout.

        Parameters
        ----------
        source : pathlib.Path
            The linking document.
        link : mm.Link
            The link being checked.
        rest : tuple[str, ...]
            The path components below the mothra root.

        Returns
        -------
        pathlib.Path | None
            The path inside the checkout, or ``None`` after a failure.

        Raises
        ------
        MissingInputError
            If no checkout was supplied and the policy is not forbidding.
        """
        if self.options.forbid:
            self.fail(source, link, "relative link into mothra")
            return None
        if self.options.mothra is None:
            message = f"{link.target} needs a mothra checkout (--mothra)"
            raise MissingInputError(message)
        return self.options.mothra.joinpath(*rest)

    def check_link(self, source: Path, link: mm.Link) -> None:
        """Check one link and record any failure.

        Parameters
        ----------
        source : pathlib.Path
            The linking document, relative to the root.
        link : mm.Link
            The link to check.
        """
        self.report.links += 1
        if is_mothra_url(link.target) and self.options.forbid:
            reason = judge_github_link(link.target, self.options.mothra)
            if reason:
                self.fail(source, link, reason)
            return
        if link.target.startswith(EXTERNAL):
            return
        path, _, fragment = urlparse.unquote(link.target).partition("#")
        target = self.locate(source, link, path)
        if target is None:
            return
        if not target.exists():
            self.fail(source, link, "target does not exist")
        elif fragment and is_markdown_file(target):
            self.check_fragment(source, link, target, fragment)

    def check_fragment(
        self, source: Path, link: mm.Link, target: Path, fragment: str
    ) -> None:
        """Check a fragment against the anchors of its target.

        Parameters
        ----------
        source : pathlib.Path
            The linking document.
        link : mm.Link
            The link being checked.
        target : pathlib.Path
            The existing Markdown file.
        fragment : str
            The text after ``#``.
        """
        found = self.anchors(target)
        if fragment not in found.names:
            self.fail(source, link, "anchor does not exist")
        elif fragment in found.ambiguous:
            self.fail(source, link, "anchor is ambiguous (several headings share it)")

    def check_document(self, source: Path) -> None:
        """Check every link of one document.

        Parameters
        ----------
        source : pathlib.Path
            The document, relative to the root.
        """
        self.report.checked += 1
        text = (self.root / source).read_text(encoding="utf-8")
        for link in mm.extract_links(text):
            self.check_link(source, link)


def check(
    root: Path,
    *,
    mothra: Path | None = None,
    forbid_relative_mothra: bool = False,
    min_links: int = 0,
) -> Report:
    """Check the links of every tracked Markdown file outside ``evidence/``.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    mothra : pathlib.Path | None
        The mothra checkout used to resolve ``../mothra/`` links and to verify
        permalinks.
    forbid_relative_mothra : bool
        Fail every relative mothra link and require commit permalinks for every
        ``github.com/leynos/mothra`` link.
    min_links : int
        The least number of links a run must examine; fewer is a failure, so
        that an empty run cannot pass.

    Returns
    -------
    Report
        Documents and links examined, and one message per failure.
    """
    report = Report()
    checker = Checker(root, Options(mothra, forbid_relative_mothra), report)
    for path in repo_files(root, ".md"):
        if path.parts[0] != EVIDENCE:
            checker.check_document(path)
    if (root / "docs" / "contents.md").is_file():
        report.failures.extend(check_reach(root))
    if report.links < min_links:
        report.failures.append(
            f"only {report.links} links were examined; at least {min_links} required"
        )
    return report


@app.default
def run(
    root: Path = Path(),
    *,
    mothra: Path | None = None,
    forbid_relative_mothra: bool = False,
    min_links: int = 0,
) -> int:
    """Check Markdown links and print ``N documents, M links, K failures``.

    Parameters
    ----------
    root
        The repository root.
    mothra
        The sibling mothra checkout, for ``../mothra/`` links and permalinks.
    forbid_relative_mothra
        Fail relative mothra links and require verified commit permalinks.
    min_links
        Fail if fewer links than this are examined.

    Returns
    -------
    int
        0 when every link resolves, otherwise 1.
    """
    report = check(
        root,
        mothra=mothra,
        forbid_relative_mothra=forbid_relative_mothra,
        min_links=min_links,
    )
    for failure in report.failures:
        sys.stdout.write(f"{failure}\n")
    sys.stdout.write(
        f"{report.checked} documents, {report.links} links, "
        f"{len(report.failures)} failures\n"
    )
    return report.exit_code


def main(argv: list[str] | None = None) -> int:
    """Run the command line and return the process exit code.

    Parameters
    ----------
    argv : list[str] | None
        Command-line tokens, or ``None`` to read ``sys.argv``.

    Returns
    -------
    int
        The exit code: 0, 1 or 2.
    """
    return invoke(app, argv)


if __name__ == "__main__":
    sys.exit(main())
