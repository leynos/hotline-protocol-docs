"""Characterize the inventory and ledger checks of ``verify-baseline-evidence.py``.

The first half of the verifier is covered by
``test_characterize_verify_baseline.py``; this module covers what it does once
every saved query has passed: the capture inventory, the data-item pages and the
ledger with its claim index and links. Expectations were observed on the script
at its pinned commit and must hold on the refactored script.
"""

import typing as typ

import pytest
from baseline_corpus_support import LEDGER, Corpus, expect, refused
from script_loading import ROOT, load_script

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

CHARACTERIZES = "verify-baseline-evidence.py"
INVENTORY = "Capture inventory differs from the plans or manifest"
PAGES = "Data inventory pages have a gap or overlap"
ZEROS = "0" * 64
AGAIN = "| V001 | Again. | Doc defect | Note. |\n"
BROKEN_HANDLER = "See [x](../evidence/hotline-server-1.9/queries/Q.c).\n"
BROKEN_REFERENCE = "[gone]: ../evidence/hotline-server-1.9/inputs/gone.txt\n"


@pytest.fixture(scope="module")
def verifier() -> ModuleType:
    """Load the verifier under test.

    Returns
    -------
    types.ModuleType
        The executed script.
    """
    return load_script(ROOT / "scripts" / CHARACTERIZES, "verify_baseline_ledger")


class InventoryChecksTests:
    """The saved queries must be exactly the planned ones, and pages must tile."""

    def test_an_unplanned_saved_query_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A record file that no plan names breaks the inventory."""
        corpus = Corpus(tmp_path)
        corpus.records["Z-9"] = corpus.records["C-1"]
        expect(verifier, corpus, INVENTORY)

    def test_a_wrong_capture_count_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The manifest's capture count must equal the identifiers."""
        corpus = Corpus(tmp_path)
        corpus.manifest["capture_count"] = 5
        expect(verifier, corpus, INVENTORY)

    def test_the_inventory_check_comes_before_the_page_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A wrong count is reported although the pages also have a gap."""
        corpus = Corpus(tmp_path)
        corpus.manifest["capture_count"] = 5
        corpus.data("B-2")["offset"] = 7
        expect(verifier, corpus, INVENTORY)

    @pytest.mark.parametrize("offset", [3, 1])
    def test_a_gap_or_overlap_between_pages_is_refused(
        self, verifier: ModuleType, tmp_path: Path, offset: int
    ) -> None:
        """Pages are ordered by offset and must start where the last ended."""
        corpus = Corpus(tmp_path)
        corpus.data("B-2")["offset"] = offset
        expect(verifier, corpus, PAGES)

    def test_a_first_page_that_does_not_start_at_zero_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The running offset starts at zero."""
        corpus = Corpus(tmp_path)
        corpus.data("B-1")["offset"] = 1
        corpus.data("B-2")["offset"] = 3
        expect(verifier, corpus, PAGES)

    def test_a_changed_total_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Every page must report the first page's total."""
        corpus = Corpus(tmp_path)
        corpus.data("B-2")["total"] = 4
        expect(verifier, corpus, "Data inventory total changed during capture")

    def test_the_offset_check_comes_before_the_total_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A page with a wrong offset and a wrong total is a gap."""
        corpus = Corpus(tmp_path)
        corpus.data("B-2")["offset"] = 3
        corpus.data("B-2")["total"] = 4
        expect(verifier, corpus, PAGES)

    def test_a_short_inventory_is_incomplete(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The items collected must reach the total."""
        corpus = Corpus(tmp_path)
        corpus.data("B-1")["total"] = 4
        corpus.data("B-2")["total"] = 4
        expect(verifier, corpus, "Incomplete data inventory")

    def test_pages_are_ordered_by_offset_not_by_file(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A later page may be planned first."""
        corpus = Corpus(tmp_path)
        corpus.plans["01-first.json"].reverse()
        corpus.plans["02-second.json"].reverse()
        verifier.verify(corpus.write())

    def test_no_data_page_at_all_is_an_index_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The first page is read for the total even when there is none."""
        corpus = Corpus(tmp_path)
        for queries in corpus.plans.values():
            for query in queries:
                if query["tool"] == "list_data_items":
                    query["tool"] = "get_function"
                    corpus.records[query["id"]]["query"]["tool"] = "get_function"
        error = refused(verifier, corpus)
        assert isinstance(error, IndexError), f"unexpected {error!r}"


class LedgerChecksTests:
    """The ledger, its claim index and its links are checked last."""

    def test_a_repeated_claim_identifier_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Two rows with one identifier are refused."""
        corpus = Corpus(tmp_path)
        corpus.ledger += AGAIN
        expect(verifier, corpus, "Duplicate ledger claim ID")

    def test_a_ledger_that_the_index_does_not_hash_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The claim index records the ledger's hash."""
        corpus = Corpus(tmp_path)
        corpus.claims["ledger_sha256"] = ZEROS
        corpus.index_ledger = False
        message = "Ledger differs from the machine-readable claim index"
        expect(verifier, corpus, message)

    def test_the_duplicate_check_comes_before_the_hash_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A repeated identifier is reported even when the hash is stale."""
        corpus = Corpus(tmp_path)
        corpus.ledger += AGAIN
        corpus.claims["ledger_sha256"] = ZEROS
        corpus.index_ledger = False
        expect(verifier, corpus, "Duplicate ledger claim ID")

    def test_claim_identifiers_must_match_the_index_in_order(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The index lists the same identifiers in the same order."""
        corpus = Corpus(tmp_path)
        corpus.claims["claims"].reverse()
        expect(verifier, corpus, "Claim IDs differ between the ledger and index")

    def test_the_hash_check_comes_before_the_identifier_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A stale hash is reported before differing identifiers."""
        corpus = Corpus(tmp_path)
        corpus.claims["claims"].reverse()
        corpus.claims["ledger_sha256"] = ZEROS
        corpus.index_ledger = False
        expect(verifier, corpus, "Ledger differs", starts=True)

    def test_the_claim_count_must_match_the_manifest(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The manifest records how many claims the ledger holds."""
        corpus = Corpus(tmp_path)
        corpus.manifest["ledger_claim_count"] = 4
        expect(verifier, corpus, "Ledger claim count differs from the manifest")

    def test_a_reference_link_to_a_missing_file_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A ``[name]: target`` line must point at an existing file."""
        corpus = Corpus(tmp_path)
        corpus.ledger += BROKEN_REFERENCE
        message = (
            "Broken evidence reference: ../evidence/hotline-server-1.9/inputs/gone.txt"
        )
        expect(verifier, corpus, message)

    def test_a_handler_link_to_a_missing_file_is_refused(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """An inline link into ``../evidence/`` must point at an existing file."""
        corpus = Corpus(tmp_path)
        corpus.ledger += BROKEN_HANDLER
        message = "Broken handler reference: ../evidence/hotline-server-1.9/queries/Q.c"
        expect(verifier, corpus, message)

    def test_the_count_check_comes_before_the_link_checks(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """A wrong count is reported although a link is also broken."""
        corpus = Corpus(tmp_path)
        corpus.manifest["ledger_claim_count"] = 4
        corpus.ledger += "[gone]: ../evidence/nowhere\n"
        expect(verifier, corpus, "Ledger claim count", starts=True)

    def test_the_reference_check_comes_before_the_handler_check(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Both kinds of broken link are present; the reference line wins."""
        corpus = Corpus(tmp_path)
        corpus.ledger += BROKEN_HANDLER + "[gone]: ../evidence/nowhere\n"
        expect(verifier, corpus, "Broken evidence reference", starts=True)

    def test_a_missing_ledger_is_a_file_not_found_error(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """The ledger is read after the data inventory."""
        root = Corpus(tmp_path).write()
        (root / LEDGER).unlink()
        with pytest.raises(FileNotFoundError):
            verifier.verify(root)

    def test_a_ledger_row_with_another_prefix_is_not_a_claim(
        self, verifier: ModuleType, tmp_path: Path
    ) -> None:
        """Only ``V`` and ``M`` followed by three digits count as claims."""
        corpus = Corpus(tmp_path)
        corpus.ledger += "| X004 | Not a claim. | Other | Note. |\n"
        verifier.verify(corpus.write())
