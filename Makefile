MDLINT ?= markdownlint-cli2
NIXIE ?= nixie
MDTABLEFIX ?= mdtablefix
MDTABLEFIX_VERSION ?= 0.6.1
MDTABLEFIX_RULES = --wrap --renumber --breaks --ellipsis --fences
export PATH := $(HOME)/.local/bin:$(HOME)/.bun/bin:$(HOME)/.cargo/bin:$(PATH)
UV ?= $(shell command -v uv 2>/dev/null || printf '%s/.local/bin/uv' "$$HOME")
TYPOS_CONFIG_BUILDER_VERSION ?= v0.1.3
TYPOS_CONFIG_BUILDER = $(UV) tool run --python $(LINT_PYTHON) --from \
	"git+https://github.com/leynos/typos-config-builder.git@$(TYPOS_CONFIG_BUILDER_VERSION)" \
	typos-config-builder
RUFF_VERSION ?= 0.16.8
TY_VERSION ?= 0.0.56
PYLINT_VERSION ?= 4.0.9
LINT_PYTHON ?= 3.14
RUFF = $(UV) tool run --python $(LINT_PYTHON) --from 'ruff==$(RUFF_VERSION)' ruff
TY = $(UV) run --group dev ty
PYLINT = $(UV) tool run --python $(LINT_PYTHON) --from 'pylint==$(PYLINT_VERSION)' pylint
DF12_PYTHON_LINTS_REF ?= v0.4.0
DF12_PYTHON_LINTS = git+https://github.com/leynos/df12-python-lints.git@$(DF12_PYTHON_LINTS_REF)
DF12_PYLINT_MESSAGES = R9101,C9102,R9103,R9104,C9105,C9106,C9107,R9108,R9109,R9110,R9111,R9112,C9112
DF12_PYLINT = $(UV) tool run --python $(LINT_PYTHON) --from 'pylint==$(PYLINT_VERSION)' \
	--with '$(DF12_PYTHON_LINTS)' pylint --disable=all --load-plugins=df12_python_lints \
	--enable=syntax-error,$(DF12_PYLINT_MESSAGES)

# Every Python file is held to the df12 standards in pyproject.toml: the tools,
# their tests, the scripts and the pytest files in scripts/tests.
PYTHON_TARGETS = $(shell git ls-files --cached --others \
	--exclude-standard 'tools/*.py' 'tools/**/*.py' 'tests/*.py' 'tests/**/*.py' \
	'scripts/*.py' 'scripts/**/*.py')
# Interrogate scans these directories recursively, so a new Python file under
# them is measured without a list to update. The evidence directories join as each
# is documented (the docstrings are held to the pinned code by pins-check). Interrogate
# rounds to the decimals of its threshold, so one missed docstring among thousands
# passes at 100; the second invocation in lint-python fails on any MISSED row.
INTERROGATE_TARGETS ?= tools tests scripts evidence/gap-remediation/2026-11-13 \
	evidence/gap-remediation/2026-11-14/native-board-01 \
	evidence/gap-remediation/2026-11-14/native-board-readiness-failure-01 \
	evidence/gap-remediation/2026-11-14/native-liveness-01 \
	evidence/gap-remediation/2026-11-14/native-roster-overlap-01 \
	evidence/gap-remediation/2026-11-14/native-runner-namespace-guard-01 \
	evidence/gap-remediation/2026-11-14/native-alias-positive-first-01 \
	evidence/gap-remediation/2026-11-14/native-alias-prestage-01 \
	evidence/gap-remediation/2026-11-14/native-alias-prestage-abort-01
RUFF_ROOT = --config pyproject.toml
# The repository tools run in the project environment.
PYTHON ?= $(UV) run --group dev python
# Recipes run the inherited scripts as `python3`, as the documents do. The project
# environment leads PATH so that a script already brought to the df12 standard
# finds Cyclopts and cuprum, and an evidence-held verifier that imports one of
# the scripts runs under the same interpreter.
export PATH := $(CURDIR)/.venv/bin:$(PATH)
# More documented evidence corpora (the ban corpora and the rest).
INTERROGATE_TARGETS += evidence/gap-remediation/2026-11-14/account-write-ordering-01 \
	evidence/gap-remediation/2026-11-14/native-121-defaults-01 \
	evidence/gap-remediation/2026-11-14/native-ban-control-01 \
	evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01 \
	evidence/gap-remediation/2026-11-14/native-ban-expiry-later-01 \
	evidence/gap-remediation/2026-11-14/native-ban-expiry-preparation-01 \
	evidence/gap-remediation/2026-11-14/native-ban-reload-01 \
	evidence/gap-remediation/2026-11-14/native-configured-ban-01
# Every interpreter that these targets start reads each evidence .py file as it was
# captured (scripts/pinned-evidence.json), so the file may gain docstrings while the
# hashes recorded for it stay true; see tools/evidence_pin_view.py.
PIN_VIEW_TARGETS = evidence-verify evidence-verify-known-red test test-legacy goldens-check continuity-tests pin-equivalence pin-experiment
$(PIN_VIEW_TARGETS): export PYTHONPATH := $(CURDIR)/tools/pinview$(if $(PYTHONPATH),:$(PYTHONPATH))
# Evidence JSON that cannot be canonical is exempted by hash in this file, once
# it exists (see tools/check_json.py).
JSON_EXCEPTIONS ?= json-exceptions.txt
JSON_EXCEPTIONS_ARG = $(if $(wildcard $(JSON_EXCEPTIONS)),--exceptions $(JSON_EXCEPTIONS))
# A local clone of mothra. Links to it are commit permalinks; the link check
# confirms that each linked path exists at its commit in this clone, and
# --forbid-relative-mothra in LINKS_ARGS rejects any ../mothra/ link.
MOTHRA ?= $(firstword $(wildcard ../mothra ../../mothra))
MOTHRA_ARG = $(if $(MOTHRA),--mothra $(MOTHRA))
# The run must examine at least this many links, so an empty run cannot pass.
LINKS_MIN ?= 2000
LINKS_ARGS ?= --forbid-relative-mothra
# Evidence is preserved byte for byte, so no Markdown tool may select it.
MD_FILES = $(shell git ls-files --cached --others --exclude-standard '*.md' ':!:evidence/**')
# gap-analysis.md is generated from gap-register.json; its layout belongs to the
# renderer, so it is linted but never reflowed.
# The validity ledger is hash-pinned by the evidence index, so it is never
# reflowed either.
MD_AUTHORED = $(filter-out gap-analysis.md docs/baseline-validity-ledger.md,$(MD_FILES))

# The withheld-files gate needs the manifest that the evidence import creates;
# until it exists the gate is skipped, with a message.
WITHHELD_GATE = $(if $(wildcard evidence/withheld.json),withheld-check,withheld-skip)

# The evidence gates need the imported evidence/ directory.
EVIDENCE_GATE = $(if $(wildcard evidence),sums-check lfs-check,evidence-skip)
# The legacy verifiers replay the retained corpora, so they need evidence/ too.
EVIDENCE_VERIFY_GATE = $(if $(wildcard evidence),evidence-verify)

# The curation gate needs the record that the evidence import creates.
CURATION_GATE = $(if $(wildcard evidence/curation.json),curation-check,curation-skip)
# Documents whose evidence citations must resolve, and the mothra commit that the
# evidence was imported from (D22).
CITING_DOCS = $(filter-out gap-analysis.md docs/documentation-style-guide.md \
	docs/baseline-validity-ledger.md docs/execplans/documentation-reconcilliation.md,$(MD_FILES))
CITING_ARGS ?= $(foreach f,$(CITING_DOCS),--citing document=$(f)) \
	$(if $(wildcard docs/baseline-validity-ledger.md),--citing ledger=docs/baseline-validity-ledger.md) \
	$(if $(wildcard gap-register.json),--citing register=gap-register.json) \
	$(foreach f,$(wildcard scripts/*.py),--citing script=$(f))
IMPORT_COMMIT ?= f9b4108ec33e59956c9f2bfbd391dc3a8a279299

.PHONY: help all build fmt check-fmt check-fmt-python check-fmt-markdown \
	lint lint-python typecheck test docs-gates markdownlint spelling nixie \
	json-check pins-check links-check style-check evidence-check evidence-index audit-check withheld-check withheld-scan withheld-skip \
	sums-check lfs-check evidence-skip curation-check import-check curation-skip \
	goldens-check pin-experiment pin-equivalence continuity-tests

.DEFAULT_GOAL := all
# Shared build caches require sequential gates even when make receives -j.
.NOTPARALLEL:

all: build check-fmt-python json-check pins-check links-check evidence-check audit-check $(WITHHELD_GATE) $(EVIDENCE_GATE) $(CURATION_GATE) $(EVIDENCE_VERIFY_GATE) lint-python typecheck test ## Run the gates that must pass at every commit

lint: lint-python ## Run every Python linter

docs-gates: check-fmt-markdown markdownlint nixie style-check ## Run the Markdown gates (they join `all` once every document conforms)

define ensure_tool
	@command -v $(1) >/dev/null 2>&1 || { \
	  printf "Error: '%s' is required, but not installed\n" "$(1)" >&2; \
	  exit 1; \
	}
endef

build: ## Create the virtual environment and install the development tools
	$(call ensure_tool,$(UV))
	$(UV) sync --group dev

fmt: ## Format the Python and Markdown sources
	$(RUFF) format $(RUFF_ROOT) $(PYTHON_TARGETS)
	$(RUFF) check $(RUFF_ROOT) --select I --fix $(PYTHON_TARGETS)
	$(PYTHON) tools/check_json.py --root . --write $(JSON_EXCEPTIONS_ARG)
	$(MDTABLEFIX) --in-place $(MDTABLEFIX_RULES) $(MD_AUTHORED)

check-fmt: check-fmt-python check-fmt-markdown ## Verify all formatting

check-fmt-python: ## Verify Python formatting
	$(RUFF) format $(RUFF_ROOT) --check $(PYTHON_TARGETS)

check-fmt-markdown: ## Verify Markdown table and wrapping layout
	$(call ensure_tool,$(MDTABLEFIX))
	@test "$$($(MDTABLEFIX) --version)" = "mdtablefix $(MDTABLEFIX_VERSION)" || { \
	  printf 'Error: mdtablefix %s is required\n' '$(MDTABLEFIX_VERSION)' >&2; exit 1; \
	}
	$(MDTABLEFIX) --check $(MDTABLEFIX_RULES) $(MD_AUTHORED)

json-check: ## Verify that every tracked JSON file is in canonical layout
	$(PYTHON) tools/check_json.py --root . $(JSON_EXCEPTIONS_ARG)

pins-check: ## Verify that each pinned script and evidence .py file is in the local history and carries its recorded hash
	python3 scripts/pinned_source_cli.py check
	$(PYTHON) tools/pinned_evidence_cli.py check --root .

links-check: ## Verify every Markdown link, fragment and mothra reference
	$(PYTHON) tools/check_links.py --root . $(MOTHRA_ARG) --min-links $(LINKS_MIN) $(LINKS_ARGS)

# The run must see at least this many tables, Mermaid blocks and glossary entries, so
# an empty run cannot pass. style-known.json lists accepted current findings.
STYLE_TABLES_MIN ?= 250
STYLE_FIGURES_MIN ?= 10
STYLE_GLOSSARY_MIN ?= 60
STYLE_KNOWN ?= style-known.json

style-check: ## Verify table captions, figure text, fence labels, heading case, person and the glossary
	$(PYTHON) tools/check_style.py check --root . --known $(STYLE_KNOWN) \
		--min-tables $(STYLE_TABLES_MIN) --min-figures $(STYLE_FIGURES_MIN) --min-glossary $(STYLE_GLOSSARY_MIN)

# The run must see at least this many ledger citations and evidence links, so an
# empty run cannot pass. evidence-known.json lists accepted current findings.
EVIDENCE_LEDGER_MIN ?= 400
EVIDENCE_LINKS_MIN ?= 700
EVIDENCE_KNOWN ?= evidence-known.json

evidence-check: ## Verify cited identifiers, scripts, gap statuses, the remaining-work ledger, corpus families and the evidence indexes
	$(PYTHON) tools/check_evidence.py check --root . $(if $(wildcard $(EVIDENCE_KNOWN)),--known $(EVIDENCE_KNOWN)) \
		--min-ledger $(EVIDENCE_LEDGER_MIN) --min-links $(EVIDENCE_LINKS_MIN)

evidence-index: ## Regenerate docs/<set>/evidence.md for every document set
	$(PYTHON) tools/check_evidence.py index --root . --write

# The renderer validates the register against the audit revision it names and
# fails if any audited document has changed since that revision was cut.
audit-check: ## Validate the gap register against the current audit revision and gap-analysis.md
	python3 scripts/render-protocol-gap-analysis.py --check

withheld-check: ## Verify the withheld-files manifest, .gitignore and patches
	$(PYTHON) tools/check_withheld.py check --root .

withheld-scan: ## As withheld-check, and scan every blob of history for withheld content
	$(PYTHON) tools/check_withheld.py check --root . --scan-history

withheld-skip:
	@printf 'withheld-check skipped: evidence/withheld.json does not exist yet\n'

sums-check: ## Verify every SHA256SUMS file under evidence/
	$(PYTHON) tools/check_sums.py check --root .

lfs-check: ## Verify that exactly the PNG, PCAP and gzip evidence is stored in Git LFS
	$(PYTHON) tools/check_sums.py lfs --root .

evidence-skip:
	@printf 'sums-check and lfs-check skipped: evidence/ does not exist yet\n'

curation-check: ## Verify the imported corpora match evidence/curation.json and every citation resolves
	$(PYTHON) tools/curate_evidence.py check --root . $(CITING_ARGS)

import-check: ## As curation-check, and compare every included file with the mothra commit
	@test -n "$(MOTHRA)" || { printf 'Error: no mothra checkout found; set MOTHRA\n' >&2; exit 2; }
	$(PYTHON) tools/curate_evidence.py check --root . $(CITING_ARGS) \
		--source-root $(MOTHRA) --source-commit $(IMPORT_COMMIT)

curation-skip:
	@printf 'curation-check skipped: evidence/curation.json does not exist yet\n'

lint-python: build ## Lint the Python that meets the df12 standards
	$(RUFF) check $(RUFF_ROOT) $(PYTHON_TARGETS)
	$(UV) run --group dev interrogate --fail-under 100 $(INTERROGATE_TARGETS)
	@! $(UV) run --group dev interrogate -vv $(INTERROGATE_TARGETS) | grep -q ' MISSED ' || { printf 'interrogate: a definition has no docstring\n' >&2; exit 1; }
	$(PYLINT) $(PYTHON_TARGETS)
	$(DF12_PYLINT) $(PYTHON_TARGETS)

typecheck: build ## Type-check the Python that meets the df12 standards
	$(TY) --version
	$(TY) check --extra-search-path tools --extra-search-path tests --extra-search-path scripts $(PYTHON_TARGETS)

test: build ## Run the tests of the repository tooling
	$(UV) run --group dev pytest -v

markdownlint: spelling ## Lint Markdown and enforce en-GB-oxendict spelling
	$(call ensure_tool,$(MDLINT))
	env -u NO_COLOR $(MDLINT) $(MD_FILES)

spelling: ## Enforce en-GB-oxendict spelling
	$(TYPOS_CONFIG_BUILDER) gate --repository .

nixie: ## Validate Mermaid diagrams
	$(call ensure_tool,$(NIXIE))
	$(NIXIE) --no-sandbox $(MD_FILES)

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?##' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS=":.*##"; printf "Available targets:\n"} {gsub(/^[[:space:]]+/, "", $$2); printf "  %-20s %s\n", $$1, $$2}'

# Hotline-specific evidence verification, ported from mothra's *-check targets
# (EP-M3-020). None needs a network, an emulator or Ghidra. Two verifiers read
# mothra's general scripts through scripts/mothra_root.py (set MOTHRA_ROOT when
# the checkout is not a sibling). Not ported: the verify_alias_window_profile.py
# recipes (that script stays in mothra) and mothra's general recipes.
# Several corpora carry their own verifier, written for a checkout named
# hotline-protocol-docs with the corpus beneath it. Run those from a scratch tree
# of that name that holds a copy of scripts/ and a hard-linked evidence/, so they
# pass in a checkout or worktree of any name.
# The copy of scripts/ then receives the pinned bytes of every script that a manifest
# or constant names by hash (scripts/pinned-sources.json, decision D29), so a verifier
# held under evidence/ sees the bytes its corpus was recorded against while it imports
# every other module from the current tree.
# The scripts that still read mothra's general tooling find the checkout through
# scripts/mothra_root.py; hand them the one that MOTHRA names.
ifneq ($(MOTHRA),)
export MOTHRA_ROOT ?= $(abspath $(MOTHRA))
endif

define in_legacy_layout
tmp=$$(mktemp -d) && trap 'rm -rf "$$tmp"' EXIT && root="$$tmp/hotline-protocol-docs" && mkdir -p "$$root" && cp -a scripts "$$root/scripts" && python3 scripts/pinned_source_cli.py stage "$$root/scripts" && { cp -al evidence "$$root/evidence" 2>/dev/null || cp -a evidence "$$root/evidence"; } && cd "$$root" && $(1)
endef

.PHONY: evidence-verify evidence-verify-known-red test-legacy

# One recipe per line, in mothra's order, so a failure names its line.
evidence-verify: ## Verify every retained Hotline corpus with its legacy verifier
	d=evidence/gap-remediation/2026-11-24/post-session-preferences-01; jq -e -f "$$d/verify.jq" --rawfile stat "$$d/catalogue-record.txt" --rawfile application "$$d/application-directory.txt" --rawfile staged "$$d/staged-directory.txt" --slurpfile loader evidence/gap-remediation/2026-11-13/receive-limit-origin-01/11-selected-consumer.json "$$d/fork-summary.json"
	d=evidence/gap-remediation/2026-11-24/receive-limit-preferences-01; jq -se -f "$$d/verify.jq" "$$d"/queries/*.json
	python3 scripts/verify_native_path_fields.py --corpus evidence/gap-remediation/2026-11-14/native-path-fields-01
	python3 -m unittest discover -s scripts -p 'test_verify_native_path_fields.py'
	python3 scripts/verify_native_rate304_sequence.py --corpus evidence/gap-remediation/2026-11-14/native-rate304-sequence-01
	python3 scripts/verify_native_rate304_partial.py --corpus evidence/gap-remediation/2026-11-14/native-rate304-first-pair-01
	python3 scripts/verify_native_board.py --corpus evidence/gap-remediation/2026-11-14/native-board-01
	python3 scripts/verify_native_liveness.py --corpus evidence/gap-remediation/2026-11-14/native-liveness-01
	python3 scripts/verify_native_roster_overlap.py --corpus evidence/gap-remediation/2026-11-14/native-roster-overlap-01
	python3 scripts/verify_native_ban_expiry_later.py evidence/gap-remediation/2026-11-14/native-ban-expiry-later-01
	python3 scripts/verify_native_ban_expiry_first.py evidence/gap-remediation/2026-11-14/native-ban-expiry-first-01
	python3 scripts/verify_native_ban_reload.py evidence/gap-remediation/2026-11-14/native-ban-reload-01
	python3 scripts/verify_native_settings_persistence.py evidence/gap-remediation/2026-11-14/native-settings-persistence-01
	python3 scripts/verify_classic_roster_subject_115.py evidence/gap-remediation/2026-11-14/classic-roster-subject-115-01
	python3 scripts/verify_native_configured_ban.py evidence/gap-remediation/2026-11-14/native-configured-ban-01
	python3 scripts/verify_classic_server_name_162.py evidence/gap-remediation/2026-11-14/classic-server-name-162-01
	python3 scripts/verify_native_ban_control.py evidence/gap-remediation/2026-11-14/native-ban-control-01
	python3 scripts/verify_classic_native_baseline.py evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01
	python3 scripts/verify_native_ui_focus.py evidence/gap-remediation/2026-11-14/native-ui-focus-01
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-14/native-121-defaults-01/verify_packets.py)
	$(call in_legacy_layout,python3 -m unittest discover -s evidence/gap-remediation/2026-11-14/native-121-defaults-01 -p test_verify_packets.py)
	python3 scripts/verify_native_transfer_repeat.py evidence/gap-remediation/2026-11-14/native-transfer-repeat-01
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/native-settings-transitions-01/verify_packets.py)
	$(call in_legacy_layout,python3 -m unittest discover -s evidence/gap-remediation/2026-11-13/native-settings-transitions-01 -p test_verify_packets.py)
	python3 scripts/verify_classic_account_constructors.py
	python3 -m pytest -q -p no:cacheprovider scripts/tests/test_verify_classic_account_constructors.py::ClassicAccountConstructorsTest
	python3 scripts/verify_native_download_send_path.py evidence/gap-remediation/2026-11-13/native-download-send-path-01
	python3 scripts/verify_native_transfer_stall.py evidence/gap-remediation/2026-11-13/native-transfer-stall-01
	python3 scripts/verify_native_ban_one.py evidence/gap-remediation/2026-11-13/native-ban-one-01
	python3 scripts/verify_native_settings_corpus.py evidence/gap-remediation/2026-11-13/native-settings-01
	python3 scripts/verify_native_pm_packet.py evidence/gap-remediation/2026-11-13/native-pm-01
	python3 scripts/verify_native_console_broadcast.py evidence/gap-remediation/2026-11-13/native-console-broadcast-01
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/failure-criterion-review-01/verify.py.txt)
	python3 -m pytest -q -p no:cacheprovider scripts/tests/test_request500_client_source.py::ChainTests
	python3 scripts/protocol_capture.py verify evidence/gap-remediation/2026-11-12/capture-tooling-01/transcript
	python3 scripts/protocol_capture.py verify evidence/gap-remediation/2026-11-12/native-handshake-01/transcript
	python3 scripts/verify_native_core.py evidence/gap-remediation/2026-11-12/native-core-01
	python3 scripts/verify_native_handshakes.py evidence/gap-remediation/2026-11-12/native-transport-01
	python3 scripts/verify_native_framing.py evidence/gap-remediation/2026-11-12/native-framing-01
	python3 scripts/verify_native_forks.py evidence/gap-remediation/2026-11-12/native-forks-01
	python3 scripts/verify_native_resume.py evidence/gap-remediation/2026-11-12/native-resume-01
	python3 scripts/verify_native_queues.py evidence/gap-remediation/2026-11-12/native-queue-01
	python3 scripts/verify_native_cleanup.py evidence/gap-remediation/2026-11-12/native-cleanup-01
	python3 scripts/verify_native_folders.py evidence/gap-remediation/2026-11-12/native-folder-01
	python3 scripts/verify_native_banners.py evidence/gap-remediation/2026-11-12/native-banner-01
	python3 scripts/verify_native_banner_formats.py evidence/gap-remediation/2026-11-12/native-banner-02
	python3 scripts/verify_native_htxf.py evidence/gap-remediation/2026-11-12/native-htxf-01
	python3 scripts/verify_native_correlation.py evidence/gap-remediation/2026-11-12/native-correlation-01
	python3 scripts/verify_native_auth.py evidence/gap-remediation/2026-11-13/native-auth-01
	python3 scripts/verify_native_agreements.py evidence/gap-remediation/2026-11-13/native-agreement-01
	python3 scripts/verify_native_login_extras.py evidence/gap-remediation/2026-11-13/native-login-extras-01
	python3 scripts/verify_native_shx.py evidence/gap-remediation/2026-11-13/native-shx-01
	python3 scripts/verify_native_shx_extras.py evidence/gap-remediation/2026-11-13/native-shx-02
	python3 scripts/verify_native_mkdir.py evidence/gap-remediation/2026-11-13/native-mkdir-01
	python3 scripts/verify_native_aliases.py evidence/gap-remediation/2026-11-13/native-alias-01
	python3 scripts/verify_native_metadata.py evidence/gap-remediation/2026-11-13/native-metadata-01
	python3 scripts/verify_native_moves.py evidence/gap-remediation/2026-11-13/native-move-01
	python3 scripts/verify_native_news.py evidence/gap-remediation/2026-11-13/native-news-01
	python3 scripts/verify_native_article_deletion.py evidence/gap-remediation/2026-11-13/native-article-delete-01
	python3 scripts/verify_native_news_boundary.py evidence/gap-remediation/2026-11-13/native-news-boundary-01
	python3 scripts/verify_native_account_updates.py evidence/gap-remediation/2026-11-13/native-account-update-01
	python3 scripts/verify_native_live_accounts.py evidence/gap-remediation/2026-11-13/native-live-accounts-01
	python3 scripts/verify_native_account_batches.py evidence/gap-remediation/2026-11-13/native-account-batch-01
	python3 scripts/verify_native_account_identity.py evidence/gap-remediation/2026-11-13/native-account-identity-01
	python3 scripts/verify_native_rooms.py evidence/gap-remediation/2026-11-13/native-rooms-01
	python3 scripts/verify_native_diagnostics.py evidence/gap-remediation/2026-11-13/native-diagnostics-01
	python3 scripts/verify_peer_tolerance.py evidence/gap-remediation/2026-11-13/delegated-peer-01 --source evidence/gap-remediation/2026-11-13
	python3 scripts/verify_mxd_reconciliation.py evidence/gap-remediation/2026-11-13/delegated-mxd-01
	python3 scripts/verify_native_bitmaps.py evidence/gap-remediation/2026-11-13/native-bitmaps-01
	python3 scripts/verify_account_attribute.py evidence/gap-remediation/2026-11-13/account-attribute-01 --root .
	python3 scripts/verify_mxd_limits.py evidence/gap-remediation/2026-11-13/mxd-limits-01
	python3 scripts/verify_native_diagnostic_load.py evidence/gap-remediation/2026-11-13/native-diagnostic-load-01
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/verify.py)
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/native-diagnostic-existing-01/verify_packets.py)
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/native-diagnostic-density-01/verify_density.py)
	python3 scripts/verify_mxd_correction.py evidence/gap-remediation/2026-11-13/mxd-correction-01
	python3 scripts/verify_mxd_direct_ack.py evidence/gap-remediation/2026-11-13/mxd-direct-ack-02
	$(call in_legacy_layout,python3 evidence/gap-remediation/2026-11-13/native-diagnostic-near-01/verify_partial.py)
	python3 scripts/verify_mxd_login_extras.py --evidence evidence/gap-remediation/2026-11-13/mxd-login-extras-01
	python3 scripts/verify_mac_peer_isolated_session.py evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01
	python3 scripts/verify_mac_peer_first_session.py evidence/gap-remediation/2026-11-13/mac-peer-first-session-01
	python3 scripts/verify-shx-login-fragment.py
	python3 scripts/verify-synhx-profiles.py
	sha256sum --quiet -c evidence/hotline-server-1.9/SHA256SUMS
	python3 scripts/extract-synhxd-evidence.py
	python3 scripts/verify-baseline-evidence.py
	python3 -m pytest -q -p no:cacheprovider scripts/tests/test_alias_record_v2.py::AliasRecordV2Tests
	python3 -m pytest -q -p no:cacheprovider scripts/tests/test_classic_proxy_rehearsal.py::ClassicProxyRehearsalTests
	python3 scripts/verify_classic_proxy_rehearsal.py evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01
	$(call in_legacy_layout,bash evidence/gap-remediation/2026-11-13/native-runtime-recovery-01/verify-smoke.txt "$$root")

# Known red (decision D18): the corpus records the SHA-256 of mothra's general
# scripts/capture_readiness.py, which has changed since the corpus was recorded.
# The expected result is ValueError: capture gate source identity.
evidence-verify-known-red: ## Run the verifier that is known to fail (decision D18)
	python3 scripts/verify_classic_field161_matrix.py evidence/gap-remediation/2026-11-14/classic-field161-01

# The one unittest file left beside the scripts is the path-fields control that
# evidence-verify runs by name. The golden test oracle reads this recipe.
test-legacy: ## Run the unittest files that remain beside the scripts
	python3 -m unittest discover -s scripts -p 'test_*.py'

# Not in `all`: it re-runs every legacy verifier, planner and test, which takes
# three to ten minutes. Run it after each change to a script family, with
# GOLDENS_FILTER set to the family's name to compare that family alone.
GOLDENS_FILTER ?=
GOLDENS_FILTER_ARGS = $(foreach f,$(GOLDENS_FILTER),--filter $(f))

goldens-check: build ## Compare the legacy scripts with tests/goldens (three to ten minutes; not in all)
	$(PYTHON) tools/capture_goldens.py compare --root . $(if $(MOTHRA),--mothra $(MOTHRA)) $(GOLDENS_FILTER_ARGS)

# Not in `all`, for the same reason as goldens-check. Decision D29: once every comparison
# reads a script at its pinned commit, a comment appended to any pinned script must leave
# the goldens at 0 differences.
pin-experiment: build ## Append a comment to every pinned script, compare the goldens, restore the scripts (three to ten minutes; not in all)
	$(PYTHON) tools/pin_experiment.py run --root . $(if $(MOTHRA),--mothra $(MOTHRA))

# Not in `all`: it runs the tests that reach each changed pinned script against both
# its pinned bytes and its current bytes. Run it with goldens-check after changing a
# pinned script (decision D29).
continuity-tests: build ## Run the error-order and corpus-fault tests of the migrated scripts (several minutes; not in all)
	$(UV) run --group dev pytest -m continuity

pin-equivalence: build ## Check that each changed pinned script behaves as its pinned bytes do (several minutes; not in all)
	$(UV) run --group dev pytest -m pin_equivalence tests/test_pin_equivalence.py

