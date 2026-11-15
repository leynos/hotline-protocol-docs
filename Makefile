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

# Python that meets the df12 standards in pyproject.toml. The inherited scripts
# in scripts/ join this list as each family is brought to that standard.
PYTHON_TARGETS = $(shell git ls-files --cached --others --exclude-standard \
	'tools/*.py' 'tools/**/*.py' 'tests/*.py' 'tests/**/*.py')
# The repository tools run in the project environment.
PYTHON ?= $(UV) run --group dev python
# Evidence JSON that cannot be canonical is exempted by hash in this file, once
# it exists (see tools/check_json.py).
JSON_EXCEPTIONS ?= json-exceptions.txt
JSON_EXCEPTIONS_ARG = $(if $(wildcard $(JSON_EXCEPTIONS)),--exceptions $(JSON_EXCEPTIONS))
# The sibling mothra checkout that the documents still link into with
# ../mothra/ paths. A later milestone replaces those links with permalinks and
# adds --forbid-relative-mothra to LINKS_ARGS.
MOTHRA ?= $(firstword $(wildcard ../mothra ../../mothra))
MOTHRA_ARG = $(if $(MOTHRA),--mothra $(MOTHRA))
# The run must examine at least this many links, so an empty run cannot pass.
LINKS_MIN ?= 2000
LINKS_ARGS ?=
# Inherited capture and verification scripts, held at their earlier rules by
# scripts/ruff.toml.
LEGACY_PYTHON = scripts
# Evidence is preserved byte for byte, so no Markdown tool may select it.
MD_FILES = $(shell git ls-files --cached --others --exclude-standard '*.md' ':!:evidence/**')
# gap-analysis.md is generated from gap-register.json; its layout belongs to the
# renderer, so it is linted but never reflowed.
MD_AUTHORED = $(filter-out gap-analysis.md,$(MD_FILES))

# The withheld-files gate needs the manifest that the evidence import creates;
# until it exists the gate is skipped, with a message.
WITHHELD_GATE = $(if $(wildcard evidence/withheld.json),withheld-check,withheld-skip)

# The evidence gates need the imported evidence/ directory.
EVIDENCE_GATE = $(if $(wildcard evidence),sums-check lfs-check,evidence-skip)

.PHONY: help all build fmt check-fmt check-fmt-python check-fmt-markdown \
	lint lint-python lint-legacy typecheck test docs-gates markdownlint spelling nixie \
	json-check links-check audit-check withheld-check withheld-scan withheld-skip \
	sums-check lfs-check evidence-skip

.DEFAULT_GOAL := all
# Shared build caches require sequential gates even when make receives -j.
.NOTPARALLEL:

all: build check-fmt-python json-check links-check $(WITHHELD_GATE) $(EVIDENCE_GATE) lint-python lint-legacy typecheck test ## Run the gates that must pass at every commit

lint: lint-python lint-legacy ## Run every Python linter

docs-gates: check-fmt-markdown markdownlint nixie ## Run the Markdown gates (they join `all` once every document conforms)

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
	$(RUFF) format $(PYTHON_TARGETS)
	$(RUFF) check --select I --fix $(PYTHON_TARGETS)
	$(PYTHON) tools/check_json.py --root . --write $(JSON_EXCEPTIONS_ARG)
	$(MDTABLEFIX) --in-place $(MDTABLEFIX_RULES) $(MD_AUTHORED)

check-fmt: check-fmt-python check-fmt-markdown ## Verify all formatting

check-fmt-python: ## Verify Python formatting
	$(RUFF) format --check $(PYTHON_TARGETS)

check-fmt-markdown: ## Verify Markdown table and wrapping layout
	$(call ensure_tool,$(MDTABLEFIX))
	@test "$$($(MDTABLEFIX) --version)" = "mdtablefix $(MDTABLEFIX_VERSION)" || { \
	  printf 'Error: mdtablefix %s is required\n' '$(MDTABLEFIX_VERSION)' >&2; exit 1; \
	}
	$(MDTABLEFIX) --check $(MDTABLEFIX_RULES) $(MD_AUTHORED)

json-check: ## Verify that every tracked JSON file is in canonical layout
	$(PYTHON) tools/check_json.py --root . $(JSON_EXCEPTIONS_ARG)

links-check: ## Verify every Markdown link, fragment and mothra reference
	$(PYTHON) tools/check_links.py --root . $(MOTHRA_ARG) --min-links $(LINKS_MIN) $(LINKS_ARGS)

# The renderer hard-codes root.parent / "hotline-protocol-docs", so this checks
# the MAIN checkout of this repository, not the current worktree. It is
# therefore not part of `all` yet. A later milestone imports the renderer into
# this repository, after which the target joins `all`.
audit-check: ## Validate the gap register with mothra's renderer (main checkout only)
	@test -n "$(MOTHRA)" || { printf 'Error: no mothra checkout found; set MOTHRA\n' >&2; exit 2; }
	python3 $(MOTHRA)/scripts/render-protocol-gap-analysis.py --check

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

lint-python: build ## Lint the Python that meets the df12 standards
	$(RUFF) check $(PYTHON_TARGETS)
	$(UV) run --group dev interrogate --fail-under 100 $(PYTHON_TARGETS)
	$(PYLINT) $(PYTHON_TARGETS)
	$(DF12_PYLINT) $(PYTHON_TARGETS)

lint-legacy: ## Lint the inherited scripts at their earlier rules
	$(RUFF) check $(LEGACY_PYTHON)
	$(RUFF) format --check $(LEGACY_PYTHON)

typecheck: build ## Type-check the Python that meets the df12 standards
	$(TY) --version
	$(TY) check --extra-search-path tools --extra-search-path tests $(PYTHON_TARGETS)

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
