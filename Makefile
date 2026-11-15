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
# Inherited capture and verification scripts, held at their earlier rules by
# scripts/ruff.toml.
LEGACY_PYTHON = scripts
# Evidence is preserved byte for byte, so no Markdown tool may select it.
MD_FILES = $(shell git ls-files --cached --others --exclude-standard '*.md' ':!:evidence/**')

.PHONY: help all build fmt check-fmt check-fmt-python check-fmt-markdown \
	lint-python lint-legacy typecheck test docs-gates markdownlint spelling nixie

.DEFAULT_GOAL := all
# Shared build caches require sequential gates even when make receives -j.
.NOTPARALLEL:

all: build check-fmt-python lint-python lint-legacy typecheck test ## Run the gates that must pass at every commit

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
	$(MDTABLEFIX) --in-place $(MDTABLEFIX_RULES) $(MD_FILES)

check-fmt: check-fmt-python check-fmt-markdown ## Verify all formatting

check-fmt-python: ## Verify Python formatting
	$(RUFF) format --check $(PYTHON_TARGETS)

check-fmt-markdown: ## Verify Markdown table and wrapping layout
	$(call ensure_tool,$(MDTABLEFIX))
	@test "$$($(MDTABLEFIX) --version)" = "mdtablefix $(MDTABLEFIX_VERSION)" || { \
	  printf 'Error: mdtablefix %s is required\n' '$(MDTABLEFIX_VERSION)' >&2; exit 1; \
	}
	$(MDTABLEFIX) --check $(MDTABLEFIX_RULES) $(MD_FILES)

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
	$(TY) check $(PYTHON_TARGETS)

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
