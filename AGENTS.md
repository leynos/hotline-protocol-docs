# Agent instructions

This repository documents the Hotline 1.9 wire protocol from retained evidence.
Read this file before changing anything.

## What lives where

- Protocol documents are Markdown, grouped by subject under `docs/<set>/`. They
  state only what the cited evidence supports and label everything else as
  unresolved. `docs/glossary.md` defines the terms they use.
- `gap-register.json` is the canonical list of open questions. `gap-analysis.md`
  is generated from it and is never edited by hand.
- `scripts/` holds the inherited capture planners and `verify_*.py` evidence
  checkers. Documents and evidence records cite them by file name.
- `tools/` holds the repository's own checking tools, with tests in `tests/`.
- `docs/execplans/` holds execution plans. While a plan is in progress it is
  the authority for scope, constraints and order of work; keep it current.
- `docs/documentation-style-guide.md` is a verbatim upstream copy. Do not edit
  it.

## Rules that protect the evidence

- Never change the meaning of a protocol claim to make a check pass. If two
  documents disagree and the evidence does not decide, record the disagreement
  and stop for that item.
- Never add, remove, re-status or re-word a gap in the register as a side
  effect of other work.
- Never rewrite, reformat or lint a file under `evidence/`. Its bytes are
  covered by recorded hashes. The one exception is a `.py` file there, which
  may gain docstrings and nothing else: `scripts/pinned-evidence.json` names
  the commit at which each carries its recorded hash, and `make pins-check`
  rejects any other change to the code.
- Never alter a quoted byte string, hash, address or wire token to satisfy the
  spelling gate. Put the token in backticks, or add an exact entry to
  `typos.local.toml`.
- Every protocol document is a hashed input to the gap audit. After editing
  one, refresh the audit before committing; the plan in `docs/execplans/`
  describes how.
- A verifier script must reach the same verdict on every retained corpus
  before and after any change to it.

## Gates

Run gates one at a time, never in parallel, and commit only when they pass.

- `make all`: the Python gates and the tests. Required before every commit.
- `make docs-gates`: Markdown layout, markdownlint, spelling and Mermaid
  validation. Run it for every Markdown change. It joins `make all` once every
  inherited document conforms.
- `make fmt`: format Python and Markdown. It never touches `evidence/`.
- `make help`: list every target.

## Python

New and changed Python follows the df12 standards configured in
`pyproject.toml`: Ruff with the full rule selection, numpy-style docstrings,
complete type annotations checked by `ty`, pytest tests, Cyclopts for command
lines, `pathlib` for paths, and modules under 400 lines. Write the failing test
first. A lint suppression must be scoped to one line and state its reason. The
inherited scripts in `scripts/` meet the same standard.

## Markdown

Follow `docs/documentation-style-guide.md`. In brief: British English with
Oxford spelling; sentence-case headings; prose wrapped at 80 columns and code
at 120; tables unwrapped; a caption beneath every table and figure; a paragraph
beginning "For screen readers:" before every Mermaid diagram; no first or
second person outside `README.md`.

## The mothra toolset

Evidence is captured with the general toolset in `leynos/mothra`. That
repository must not contain anything specific to this project. Link to it only
by absolute GitHub URL, never by a relative path, and do not copy its set-up
guidance here.

<!-- typos-config-builder:agents-md:start -->

## Spelling

- `make spelling` runs the pinned `typos-config-builder gate`, which
  regenerates `typos.toml` from the shared en-GB-oxendict dictionary and
  `typos.local.toml`, then checks spelling and the shared phrase corrections.
- `typos.toml` is generated: never edit it by hand. Put narrow
  repository-specific exceptions in `typos.local.toml`, as exact or full-line
  patterns rather than bare accepted words.
- When `make spelling` changes `typos.toml`, commit the regenerated file. If
  the change is unrelated to your work, commit it in a separate base pull
  request and stack your branch on it, so each review diff stays focused.

<!-- typos-config-builder:agents-md:end -->
