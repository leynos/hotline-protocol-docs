# Reproducing the protocol evidence baseline

The guide and supplements depend on hashed native evidence in the sibling
`mothra` checkout. A pair of committed source revisions plus their exported
archives makes those references portable. The immutable validity ledger,
original inputs and successive reviewed snapshots remain part of the export.
This is the packaging procedure for GAP-087.

## Build a revision-pinned package

Commit the intended changes in both repositories. From `mothra`, run:

```sh
python3 scripts/package-protocol-evidence.py
```

The script refuses tracked changes and an existing destination. It writes two
archives, a manifest containing both full commit IDs, extraction instructions
and SHA256SUMS beneath `mothra/state/protocol-exports/`. Its directory name
contains the two abbreviated revisions. Archives contain committed files and
preserve the sibling directory names; installed toolchains and runtime caches
are kept separately. Building this local package does not publish it.

The manifest identifies the exact document/evidence pair. Git HEAD alone is
not sufficient to identify uncommitted historical sources, so their original
snapshot hashes and worktree metadata are retained too. Ghidra addresses remain
tied to the full binary hash in each query record, not merely an application
name or an address copied into prose.

## Verify and extract elsewhere

From the package directory, verify its outer checksums:

```sh
sha256sum --quiet -c SHA256SUMS
```

Extract both archives into the same empty parent directory:

```sh
tar -xzf mothra.tar.gz
tar -xzf hotline-protocol-docs.tar.gz
cd mothra
python3 scripts/extract-synhxd-evidence.py
python3 scripts/verify-baseline-evidence.py
python3 scripts/render-protocol-gap-analysis.py --check
```

Also check every retained `evidence/**/SHA256SUMS` from the extracted `mothra`
directory. Those files use paths relative to that directory. The renderer checks
current document/snapshot hashes, stable IDs, source section coverage, dependency
cycles and local links. Full `make check` additionally needs the lint, type and
diagram tools described in mothra's README; re-querying the binary needs its
local Ghidra/MCP installation.

## Updating evidence without rewriting history

New investigations use a new batch directory and unique query IDs. Keep raw
queries, plans and exports unchanged once committed and hashed. When documents
change, review the changed sections, capture a new manifest and section inventory,
and update current register locations/coverage to that new snapshot. Old dated
snapshots remain unchanged. Regenerate `gap-analysis.md` from `gap-register.json`
and run `make check` before committing the reviewed pair.

Resolved records retain their evidence and closure rationale. If a static
criterion is satisfied but native wire/peer fixtures are still required by a
separate gap, record that distinction explicitly rather than implying native
execution. Deferred records need a scope decision and revisit condition. Stable
gap IDs must not be renumbered or deleted because a document was reorganized.
