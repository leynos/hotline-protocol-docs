#!/usr/bin/env bash
set -euo pipefail
base=/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c11/full
export PATH=/home/leynos/.cargo/bin:/home/leynos/.local/bin:/usr/local/bin:/usr/bin:/bin
export CARGO_TARGET_DIR=/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/mxd-target
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=1
export NEXTEST_TEST_THREADS=2
export PG_EMBED_ROOT="$base/root"
export PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install
unset PG_DATA_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
cd /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd
printf '%s\n' "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" > "$base/full.started"
set +e
/usr/bin/make --no-print-directory --eval 'test-rstest-bdd-ui: export CARGO_TARGET_DIR := /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd/target' test > "$base/full.log" 2>&1
status=$?
set -e
printf '%s\n' "$status" > "$base/full.exit"
exit "$status"
