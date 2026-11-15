#!/usr/bin/env bash
set -euo pipefail
export PATH=/home/leynos/.cargo/bin:/home/leynos/.local/bin:/usr/local/bin:/usr/bin:/bin
export CARGO_TARGET_DIR=/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/mxd-target
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=1
export NEXTEST_TEST_THREADS=2
export PG_EMBED_ROOT=/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c9-full/root
export PG_RUNTIME_DIR=/var/tmp/pg-embed-1000/install
unset PG_DATA_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
test -f /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c9-full/watch/ready
test -x "$PG_RUNTIME_DIR/18.6.0/bin/pg_ctl"
cd /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd
printf '%s\n' "$(date -u +'%Y-%m-%d %H:%M:%S UTC')" > /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c9-full/full.started
exec /usr/bin/make --no-print-directory --eval 'test-rstest-bdd-ui: export CARGO_TARGET_DIR := /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd/target' test >> /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c9-full/full.log 2>&1
