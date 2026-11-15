#!/usr/bin/env bash
set -euo pipefail
export PATH=/home/leynos/.cargo/bin:/home/leynos/.local/bin:/usr/local/bin:/usr/bin:/bin
export CARGO_TARGET_DIR=/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/mxd-target
export CARGO_NET_OFFLINE=true
export CARGO_BUILD_JOBS=1
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
cd /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd
printf '%s\n' "$(date -u +'%Y-%m-%d %H:%M:%S UTC')" > /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c7-direct-ack/full-test-extension.started
exec /usr/bin/make --no-print-directory --eval 'test-rstest-bdd-ui: export CARGO_TARGET_DIR := /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mxd/target' test >> /data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd/mothra/state/delegation/c7-direct-ack/full-test-extension.log 2>&1
