#!/bin/bash
# shellcheck disable=SC2024
# Prepared operator command; output belongs to the owned lab epoch.
set -euo pipefail
# PREPARED ONLY. Requires a separate live START and approved source pin.
BOARD_ROOT=/data/leynos/Projects/mothra
BOARD_PREP=$BOARD_ROOT/state/native-sessions/native-path-fields-preparation-01
BOARD_R=$BOARD_ROOT/state/mac-runtime/native-path-fields-01
BOARD_D=$BOARD_ROOT/state/mac-displays/native-path-fields-01
BOARD_O=$BOARD_ROOT/state/native-sessions/native-path-fields-epoch-01
BOARD_LOCK=$BOARD_ROOT/state/delegation/oracle.lock
cd "$BOARD_ROOT"
test -s "$BOARD_PREP/approved-helpers.sha256"
# Approval pins are intentionally absent until root reviews A112/B96.
test -s "$BOARD_PREP/approved-path-fields-sources.sha256"
test -s "$BOARD_PREP/approved-source-closure.sha256"
test -s "$BOARD_PREP/script-SHA256SUMS"
(cd "$BOARD_ROOT" && sha256sum --quiet -c "$BOARD_PREP/approved-helpers.sha256")
(cd "$BOARD_ROOT" && sha256sum --quiet -c "$BOARD_PREP/script-SHA256SUMS")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-path-fields-sources.sha256")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-source-closure.sha256")
python3 - "$BOARD_PREP/approved-source-closure.sha256" "$BOARD_PREP/proposed-source-closure.json" /data/leynos/Projects/hotline-protocol-docs <<'PY'
import hashlib
import json
import pathlib
import sys

pin, proposal, docs = map(pathlib.Path, sys.argv[1:])
proposed = json.loads(proposal.read_text())['hashes']
lines = pin.read_text().splitlines()
assert len(lines) == len(proposed) and len(proposed) >= 2
entries = [line.split() for line in lines]
assert all(len(entry) == 2 for entry in entries)
approved = {path: digest for digest, path in entries}
assert len(approved) == len(proposed)
assert approved == {f'scripts/{name}': digest for name, digest in proposed.items()}
for name, digest in approved.items():
    assert len(digest) == 64 and all(c in '0123456789abcdef' for c in digest)
    assert hashlib.sha256((docs / name).read_bytes()).hexdigest() == digest
PY
test ! -e "$BOARD_D" && test ! -e "$BOARD_O" && test ! -e /tmp/.X11-unix/X120
# Root holder proof must precede every owned disk/ROM byte read. Keep the
# stopped preparation separate from the future epoch directory.
for name in base.dsk working.dsk rom; do
    if sudo -n fuser "$BOARD_R/$name" > "$BOARD_PREP/boot-prehash-$name.stdout" 2> "$BOARD_PREP/boot-prehash-$name.stderr"; then
        code=0
    else
        code=$?
    fi
    printf '%s\n' "$code" > "$BOARD_PREP/boot-prehash-$name.exit"
    test "$code" = 1 && test ! -s "$BOARD_PREP/boot-prehash-$name.stdout" && test ! -s "$BOARD_PREP/boot-prehash-$name.stderr"
done
for pair in 'base.dsk 5999397981' 'working.dsk 5999397982' 'rom 5999397980'; do
    read -r name inode <<< "$pair"
    test "$(stat -c %i "$BOARD_R/$name")" = "$inode"
done
test "$(sha256sum "$BOARD_R/base.dsk" | cut -d' ' -f1)" = e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910
test "$(sha256sum "$BOARD_R/working.dsk" | cut -d' ' -f1)" = e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910
test "$(sha256sum "$BOARD_R/rom" | cut -d' ' -f1)" = 18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd
test "$(sha256sum tools/macemu/SheepShaver/src/Unix/SheepShaver | cut -d' ' -f1)" = 9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4
flock --exclusive --nonblock "$BOARD_LOCK" true
mkdir -m 700 "$BOARD_O"
if sudo -n fuser "$BOARD_R/working.dsk" > "$BOARD_O/pre-fuser.stdout" 2> "$BOARD_O/pre-fuser.stderr"; then
    printf 'Working image unexpectedly held\n' >&2; exit 1
else
    code=$?; test "$code" = 1
fi
ss -ltn > "$BOARD_O/pre-ports.txt"
if rg -q ':(15900|15901|15902|15903)\b' "$BOARD_O/pre-ports.txt"; then
    printf 'Path-fields frontend port occupied\n' >&2; exit 1
fi
python3 - <<'PY'
from pathlib import Path
expected={1099659:'767842',1012834:'2357813'}
for pid,tick in expected.items():
    raw=Path(f'/proc/{pid}/stat').read_text()
    assert raw[raw.rfind(')')+2:].split()[19]==tick
PY
# Fix the sole epoch window immediately before the first managed service.
python3 - <<'PY'
import datetime as dt
from pathlib import Path
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-path-fields-epoch-01')
start=dt.datetime.now(dt.UTC)
(p/'epoch-start.utc').write_text(start.isoformat()+'\n')
(p/'case-deadline.utc').write_text((start+dt.timedelta(minutes=12)).isoformat()+'\n')
PY
sudo -n systemd-run --unit=mothra-native-path-fields-01-lease --property=Type=exec --property=User=1000 --property=Group=1000 --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/bin/flock --exclusive --nonblock "$BOARD_LOCK" /usr/bin/sleep 900 > "$BOARD_O/lease-launch.stdout"
# Wait at most five seconds for the actual lease PID and lock FD.
sudo -n python3 "$BOARD_PREP/wait-managed-path-fields-01.py" --unit mothra-native-path-fields-01-lease.service --lock "$BOARD_LOCK" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/lease-initial-wait.json" > "$BOARD_O/lease-initial-wait.stdout"
# Fail closed if the lease did not become active and exclusive.
sudo -n systemctl show mothra-native-path-fields-01-lease.service -p MainPID -p ActiveState > "$BOARD_O/lease-initial-show.txt"
rg -q '^ActiveState=active$' "$BOARD_O/lease-initial-show.txt"
if flock --exclusive --nonblock "$BOARD_LOCK" true; then
    printf 'Oracle lease did not hold lock\n' >&2; exit 1
fi
sudo -n systemd-run --unit=mothra-native-path-fields-01-host --property=Type=exec --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/sbin/tcpdump -i lo -U -n -s 0 -w "$BOARD_O/primary-syn.pcap" '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' > "$BOARD_O/host-launch.stdout"
sudo -n python3 "$BOARD_PREP/wait-managed-path-fields-01.py" --unit mothra-native-path-fields-01-host.service --pcap "$BOARD_O/primary-syn.pcap" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/host-initial-wait.json" > "$BOARD_O/host-initial-wait.stdout"
sudo -n python3 scripts/capture_readiness.py --unit mothra-native-path-fields-01-host.service --pcap "$BOARD_O/primary-syn.pcap" --netns-inode "$(stat -Lc %i /proc/self/ns/net)" --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --filter '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' > "$BOARD_O/host-ready.json"
python3 scripts/mac_runtime.py display "$BOARD_D" --display :120 > "$BOARD_O/display-launch.stdout"
xdpyinfo -display :120 >/dev/null
python3 scripts/mac_runtime.py sheep "$BOARD_R" --display :120 --port 15900 --guest-pcap "$BOARD_O/lab-guest.pcap" --service --isolate-network > "$BOARD_O/sheep-launch.stdout"
# Disk phase only: guest capture opens lazily on first Ethernet activity.
# No guest PCAP is created or inspected in this boot script.
sudo -n python3 scripts/native_emulator_readiness.py --phase disk --working-image "$BOARD_R/working.dsk" --working-inode 5999397982 --exe-sha256 9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4 --uid 1000 --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/disk-ready.json" > "$BOARD_O/disk-ready.stdout"
