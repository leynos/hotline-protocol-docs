#!/bin/bash
# shellcheck disable=SC2024
# Redirect privileged command output as the unprivileged owner of BOARD_O.
set -euo pipefail
# PREPARED ONLY. Requires a separate live START and approved source pin.
BOARD_ROOT=/data/leynos/Projects/mothra
BOARD_PREP=$BOARD_ROOT/state/native-sessions/native-rate304-preparation-02
BOARD_R=$BOARD_ROOT/state/mac-runtime/native-rate304-02
BOARD_D=$BOARD_ROOT/state/mac-displays/native-rate304-02
BOARD_O=$BOARD_ROOT/state/native-sessions/native-rate304-epoch-02
BOARD_LOCK=$BOARD_ROOT/state/delegation/oracle.lock
cd "$BOARD_ROOT"
test -f "$BOARD_PREP/approved-helper.sha256"
# B91 sources are proposed; root supplies the exact pin after review.
test -s "$BOARD_PREP/approved-rate304-sources.sha256"
test -s "$BOARD_PREP/wait-managed-r02.py"
(cd "$BOARD_ROOT" && sha256sum --quiet -c "$BOARD_PREP/approved-helper.sha256")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-rate304-sources.sha256")
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
for pair in 'base.dsk 77099976' 'working.dsk 65602436' 'rom 65578607'; do
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
if rg -q ':(15880|15881|15882|15883)\b' "$BOARD_O/pre-ports.txt"; then
    printf 'Rate 304 frontend port occupied\n' >&2; exit 1
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
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-rate304-epoch-02')
start=dt.datetime.now(dt.UTC)
(p/'epoch-start.utc').write_text(start.isoformat()+'\n')
(p/'case-deadline.utc').write_text((start+dt.timedelta(minutes=12)).isoformat()+'\n')
PY
sudo -n systemd-run --unit=mothra-native-rate304-r02-lease --property=Type=exec --property=User=1000 --property=Group=1000 --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/bin/flock --exclusive --nonblock "$BOARD_LOCK" /usr/bin/sleep 900 > "$BOARD_O/lease-launch.stdout"
# Wait at most five seconds for the actual lease PID and lock FD.
sudo -n python3 "$BOARD_PREP/wait-managed-r02.py" --unit mothra-native-rate304-r02-lease.service --lock "$BOARD_LOCK" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/lease-initial-wait.json" > "$BOARD_O/lease-initial-wait.stdout"
# Fail closed if the lease did not become active and exclusive.
sudo -n systemctl show mothra-native-rate304-r02-lease.service -p MainPID -p ActiveState > "$BOARD_O/lease-initial-show.txt"
rg -q '^ActiveState=active$' "$BOARD_O/lease-initial-show.txt"
if flock --exclusive --nonblock "$BOARD_LOCK" true; then
    printf 'Oracle lease did not hold lock\n' >&2; exit 1
fi
sudo -n systemd-run --unit=mothra-native-rate304-r02-host --property=Type=exec --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/sbin/tcpdump -i lo -U -n -s 0 -w "$BOARD_O/primary-syn.pcap" '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' > "$BOARD_O/host-launch.stdout"
sudo -n python3 "$BOARD_PREP/wait-managed-r02.py" --unit mothra-native-rate304-r02-host.service --pcap "$BOARD_O/primary-syn.pcap" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/host-initial-wait.json" > "$BOARD_O/host-initial-wait.stdout"
sudo -n python3 scripts/capture_readiness.py --unit mothra-native-rate304-r02-host.service --pcap "$BOARD_O/primary-syn.pcap" --netns-inode "$(stat -Lc %i /proc/self/ns/net)" --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --filter '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' > "$BOARD_O/host-ready.json"
python3 scripts/mac_runtime.py display "$BOARD_D" --display :120 > "$BOARD_O/display-launch.stdout"
xdpyinfo -display :120 >/dev/null
python3 scripts/mac_runtime.py sheep "$BOARD_R" --display :120 --port 15880 --guest-pcap "$BOARD_O/lab-guest.pcap" --service --isolate-network > "$BOARD_O/sheep-launch.stdout"
# No first protocol socket is permitted by this script. Root inspects the
# actual emulator PID, pinned executable, FD6 and FD16 within five seconds.
sudo -n python3 "$BOARD_PREP/wait-emulator-r02.py" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/emulator-initial-wait.json" > "$BOARD_O/emulator-initial-wait.stdout"
