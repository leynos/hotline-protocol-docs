#!/bin/bash
# shellcheck disable=SC2024
# Prepared operator command; output belongs to the owned lab epoch.
set -euo pipefail
# PREPARED ONLY. Invoke on the host after a separate live START and PID proof.
BOARD_PID=${1:?actual emulator PID required}
[[ $BOARD_PID =~ ^[0-9]+$ ]]
BOARD_ROOT=/data/leynos/Projects/mothra
BOARD_PREP=$BOARD_ROOT/state/native-sessions/native-alias-live-preparation-02
BOARD_O=$BOARD_ROOT/state/native-sessions/native-alias-live-02
BOARD_LOCK=$BOARD_ROOT/state/delegation/oracle.lock
test "$EUID" = 0
cd "$BOARD_ROOT"
test -s "$BOARD_PREP/approved-helpers.sha256"
test -s "$BOARD_PREP/approved-alias-live-sources.sha256"
test -s "$BOARD_PREP/approved-source-closure.sha256"
test -s "$BOARD_PREP/script-SHA256SUMS"
sha256sum --quiet -c "$BOARD_PREP/approved-helpers.sha256"
sha256sum --quiet -c "$BOARD_PREP/approved-runtime-launchers.sha256"
sha256sum --quiet -c "$BOARD_PREP/script-SHA256SUMS"
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-alias-live-sources.sha256")
(cd /data/leynos/Projects/hotline-protocol-docs && sha256sum --quiet -c "$BOARD_PREP/approved-source-closure.sha256")
for script in boot-alias-live-02.sh complete-readiness-alias-live-02.sh run18-alias-live-02.sh build-runtime-alias-live-02.py wait-managed-alias-live-02.py run-case-alias-live-02.sh launch-case-alias-live-02.sh; do
    test -s "$BOARD_PREP/$script"
done
bash -n "$BOARD_PREP/run18-alias-live-02.sh"
test ! -e "$BOARD_O/runtime.json" && test ! -e "$BOARD_O/capture-ready.json" && test ! -e "$BOARD_O/readiness"
test -f "$BOARD_O/host-ready.json" && test -f "$BOARD_O/epoch-start.utc" && test -f "$BOARD_O/case-deadline.utc"
test -s "$BOARD_O/disk-ready.json"
python3 - "$BOARD_PID" "$BOARD_O/disk-ready.json" <<'PY'
import json,sys
actual=json.load(open(sys.argv[2]))
assert actual['phase']=='disk' and actual['pid']==int(sys.argv[1])
prep=json.load(open('/data/leynos/Projects/mothra/state/native-sessions/native-alias-live-preparation-02/stopped-preparation/preflight.json'))
assert actual['working_inode']==prep['prepared']['working.dsk']['inode'] and actual['exe_sha256']=='9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
PY
# The host-root operator has already run the generic capture phase and
# reviewed Finder prestage. This command never reopens the capture receipt.
test -s "$BOARD_O/guest-capture-ready.json" && test -s "$BOARD_O/prestage/reviewed.json"
python3 - "$BOARD_PID" "$BOARD_O/guest-capture-ready.json" <<'PY'
import json,sys
actual=json.load(open(sys.argv[2]))
prep=json.load(open('/data/leynos/Projects/mothra/state/native-sessions/native-alias-live-preparation-02/stopped-preparation/preflight.json'))
assert actual['phase']=='capture' and actual['pid']==int(sys.argv[1])
assert actual['working_inode']==prep['prepared']['working.dsk']['inode'] and actual['guest_fd']==16
PY
BOARD_NS=$(sudo -n stat -Lc %i "/proc/$BOARD_PID/ns/net")
sudo -n python3 "$BOARD_PREP/build-runtime-alias-live-02.py" "$BOARD_PID" > "$BOARD_O/build-runtime.stdout"
sudo -n systemd-run --unit=mothra-native-alias-live-02-namespace --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=900 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /usr/sbin/tcpdump -i lo -U -n -s 0 -w "$BOARD_O/lab-namespace.pcap" '(tcp port 15500 or tcp port 15501 or tcp port 15960 or tcp port 15961)' > "$BOARD_O/namespace-launch.stdout"
sudo -n python3 "$BOARD_PREP/wait-managed-alias-live-02.py" --unit mothra-native-alias-live-02-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/namespace-initial-wait.json" > "$BOARD_O/namespace-initial-wait.stdout"
sudo -n python3 scripts/capture_readiness.py --unit mothra-native-alias-live-02-namespace.service --pcap "$BOARD_O/lab-namespace.pcap" --netns-inode "$BOARD_NS" --deadline-utc "$(cat "$BOARD_O/case-deadline.utc")" --filter '(tcp port 15500 or tcp port 15501 or tcp port 15960 or tcp port 15961)' > "$BOARD_O/namespace-ready.json"
# B82/B83 helper runs in HOST root namespace; it alone builds managed_lock.
sudo -n python3 scripts/native_capture_receipt.py --runtime "$BOARD_O/runtime.json" --host-ready "$BOARD_O/host-ready.json" --namespace-ready "$BOARD_O/namespace-ready.json" --host-filter '(tcp port 15500 or tcp port 15501) and (tcp[tcpflags] & tcp-syn != 0)' --namespace-filter '(tcp port 15500 or tcp port 15501 or tcp port 15960 or tcp port 15961)' --lease-unit mothra-native-alias-live-02-lease.service --oracle-lock "$BOARD_LOCK" --guest-pcap "$BOARD_O/lab-guest.pcap" --epoch-start "$(cat "$BOARD_O/epoch-start.utc")" --deadline "$(cat "$BOARD_O/case-deadline.utc")" --output "$BOARD_O/capture-ready.json" > "$BOARD_O/receipt-helper.stdout"
(cd /data/leynos/Projects/hotline-protocol-docs && sudo -n python3 - <<'PY'
import json,sys
from pathlib import Path
sys.path.insert(0,'scripts')
from native_ban_control_cases import write_plans
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-alias-live-02')
r=json.loads((p/'runtime.json').read_text())
print('control',write_plans(p/'control-plans',r,15960)['readiness'])

PY
) > "$BOARD_O/plan-hashes.stdout"
(cd /data/leynos/Projects/hotline-protocol-docs && python3 scripts/native_missing_alias_cases.py --runtime "$BOARD_O/runtime.json" --output "$BOARD_O/alias-live-plan" --port 15960) >> "$BOARD_O/plan-hashes.stdout"
sudo -n systemd-run --unit=mothra-native-alias-live-02-readiness --property=Type=exec "--property=NetworkNamespacePath=/proc/$BOARD_PID/ns/net" --property=RuntimeMaxSec=90 --property=KillMode=control-group --property=Restart=no --property=RemainAfterExit=yes --no-block /bin/bash "$BOARD_PREP/run18-alias-live-02.sh" > "$BOARD_O/readiness-launch.stdout"
for ((attempt=0; attempt<90; attempt++)); do
    if test -f "$BOARD_O/readiness.exit"; then break; fi
    sleep 1
done
test -f "$BOARD_O/readiness.exit" && test "$(cat "$BOARD_O/readiness.exit")" = 0
sudo -n systemctl show mothra-native-alias-live-02-readiness.service -p Id -p ActiveState -p Result -p ExecMainStatus > "$BOARD_O/readiness-unit-final.txt"
rg -q '^ExecMainStatus=0$' "$BOARD_O/readiness-unit-final.txt"
python3 - <<'PY'
import datetime as dt,json
from pathlib import Path
p=Path('/data/leynos/Projects/mothra/state/native-sessions/native-alias-live-02')
r=json.loads((p/'readiness/report.json').read_text())
assert r['status']=='completed' and r['completed_actions']==18
remaining=(dt.datetime.fromisoformat((p/'case-deadline.utc').read_text().strip())-dt.datetime.now(dt.UTC)).total_seconds()
print(f'readiness complete; seconds until fixed cutoff: {remaining:.1f}')
if remaining < 390: raise SystemExit('Next-case >=390s readiness margin missed; retire lab')
PY
