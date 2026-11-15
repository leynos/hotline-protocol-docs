import hashlib,json,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
root=Path('/data/leynos/Projects/mothra');docs=root.parent/'hotline-protocol-docs'
sys.path.insert(0,str(docs/'scripts'))
from protocol_capture import verify_capture
from native_control_readiness import readiness
from native_missing_alias_control import host_state
from native_ban_expiry_control import runtime_gate,utc
p=root/'state/native-sessions/native-alias-live-03'
r=json.loads((p/'capture-ready.json').read_text())
disk=json.loads((p/'disk-ready.json').read_text())
assert r['emulator_pid']==disk['pid'] and r['emulator_netns_inode']==disk['netns_inode']
verify_capture(p/'readiness');readiness(json.loads((p/'readiness/report.json').read_text()))
subprocess.run(['python3',str(docs/'scripts/native_missing_alias_cases.py'),'--runtime',str(p/'runtime.json'),'--output',str(p/'parent-regenerated-plan'),'--port','15980'],check=True,capture_output=True)
raw=(p/'alias-live-plan/plan.json').read_bytes();assert raw==(p/'parent-regenerated-plan/plan.json').read_bytes()
plan=json.loads(raw);assert plan['case_numbered_with_login']==5 and plan['total_numbered_including_readiness']==11 and plan['mutations']==1
assert plan['barrier500_requests']==0 and plan['handshakes']==2
assert plan['endpoint']=={'host':'127.0.0.1','port':15980}
fixed=utc((p/'case-deadline.utc').read_text().strip());assert fixed==utc(r['deadline_utc'])
runtime_gate(r,plan['environment'],fixed)
assert host_state(plan)['finder']['sha256']==plan['environment']['initial_finf_sha256']
assert plan['environment']['owned_runtime']==str(root/'state/mac-runtime/native-alias-live-03')
assert (p/'prestage/reviewed.json').stat().st_uid==0
assert (p/'prestage/reviewed.json').stat().st_mode & 0o077==0
prestage=json.loads((p/'prestage/reviewed.json').read_text())
assert prestage['emulator_pid']==r['emulator_pid']
assert prestage['emulator_netns_inode']==r['emulator_netns_inode']
assert prestage['status']=='finder_target_selected_reviewed'
assert prestage['hfs_files_parent_visible'] is True
assert prestage['emulator_starttime']==int(plan['environment']['emulator_starttime'])
assert disk['start_ticks']==int(plan['environment']['emulator_starttime'])
assert disk['exe_sha256']==plan['environment']['emulator_sha256']
assert disk['working_inode']==plan['environment']['owned_working_image_inode']
assert prestage['disk_receipt_sha256']==hashlib.sha256((p/'disk-ready.json').read_bytes()).hexdigest()
assert prestage['capture_receipt_sha256']==hashlib.sha256((p/'guest-capture-ready.json').read_bytes()).hexdigest()
for key in ('finder','unix','target'):
    assert prestage['screenshots'][key]==hashlib.sha256((p/'prestage/screens'/f'{key}.png').read_bytes()).hexdigest()
remaining=(fixed-datetime.now(timezone.utc)).total_seconds();assert remaining>=390
out={'status':'PASS','emulator_pid':r['emulator_pid'],'deadline':fixed.isoformat(),'remaining_seconds':remaining,'plan_sha256':hashlib.sha256(raw).hexdigest(),'case_numbered':5,'total_numbered':11,'maximum_protocol_mutations':1}
(p/'parent-readiness-review.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
