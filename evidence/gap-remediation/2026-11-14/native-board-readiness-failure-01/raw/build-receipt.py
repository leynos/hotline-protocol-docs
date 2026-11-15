import datetime as dt, hashlib, json, os, shutil, subprocess
from pathlib import Path
R=Path('/data/leynos/Projects/mothra'); O=R/'state/native-sessions/native-board-epoch-01'; PID=1364862
start=(O/'epoch-start.utc').read_text().strip(); deadline=(O/'case-deadline.utc').read_text().strip()
def run(argv): return subprocess.run(argv,capture_output=True,text=True,check=True).stdout
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def tick(pid):
 x=Path(f'/proc/{pid}/stat').read_text();return x[x.rfind(')')+2:].split()[19]
assert tick(PID)=='7054838'
assert Path(f'/proc/{PID}/fd/6').stat().st_ino==3290903959
assert os.readlink(f'/proc/{PID}/fd/16')==str(O/'lab-guest.pcap')
exe=Path(os.readlink(f'/proc/{PID}/exe'));assert sha(exe)=='9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
ns=os.stat(f'/proc/{PID}/ns/net').st_ino;assert ns==4026532471
assert [json.loads(run(['nsenter','-t',str(PID),'-n','ip','-j',f,'route','show','table','main'])) for f in ('-4','-6')]==[[],[]]
assert [x['ifname'] for x in json.loads(run(['nsenter','-t',str(PID),'-n','ip','-j','link','show']))]==['lo']
assert {str(pid):tick(pid) for pid in (1099659,1012834)}=={'1099659':'767842','1012834':'2357813'}
lockpid=int(run(['systemctl','show','-p','MainPID','--value','mothra-native-board-c97-lease.service']).strip())
assert lockpid>0 and Path(f'/proc/{lockpid}/fd/3').stat().st_ino==(R/'state/delegation/oracle.lock').stat().st_ino
busy=subprocess.run(['flock','-n',str(R/'state/delegation/oracle.lock'),'true']).returncode;assert busy==1
props={}
coverage={}
for unit in ('lease','host','namespace'):
 name=f'mothra-native-board-c97-{unit}.service'
 values=run(['systemctl','show',name,'-p','ActiveState','-p','SubState','-p','MainPID','-p','ActiveEnterTimestamp','-p','RuntimeMaxUSec','-p','RemainAfterExit','-p','KillMode']).splitlines()
 item=dict(v.split('=',1) for v in values)
 assert item['ActiveState']=='active' and item['RuntimeMaxUSec']=='15min' and item['RemainAfterExit']=='yes' and item['KillMode']=='control-group'
 entered=dt.datetime.strptime(item['ActiveEnterTimestamp'],'%a %Y-%m-%d %H:%M:%S %Z').replace(tzinfo=dt.UTC)
 end=entered+dt.timedelta(seconds=900)
 assert end>dt.datetime.fromisoformat(deadline)+dt.timedelta(seconds=5)
 props[unit]=item;coverage[name]={'properties':item,'earliest_runtime_end_utc':end.isoformat(),'coverage_utc':(dt.datetime.fromisoformat(deadline)+dt.timedelta(seconds=5)).isoformat(),'covers_plus5':True}
(O/'independent-plus5-coverage.json').write_text(json.dumps(coverage,indent=2)+'\n')
base={
 'source_a7_sha256':'5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e',
 'fixture_profile':'control-only','full_file_baseline':'not_exercised','emulator_pid':PID,
 'emulator_starttime':'7054838','emulator_sha256':'9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4',
 'emulator_netns':f'net:[{ns}]','emulator_netns_inode':ns,
 'owned_working_image':str(R/'state/mac-runtime/native-board-01/working.dsk'),'owned_working_image_inode':3290903959,
 'owned_runtime':str(R/'state/mac-runtime/native-board-01'),
 'source_base_sha256':'e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910',
 'rom_sha256':'18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd',
 'native_data_sha256':'ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b',
 'stopped_board_baseline':{'path':'Hotline19/MessageBoard.txt','catalog_id':11191,'data_size':0,'resource_size':0,'finder_type':'TEXT','finder_creator':'ttxt'}
}
(O/'runtime.json').write_text(json.dumps(base,indent=2)+'\n')
lock={'unit':'mothra-native-board-c97-lease.service','pid':lockpid,'start':tick(lockpid),'fd':3,'lock_inode':(R/'state/delegation/oracle.lock').stat().st_ino,'busy_exit':busy,'uid':next(x for x in Path(f'/proc/{lockpid}/status').read_text().splitlines() if x.startswith('Uid:')),'unit_properties':props['lease']}
rece={**base,'utc':dt.datetime.now(dt.UTC).isoformat(),'epoch_started_utc':start,'deadline_utc':deadline,
'oracle_lock':str(R/'state/delegation/oracle.lock'),'managed_lock':lock,
'managed_capture':{label:json.loads((O/f'{label}-ready.json').read_text()) for label in ('host','namespace')},
'host_pcap':str(O/'primary-syn.pcap'),'namespace_pcap':str(O/'lab-namespace.pcap'),'guest_pcap':str(O/'lab-guest.pcap'),
'host_recorder_pid':int(props['host']['MainPID']),'host_recorder_starttime':int(tick(int(props['host']['MainPID']))),
'namespace_recorder_pid':int(props['namespace']['MainPID']),'namespace_recorder_starttime':int(tick(int(props['namespace']['MainPID']))),
'primary_syn_count':0,'ns_routes':[],'runtime_mode':'board control readiness only'}
assert (O/'primary-syn.pcap').stat().st_size==24
(O/'capture-ready.json').write_text(json.dumps(rece,indent=2)+'\n')
sources=['native_board_cases.py','native_board_control.py','native_ban_control_cases.py','native_control_readiness.py','native_ban_expiry_control.py','native_plan.py','native_auth_cases.py','protocol_capture.py','verify_native_auth.py','verify_native_shx.py','pcap_tcp.py']
folder=O/'sources';folder.mkdir(exist_ok=False);hashes={}
for name in sources:
 path=R/'../hotline-protocol-docs/scripts'/name;shutil.copy2(path,folder/name);hashes[name]=sha(folder/name)
assert hashes['native_board_cases.py']=='19e699317afd769c4a4b483e6094337fe92a5baaed279ae6ab98c18b7b554344'
assert hashes['native_board_control.py']=='da343b8d39f35c18bc267f301fdac316c720c0d5d4334eaec1d389ef381d1f6c'
(O/'source-freeze.json').write_text(json.dumps({'docs_head':run(['git','-C',str(R/'../hotline-protocol-docs'),'rev-parse','HEAD']).strip(),'hashes':hashes},indent=2)+'\n')
print(json.dumps({'pid':PID,'start':tick(PID),'ns':ns,'deadline':deadline,'lease_pid':lockpid,'source_hashes':hashes},indent=2))
