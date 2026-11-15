import datetime as dt,hashlib,json,os,subprocess
from pathlib import Path
R=Path('/data/leynos/Projects/mothra');O=R/'state/native-sessions/native-board-epoch-01';W=R/'state/mac-runtime/native-board-01/working.dsk'; B=R/'tools/sleuthkit/usr/bin';E=dict(os.environ,LD_LIBRARY_PATH=str(R/'tools/sleuthkit/usr/lib64'))
def run(label,argv,env=None):
 p=subprocess.run(argv,capture_output=True,env=env,check=False);(O/f'{label}.stdout').write_bytes(p.stdout);(O/f'{label}.stderr').write_bytes(p.stderr);(O/f'{label}.exit').write_text(str(p.returncode)+'\n');return p
assert not Path('/proc/1364862').exists()
fuser=run('stopped-fuser',['sudo','-n','fuser',str(W)]);assert fuser.returncode==1 and not fuser.stdout and not fuser.stderr
scan=run('stopped-proc-scan',['sudo','-n','python3','-c', '''import json
from pathlib import Path
p=Path("/data/leynos/Projects/mothra/state/mac-runtime/native-board-01/working.dsk"); k=(p.stat().st_dev,p.stat().st_ino); hit=[]
for d in Path("/proc").iterdir():
 if not d.name.isdecimal():continue
 for fd in (d/"fd").glob("*"):
  try:
   s=fd.stat()
   if (s.st_dev,s.st_ino)==k:hit.append([d.name,fd.name])
  except OSError:pass
print(json.dumps(hit))''']);assert scan.returncode==0 and json.loads(scan.stdout)==[]
files={'admin':('11193','26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3',734),'fixture-low':('11201','fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5',734),'Prefs':('11202','4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196',175),'server-data':('11183-4352-0','ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b',616821),'server-rsrc':('11183-4353-1','fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12',38460)}
record={'utc':dt.datetime.now(dt.UTC).isoformat(),'emulator_pid_gone':True,'working_inode':W.stat().st_ino,'fd_free':True,'files':{}}
for name,(inode,want,size) in files.items():
 p=run('stopped-icat-'+name,[str(B/'icat'),'-f','hfs',str(W),inode],E)
 digest=hashlib.sha256(p.stdout).hexdigest();record['files'][name]={'catalog':inode,'exit':p.returncode,'size':len(p.stdout),'sha256':digest,'matches_preflight':p.returncode==0 and digest==want and len(p.stdout)==size}
 assert record['files'][name]['matches_preflight']
 (O/f'stopped-icat-{name}.stdout').unlink()
board=run('stopped-istat-board',[str(B/'istat'),'-f','hfs',str(W),'11191'],E);text=board.stdout.decode();assert board.returncode==0
assert 'File Path: /Hotline19/MessageBoard.txt' in text and 'Size:\t0' in text and 'Resource fork size:\t0' in text and 'File type:\t54455854  TEXT' in text and 'File creator:\t74747874  ttxt' in text
record['board']={'catalog_id':11191,'path':'/Hotline19/MessageBoard.txt','istat_exit':board.returncode,'istat_sha256':hashlib.sha256(board.stdout).hexdigest(),'finder_type':'TEXT','finder_creator':'ttxt'}
for label,inode in [('data','11191'),('rsrc','11191-4353-1')]:
 p=run('stopped-icat-board-'+label,[str(B/'icat'),'-f','hfs',str(W),inode],E)
 record['board'][label]={'exit':p.returncode,'size':len(p.stdout),'sha256':hashlib.sha256(p.stdout).hexdigest()}
 if label=='data':
  assert p.returncode==0 and len(p.stdout)==0
 else:
  # TSK represents a zero-byte resource fork with no 4353-1 attribute.
  assert p.returncode==1 and len(p.stdout)==0 and b'Attribute 4353-1 not found' in p.stderr
  record['board'][label]['status']='absent_attribute; istat resource fork size 0'
(O/'stopped-hfs.json').write_text(json.dumps(record,indent=2)+'\n');print(json.dumps(record,indent=2))
