from __future__ import annotations
import datetime as dt
import hashlib
import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
root=Path('/data/leynos/Projects/mothra')
out=root/'state/native-sessions/native-rate304-preparation-01'
working=root/'state/mac-runtime/native-rate304-01/working.dsk'
exe=root/'tools/macemu/SheepShaver/src/Unix/SheepShaver'
assert os.geteuid()==0
st=working.stat()
hits=[]
for process in Path('/proc').iterdir():
 if not process.name.isdigit(): continue
 for fd in (process/'fd').glob('*'):
  try:
   fs=fd.stat()
  except (OSError,PermissionError): continue
  if (fs.st_dev,fs.st_ino)==(st.st_dev,st.st_ino): hits.append([int(process.name),fd.name])
result={'recorded_utc':dt.datetime.now(dt.UTC).isoformat(),'new_working_fd_hits':hits,
 'emulator_binary':{'path':str(exe),'inode':exe.stat().st_ino,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest()},
 'working_inode':st.st_ino,'working_mode':oct(st.st_mode&0o777),
 'original_ticks':{},'display120_absent':not Path('/tmp/.X11-unix/X120').exists() and not (root/'state/mac-displays/native-rate304-01').exists(),
 'future_epoch_absent':not (root/'state/native-sessions/native-rate304-epoch-01').exists(),
 'disk_free_bytes':shutil.disk_usage(root/'state/mac-runtime').free}
for pid in (1099659,1012834):
 text=(Path('/proc')/str(pid)/'stat').read_text();result['original_ticks'][str(pid)]=text[text.rfind(')')+2:].split()[19]
ports=subprocess.run(['ss','-ltn'],capture_output=True,text=True,check=True)
(out/'supplement-ports.txt').write_text(ports.stdout)
result['ports_15880_15883_absent']=all(f':{port} ' not in ports.stdout and not ports.stdout.rstrip().endswith(f':{port}') for port in range(15880,15884))
(out/'supplement.json').write_text(json.dumps(result,indent=2)+'\n')
assert result['new_working_fd_hits']==[]
assert result['emulator_binary']['sha256']=='9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4'
assert result['original_ticks']=={'1099659':'767842','1012834':'2357813'}
assert result['display120_absent'] and result['future_epoch_absent'] and result['ports_15880_15883_absent']
print('stopped supplement PASS')
