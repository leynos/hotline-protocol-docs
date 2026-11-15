import json,subprocess,sys
from datetime import datetime,timezone
from pathlib import Path
r=Path('state/native-sessions/runtime-27');tag=sys.argv[1];args=sys.argv[2:];started=datetime.now(timezone.utc).isoformat();command=['python3','state/native-sessions/runtime-24/mac-input-99.py',*args];p=subprocess.run(command,check=False);image=r/(tag+'.png');subprocess.run(['env','DISPLAY=:99','import','-window','root',str(image)],check=True)
with (r/'ui-events.jsonl').open('a') as f:f.write(json.dumps({'started_at_utc':started,'command':command,'exit_code':p.returncode,'finished_at_utc':datetime.now(timezone.utc).isoformat(),'screenshot':str(image)})+'\n')
if p.returncode:raise SystemExit(p.returncode)
