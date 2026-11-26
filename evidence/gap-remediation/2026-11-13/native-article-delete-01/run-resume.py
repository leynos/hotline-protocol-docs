"""Resume the article deletion captures for each case and check the recreated article tree."""
import json,subprocess,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_news_decode import articles
from native_news_delete_cases import NODES,specs
from protocol_capture import run_plan
from verify_native_auth import reply
from verify_native_shx import fields
r=Path('state/native-sessions/runtime-24');inventory=json.loads((r/'resume-inventory.json').read_text())
for spec in specs():
 name=spec['case'];v=inventory[name];out=r/'plans-resume'/name
 command=[sys.executable,'../hotline-protocol-docs/scripts/prepare_native_cases.py','article-delete-resume','--case-name',name,'--completed-nodes',str(v['completed']),'--runtime-record',str(r/'runtime-recovery.json'),'--output',str(out)]
 if v['exists']:command.append('--category-exists')
 subprocess.run(command,check=True)
 p=run_plan(out/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/'resumed'/name)
 print(name,p['status'],p['error'],flush=True)
 assert p['status']=='completed' and all(f['error']==0 for f in p['frames'])
 a=articles(fields(reply(p,20))[321]);by_id={x['id']:x for x in a};assert set(by_id)==set(range(1,9))
 for identifier,title,parent in NODES:assert by_id[identifier]['title']==title and by_id[identifier]['parent']==parent and by_id[identifier]['flavours']==[(b'text/plain',6)]
