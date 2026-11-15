import sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_news_delete_cases import deletions
from protocol_capture import run_plan
r=Path('state/native-sessions/runtime-24')
for name in deletions():
 p=run_plan(r/'plans-cases-recovery'/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/'deletions'/name)
 print(name,p['status'],p['error'],flush=True)
 if p['status']!='completed':raise RuntimeError('Incomplete '+name)
