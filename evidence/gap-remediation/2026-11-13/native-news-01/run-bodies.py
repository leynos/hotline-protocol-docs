import sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_news_cases import bodies
from protocol_capture import run_plan
r=Path('state/native-sessions/runtime-23')
for name in bodies():
 p=run_plan(r/'plans-bodies'/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/'bodies'/name)
 print(name,p['status'],p['error'],flush=True)
 if p['status']!='completed':raise RuntimeError('Incomplete '+name)
