"""Run each move and deletion plan against the retained runtime and require it to complete."""
import sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_news_cases import listings,structures
from protocol_capture import run_plan
r=Path('state/native-sessions/runtime-23')
for group,cases in [('listings',listings()),('structures',structures())]:
 for name in cases:
  p=run_plan(r/('plans-'+group)/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/group/name)
  print(group,name,p['status'],p['error'],flush=True)
  if p['status']!='completed':raise RuntimeError('Incomplete '+group+'/'+name)
