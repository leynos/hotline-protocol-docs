import sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_move_cases import moves,deletions
from protocol_capture import run_plan
r=Path('state/native-sessions/runtime-22')
for group,cases in [('moves',moves()),('deletions',deletions())]:
 for name in cases:
  p=run_plan(r/('plans-'+group)/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/group/name)
  print(group,name,p['status'],p['error'],flush=True)
  if p['status']!='completed':raise RuntimeError('Incomplete '+group+'/'+name)
