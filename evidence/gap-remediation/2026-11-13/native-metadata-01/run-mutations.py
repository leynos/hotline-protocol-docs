"""Run each metadata mutation plan against the retained runtime and require it to complete."""
import sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_metadata_cases import mutations
from protocol_capture import run_plan
r=Path('state/native-sessions/runtime-21')
for name in mutations():
 p=run_plan(r/'plans-mutations'/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/'mutations'/name)
 print(name,p['status'],p['error'],flush=True)
 if p['status']!='completed':raise RuntimeError('Incomplete '+name)
