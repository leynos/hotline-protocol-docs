import json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
from native_metadata_cases import combined_empty
from protocol_capture import run_plan
from verify_native_auth import reply
from verify_native_mkdir import listing
r=Path('state/native-sessions/runtime-21')
baseline=listing(reply(json.loads((r/'account-cleanup/report.json').read_text()),90))
for name,(_,expected) in combined_empty().items():
 assert bytes.fromhex(expected['name_hex']) not in baseline
 assert bytes.fromhex(expected['final_hex']) not in baseline
for name in combined_empty():
 p=run_plan(r/'plans-combined-empty'/(name+'.json'),Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/'combined-empty'/name)
 print(name,p['status'],p['error'],flush=True)
 if p['status']!='completed':raise RuntimeError('Incomplete '+name)
 assert reply(p,12)['error']==0 and reply(p,40)['error']==0
 assert listing(reply(p,9))==listing(reply(p,90))==baseline
