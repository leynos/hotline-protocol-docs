import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_account_update_cases as cases
from protocol_capture import run_plan
from verify_native_auth import reply
r=Path('state/native-sessions/runtime-26');template=json.loads(Path('state/native-sessions/runtime-25/preflight/plan.json').read_text());template['environment']=json.loads((r/'runtime.json').read_text());template['gap_ids']=['GAP-016','GAP-019','GAP-071','GAP-072','GAP-073','GAP-084']
def run(name,pair):
 steps,expectation=pair;plan=copy.deepcopy(template);plan.update(steps=steps,expectation=expectation);p=r/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n');report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/name);print(name,report['status'],report['error'],flush=True);return report
if sys.argv[1]=='seed':
 pre=run('preflight',cases.preflight());assert pre['status']=='completed';assert all(reply(pre,i)['error']==1 for i in range(100,108));seed=run('seed',cases.seed());assert seed['status']=='completed' and all(f['error']==0 for f in seed['frames'])
elif sys.argv[1]=='mutate':
 before=run('base32-login',cases.probe('preserve32',b'q'*32,True));print('baseline32firstreply',reply(before,1)['error'],flush=True)
 for label in cases.LABELS:
  changed=run('mutation-'+label,cases.mutate(label));assert changed['status']=='completed' and all(f['error']==0 for f in changed['frames']);positive=run('login-'+label,cases.probe(label,cases.result_password(label),True));print('positivefirstreply',reply(positive,1)['error'],flush=True);wrong=cases.initial_password(label) if cases.initial_password(label)!=cases.result_password(label) else b'wrong-account26';negative=run('reject-'+label,cases.probe(label,wrong,False));print('negativefirstreply',reply(negative,1)['error'],flush=True)
 final=run('final',cases.finalization());assert final['status']=='completed' and all(f['error']==0 for f in final['frames'])
elif sys.argv[1]=='cleanup':
 cleaned=run('cleanup',cases.cleanup());assert cleaned['status']=='completed' and all(f['error']==0 for f in cleaned['frames'])
elif sys.argv[1] in {'publish','remove-publisher'}:
 name=sys.argv[1];factory=cases.publish_cleanup if name=='publish' else cases.remove_publisher;report=run(name,factory());assert report['status']=='completed' and all(f['error']==0 for f in report['frames'])
else:raise ValueError('Unknown stage')
