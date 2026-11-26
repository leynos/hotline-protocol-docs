"""Run one stage of the account-identity captures against the retained runtime."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_account_identity_cases as cases
from protocol_capture import run_plan
from verify_native_auth import reply
root=Path('state/native-sessions/runtime-29')
template=json.loads(Path('state/native-sessions/runtime-28/preflight/plan.json').read_text())
template['environment']=json.loads((root/'runtime.json').read_text())
template['gap_ids']=['GAP-003','GAP-021','GAP-031','GAP-036','GAP-072','GAP-074','GAP-084']
def run(name,pair):
 """Build a plan from a step list and expectation, run it, print the frames and require completion."""
 steps,expectation=pair
 plan=copy.deepcopy(template);plan.update(steps=steps,expectation=expectation)
 p=root/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n')
 report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),root/name)
 print(name,report['status'],report['error'],[(f['connection'],f['type'],f['id'],f['error']) for f in report['frames']],flush=True)
 assert report['status']=='completed'
 return report
stage=sys.argv[1]
if stage=='seed':
 pre=run('preflight',cases.inspect());assert all(reply(pre,i)['error']==1 for i in range(20,23))
 report=run('seed',cases.seed());assert all(f['error']==0 for f in report['frames'])
elif stage=='duplicates':
 run('duplicate-exact',cases.duplicate());run('duplicate-uppercase',cases.duplicate(True))
 run('duplicate-original-login',cases.probe(cases.PASSWORD,cases.KEYS['duplicate'],success=True))
 run('duplicate-changed-login',cases.probe(cases.CHANGED,cases.KEYS['duplicate']))
elif stage in {'protected','self'}:
 run(stage,cases.target_case(stage));run(stage+'-login',cases.probe(cases.PASSWORD,cases.KEYS[stage]));run('after-'+stage,cases.inspect())
elif stage=='cleanup':run('cleanup',cases.cleanup());run('final',cases.inspect())
else:raise ValueError(stage)
