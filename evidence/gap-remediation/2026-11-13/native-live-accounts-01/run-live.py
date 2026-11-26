"""Run one stage of the live account captures (before, stopped, after and cleanup)."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_live_account_cases as cases
from protocol_capture import run_plan
from verify_native_auth import reply
r=Path('state/native-sessions/runtime-27');template=json.loads(Path('state/native-sessions/runtime-26/preflight/plan.json').read_text());template['gap_ids']=['GAP-035','GAP-036','GAP-071','GAP-072','GAP-073','GAP-084']
def run(name,pair,epoch='before'):
 """Build a plan for the given epoch, run it and return the report."""
 steps,expectation=pair;plan=copy.deepcopy(template);plan['environment']=json.loads((r/('runtime-'+epoch+'.json')).read_text());plan.update(steps=steps,expectation=expectation);p=r/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n');report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/name);print(name,report['status'],report['error'],flush=True);return report
stage=sys.argv[1]
if stage=='before':
 pre=run('preflight',cases.preflight());assert pre['status']=='completed' and all(reply(pre,i)['error']==1 for i in [20,21]);seed=run('seed',cases.seed());assert seed['status']=='completed' and all(f['error']==0 for f in seed['frames']);edited=run('edit',cases.edit());assert edited['status']=='completed';deleted=run('delete',cases.delete());assert deleted['status']=='completed'
 for label in ['old','intermediate','final','deleted']:
  report=run('before-login-'+label,cases.probe(label));assert report['status']=='completed'
 final=run('before-final',cases.finalize());assert final['status']=='completed'
elif stage=='stopped':run('stopped',cases.stopped())
elif stage=='after':
 inspected=run('after-inspect',cases.inspect(),'after');assert inspected['status']=='completed'
 for label in ['old','intermediate','final','deleted']:
  report=run('after-login-'+label,cases.probe(label),'after');assert report['status']=='completed'
elif stage=='cleanup':
 report=run('cleanup',cases.cleanup(),'after');assert report['status']=='completed'
elif stage in {'confirmation','publish','remove-publisher'}:
 factory={'confirmation':cases.inspect,'publish':cases.publish_cleanup,'remove-publisher':cases.remove_publisher}[stage];name='after-inspect-confirmation' if stage=='confirmation' else stage;report=run(name,factory(),'after');assert report['status']=='completed'
else:raise ValueError('Unknown stage')
