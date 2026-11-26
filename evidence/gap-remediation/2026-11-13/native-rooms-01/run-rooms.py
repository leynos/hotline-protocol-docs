"""Run one stage of the room captures against the retained runtime."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_room_cases as cases
from protocol_capture import run_plan
from verify_native_auth import reply
root=Path('state/native-sessions/runtime-30');template=json.loads(Path('state/native-sessions/runtime-29/preflight/plan.json').read_text());template['environment']=json.loads((root/'runtime.json').read_text());template['gap_ids']=['GAP-003','GAP-018','GAP-019','GAP-031','GAP-033','GAP-038','GAP-039','GAP-040','GAP-041','GAP-042','GAP-084']
def run(name,pair):
 """Build a plan from a step list and expectation, run it and require it to complete."""
 steps,expectation=pair;plan=copy.deepcopy(template);plan.update(steps=steps,expectation=expectation);p=root/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n');report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),root/name);print(name,report['status'],report['error'],'frames',len(report['frames']),flush=True);assert report['status']=='completed';return report
stage=sys.argv[1]
if stage=='seed':
 pre=run('preflight',cases.inspect());assert all(reply(pre,i)['error']==1 for i in range(20,23));result=run('seed',cases.seed());assert all(f['error']==0 for f in result['frames'])
elif stage=='recovery-inspect':run(stage,cases.inspect())
elif stage in ['basics','topics','lifecycle','concurrent','create_invites','invites','refusals','formatting']:run(stage,getattr(cases,stage)())
elif stage=='cleanup':run('cleanup',cases.cleanup());run('final',cases.inspect())
else:raise ValueError(stage)
