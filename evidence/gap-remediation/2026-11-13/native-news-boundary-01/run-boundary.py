import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_news_boundary_cases as cases
from native_news_decode import articles,categories
from protocol_capture import run_plan
from verify_native_auth import reply
from verify_native_shx import fields
r=Path('state/native-sessions/runtime-25')
template=json.loads(Path('state/native-sessions/runtime-24/deletions/parent-three-one/plan.json').read_text());template['environment']=json.loads((r/'runtime.json').read_text());template['gap_ids']=['GAP-067','GAP-068','GAP-084']
def run(name,pair):
 steps,expected=pair;plan=copy.deepcopy(template);plan['steps']=steps;plan['expectation']=expected;p=r/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n');report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/name);print(name,report['status'],report['error'],flush=True);assert report['status']=='completed' and all(f['error']==0 for f in report['frames']);return report
pre=run('preflight',cases.preflight());assert categories(reply(pre,10))==[]
seed=run('seed',cases.seed());previous=fields(reply(seed,20))[321];assert [a['id'] for a in articles(previous)]==[1]
ranges=[(n,min(n+9,99)) for n in range(1,100,10)]+[(100,100),(101,101),(102,102)]
for first,last in ranges:
 report=run(f'append-{first:03}-{last:03}',cases.append(first,last));assert fields(reply(report,10))=={321:previous};previous=fields(reply(report,20))[321];assert fields(reply(report,21))=={321:previous};print('  children requested',last,'reachable IDs',[a['id'] for a in articles(previous)][-5:],'count',len(articles(previous)),flush=True)
run('observe',cases.observe());run('final',cases.finalization())
