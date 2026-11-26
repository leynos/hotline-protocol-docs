"""Run one stage of the account-batch captures (seed, batches, cleanup and the supplementary stages) against the retained runtime."""
import copy,json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_account_batch_cases as cases
from protocol_capture import run_plan
from verify_native_auth import reply
r=Path('state/native-sessions/runtime-28');template=json.loads(Path('state/native-sessions/runtime-27/preflight/plan.json').read_text());template['environment']=json.loads((r/'runtime.json').read_text());template['gap_ids']=['GAP-003','GAP-016','GAP-017','GAP-019','GAP-021','GAP-031','GAP-071','GAP-072','GAP-078','GAP-084']
def run(name,pair):
 """Build a plan from a step list and expectation, run it and return the report."""
 steps,expected=pair;plan=copy.deepcopy(template);plan.update(steps=steps,expectation=expected);p=r/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n');report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/name);print(name,report['status'],report['error'],flush=True);return report
stage=sys.argv[1]
if stage=='seed':
 pre=run('preflight',cases.preflight());assert pre['status']=='completed' and all(reply(pre,i)['error']==1 for i in range(100,100+len(cases.OWNED)));seed=run('seed',cases.seed());assert seed['status']=='completed' and all(f['error']==0 for f in seed['frames'])
elif stage=='batches':
 for spec in cases.specifications():
  before=run('before-'+spec['case'],cases.inspect(spec));assert before['status']=='completed';batch=run('batch-'+spec['case'],cases.batch(spec));print(' batch frames',[(f['type'],f['id'],f['error']) for f in batch['frames']],flush=True);after=run('after-'+spec['case'],cases.inspect(spec));assert after['status']=='completed'
 probe=run('nul-password-login',cases.probe_nul());assert probe['status']=='completed';final=run('final',cases.finalization());assert final['status']=='completed'
elif stage=='cleanup':
 final=json.loads((r/'distinct-final/report.json').read_text());existing=[label for identifier,label in enumerate(cases.OWNED+cases.EXTRA,100) if reply(final,identifier)['error']==0];(r/'cleanup-inventory.json').write_text(json.dumps(existing,indent=2)+'\n');report=run('cleanup',cases.cleanup(existing));assert report['status']=='completed' and all(f['error']==0 for f in report['frames'])
elif stage=='seed-extra':
 spec=cases.supplementary_spec();pre=run('distinct-preflight',cases.inspect(spec));assert pre['status']=='completed' and all(reply(pre,i)['error']==1 for i in range(100,104));seed=run('distinct-seed',cases.supplementary_seed());assert seed['status']=='completed'
elif stage=='batch-extra':
 spec=cases.supplementary_spec();before=run('distinct-before',cases.inspect(spec));assert before['status']=='completed';run('distinct-batch',cases.batch(spec));after=run('distinct-after',cases.inspect(spec));assert after['status']=='completed'
 for label in ['source','destination-source','destination-old']:
  report=run('distinct-login-'+label,cases.supplementary_probe(label));assert report['status']=='completed'
 final=run('distinct-final',cases.supplementary_final());assert final['status']=='completed'
elif stage in {'publish','remove-publisher'}:
 factory=cases.publish_cleanup if stage=='publish' else cases.remove_publisher;report=run(stage,factory());assert report['status']=='completed' and all(f['error']==0 for f in report['frames'])
else:raise ValueError('Unknown batch stage')
