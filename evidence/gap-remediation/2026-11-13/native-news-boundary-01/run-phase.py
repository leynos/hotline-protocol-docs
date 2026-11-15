import json,sys
from pathlib import Path
sys.path.insert(0,'../hotline-protocol-docs/scripts')
import native_news_boundary_cases as cases
from native_news_decode import categories
from protocol_capture import run_plan
from verify_native_auth import reply
from verify_native_mkdir import listing
r=Path('state/native-sessions/runtime-25');name=sys.argv[1]
factory={'cleanup':cases.cleanup,'publish':cases.publish_cleanup,'remove-publisher':cases.remove_publisher}[name]
plan=json.loads((r/'seed.plan.json').read_text());plan['steps'],plan['expectation']=factory();p=r/(name+'.plan.json');p.write_text(json.dumps(plan,indent=2)+'\n')
report=run_plan(p,Path('evidence/hotline-server-1.9/inputs/HLserver19.pef'),r/name);print(name,report['status'],report['error'],flush=True)
assert report['status']=='completed' and all(f['error']==0 for f in report['frames']);assert not categories(reply(report,90))
baseline=listing(reply(json.loads((r/'preflight/report.json').read_text()),11));after=listing(reply(report,91))
if name=='publish':assert set(after)==set(baseline)|{b'm-nb25-publish'}
else:assert after==baseline
