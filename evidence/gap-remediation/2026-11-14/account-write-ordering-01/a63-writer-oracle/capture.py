"""Capture the Ghidra queries about the account writer through the MCP server and save the report and the raw results."""
import asyncio,hashlib,json,os
from datetime import datetime,timedelta,timezone
from pathlib import Path
from mcp import ClientSession,StdioServerParameters
from mcp.client.stdio import stdio_client
ROOT=Path('/data/leynos/Projects/mothra')
BASE=ROOT/'state/delegation/workspaces/batch-02-native/mothra/state/delegation/a63-writer-oracle'
SHA='ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b'
BINARY=ROOT/'evidence/hotline-server-1.9/inputs/HLserver19.pef'
JAR=ROOT/'tools/ghidra_12.2_PUBLIC/Ghidra/Extensions/GhidraMCP/lib/GhidraMCP.jar'
for name in ['project','config','cache','data','tmp','home','raw']:(BASE/name).mkdir(exist_ok=True)
assert hashlib.sha256(BINARY.read_bytes()).hexdigest()==SHA
assert (ROOT/'state/delegation/endpoint-oracle-01/project/independent-endpoint-01.gpr').is_file()
env=dict(os.environ)
env.update(JAVA_HOME=str(ROOT/'tools/jdk-25.0.5+8'),GHIDRA_INSTALL_DIR=str(ROOT/'tools/ghidra_12.2_PUBLIC'),XDG_CONFIG_HOME=str(BASE/'config'),XDG_CACHE_HOME=str(BASE/'cache'),XDG_DATA_HOME=str(BASE/'data'),TMPDIR=str(BASE/'tmp'),JAVA_TOOL_OPTIONS=f'-Duser.home={BASE/"home"} -Djava.io.tmpdir={BASE/"tmp"}')
env['PATH']=str(ROOT/'tools/jdk-25.0.5+8/bin')+os.pathsep+env['PATH']
args=['--headless','--binary',str(BINARY),'--project',str(ROOT/'state/delegation/endpoint-oracle-01/project'),'--project-name','independent-endpoint-01','--no-analyze','--discard','--language','PowerPC:BE:32:default','--compiler','default','--extension-jar',str(JAR),'--ready-timeout','900']
report={'started_at_utc':datetime.now(timezone.utc).isoformat(),'command':str(ROOT/'tools/ghidramcp/.venv/bin/ghidra-mcp'),'args':args,'binary_sha256':SHA,'jar_sha256':hashlib.sha256(JAR.read_bytes()).hexdigest(),'project_scope':'read-only saved independent import from endpoint-oracle-01; no GUI-owned project accessed','queries':[],'status':'starting'}
def save():
    """Write the capture report to disk."""
    (BASE/'report.json').write_text(json.dumps(report,indent=2)+'\n')
save()
async def main():
 """Start the Ghidra MCP server, run the writer-oracle queries and record the results."""
 params=StdioServerParameters(command=report['command'],args=args,env=env,cwd=str(ROOT))
 try:
  with (BASE/'server.stderr.log').open('w') as err:
   async with stdio_client(params,errlog=err) as (reader,writer),ClientSession(reader,writer,read_timeout_seconds=timedelta(seconds=1050)) as session:
    init=await session.initialize()
    async def query(label,tool,arguments):
     """Run one Ghidra tool call and save its raw result and any decompiled code."""
     result=await session.call_tool(tool,arguments,read_timeout_seconds=timedelta(seconds=300))
     payload={'captured_at_utc':datetime.now(timezone.utc).isoformat(),'query':{'id':label,'tool':tool,'arguments':arguments},'result':result.model_dump(mode='json')}
     (BASE/'raw'/(label+'.json')).write_text(json.dumps(payload,indent=2)+'\n')
     data=result.structuredContent
     if data and 'code' in data:(BASE/'raw'/(label+'.c')).write_text(data['code'])
     report['queries'].append({'label':label,'tool':tool,'arguments':arguments,'is_error':bool(result.isError)});save(); print(label,'ERROR' if result.isError else 'OK',flush=True)
     return data
    info=await query('identity-before','get_program_info',{})
    assert info and info['sha256']==SHA and info['language_id']=='PowerPC:BE:32:default' and info['min_address']=='10000000' and info['function_count']==1840,info
    report['identity']=info;report['mcp_server']=init.serverInfo.model_dump(mode='json');report['status']='querying';save()
    for address in ['1007fc50','1002c5a0','1002c440','1002b2f0']:
     await query('A63-D-'+address,'decompile_function_by_address',{'address':address})
    for address in ['1007fc50','1002c5a0','1002c440','1002b2f0']:
     await query('A63-A-'+address,'disassemble_function',{'address':address,'limit':400})
    after=await query('identity-after','get_program_info',{});assert after==info
  report['status']='complete'
 except Exception as exc:
  report['status']='failed-preserved';report['error']=f'{type(exc).__name__}: {exc}';raise
 finally:
  report['finished_at_utc']=datetime.now(timezone.utc).isoformat();save()
asyncio.run(main())
