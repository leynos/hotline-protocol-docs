"""Resume the suspended timer thread of the emulator and record the action."""
import ctypes,json,signal,subprocess
from pathlib import Path
from datetime import datetime,timezone
pid=774378;tid=774395
exe=subprocess.check_output(['sudo','-n','sha256sum',f'/proc/{pid}/exe'],text=True).split()[0]
assert exe=='b109f5c470fca6a1a5e0e0eaec4b5f5658d0e45ddafabf6b59bb7c4b35340146'
script='import ctypes,signal; c=ctypes.CDLL(None,use_errno=True); r=c.syscall(234,774378,774395,signal.SIGRTMIN+7); assert r==0,ctypes.get_errno()'
subprocess.run(['sudo','-n','python3','-c',script],check=True)
Path('state/native-sessions/runtime-15/timer-resume.json').write_text(json.dumps({'utc':datetime.now(timezone.utc).isoformat(),'emulator_pid':pid,'timer_tid':tid,'executable_sha256':exe,'signal':int(signal.SIGRTMIN+7),'method':'Linux tgkill to the timer thread using its installed SIGRESUME handler. No guest memory/register writes, app restart or emulator restart. Read-only debugger confirmed mutex owner and suspended timer thread first.'},indent=2)+'\n')
