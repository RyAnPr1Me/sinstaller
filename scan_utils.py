# Scanning and sandboxing for Secure Installer
import subprocess
import os
import tempfile
from colorama import Fore, Style
from logging_utils import log_event

def scan_with_defender(exe_path, defender_path):
    try:
        result = subprocess.run([
            defender_path, '-Scan', '-ScanType', '3', '-File', exe_path
        ], capture_output=True, text=True)
        log_event('defender_scan', {'exe': exe_path, 'stdout': result.stdout})
        return 'No threats' in result.stdout, result.stdout
    except Exception as e:
        log_event('error', {'stage': 'scan_with_defender', 'error': str(e)})
        return False, str(e)

def run_in_sandbox(exe_path):
    try:
        wsb_content = f"""
<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{os.path.dirname(exe_path)}</HostFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>cmd.exe /c start powershell -NoProfile -Command \"Start-Transcript -Path C:\\activity.log; {os.path.basename(exe_path)}; Stop-Transcript\"</Command>
  </LogonCommand>
</Configuration>
"""
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.wsb') as f:
            f.write(wsb_content)
            wsb_path = f.name
        subprocess.run(['WindowsSandbox.exe', wsb_path])
        sandbox_log = os.path.join(os.path.dirname(exe_path), 'activity.log')
        log_content = None
        if os.path.exists(sandbox_log):
            with open(sandbox_log, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
                log_event('sandbox_activity_log', {'log': log_content})
        os.remove(wsb_path)
        return True, log_content
    except Exception as e:
        log_event('error', {'stage': 'run_in_sandbox', 'error': str(e)})
        return False, str(e)
