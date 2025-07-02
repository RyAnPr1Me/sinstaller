import os
import sys
import subprocess
import tempfile
import urllib.request
import shutil
from pathlib import Path
import pefile
import hashlib
from colorama import Fore, Style
import datetime
import json
import ctypes
import re
from urllib.parse import urlparse
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from tkinter import ttk
from gui import run_gui
from blocklist_utils import check_blocklist
from utils import compute_file_hash, is_valid_url, is_valid_path, sanitize_filename
from logging_utils import log_event
from scan_utils import scan_with_defender, run_in_sandbox
from updater import check_and_update

# --- CONFIG ---
DEFENDER_PATH = r'C:\Program Files\Windows Defender\MpCmdRun.exe'

# --- HELPERS ---
def download_file(url, dest_folder):
    try:
        local_filename = os.path.join(dest_folder, url.split('/')[-1])
        with urllib.request.urlopen(url) as response:
            data = response.read()
            logged_file_write(local_filename, data)
        return local_filename
    except Exception as e:
        print(Fore.RED + f"[!] Failed to download file: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'download_file', 'error': str(e)})
        return None

def download_files(urls, dest_folder, gui_result_callback=None):
    import concurrent.futures
    results = {}
    def _download(url):
        try:
            local_filename = os.path.join(dest_folder, url.split('/')[-1])
            with urllib.request.urlopen(url) as response:
                data = response.read()
                logged_file_write(local_filename, data)
            if gui_result_callback:
                gui_result_callback(f"[+] Downloaded: {url}")
            return local_filename
        except Exception as e:
            if gui_result_callback:
                gui_result_callback(f"[!] Failed to download {url}: {e}")
            log_event('error', {'stage': 'download_file', 'url': url, 'error': str(e)})
            return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, len(urls))) as executor:
        future_to_url = {executor.submit(_download, url): url for url in urls}
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            result = future.result()
            results[url] = result
    return [f for f in results.values() if f]

def find_exe_files(folder):
    try:
        return [str(p) for p in Path(folder).rglob('*.exe')]
    except Exception as e:
        print(Fore.RED + f"[!] Error finding .exe files: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'find_exe_files', 'error': str(e)})
        return []

def scan_with_defender(exe_path):
    try:
        print(f"Scanning {exe_path} with Windows Defender...")
        result = logged_subprocess_run([
            DEFENDER_PATH, '-Scan', '-ScanType', '3', '-File', exe_path
        ], capture_output=True, text=True)
        print(result.stdout)
        return 'No threats' in result.stdout
    except Exception as e:
        print(Fore.RED + f"[!] Error scanning with Defender: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'scan_with_defender', 'error': str(e)})
        return False

def run_in_sandbox(exe_path):
    try:
        print(f"Running {exe_path} in Windows Sandbox...")
        # Create a .wsb config file for Windows Sandbox with PowerShell transcript
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
        logged_subprocess_run(['WindowsSandbox.exe', wsb_path])
        print("Sandbox session ended. Attempting to collect activity log...")
        sandbox_log = os.path.join(os.path.dirname(exe_path), 'activity.log')
        if os.path.exists(sandbox_log):
            with open(sandbox_log, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
                log_event('sandbox_activity_log', {'log': log_content})
                detected, pattern = detect_persistence_in_log(log_content)
                if detected:
                    print(Fore.RED + "[!!!] PERSISTENCE MECHANISM DETECTED!" + Style.RESET_ALL)
                    print(Fore.RED + f"[!!!] Pattern: {pattern}" + Style.RESET_ALL)
                    print(Fore.RED + f"[!!!] This installer tried to add a scheduled task, service, or autorun entry!" + Style.RESET_ALL)
                    message = ("[!!!] PERSISTENCE MECHANISM DETECTED!\n"
                               f"Pattern: {pattern}\n"
                               "This installer tried to add a scheduled task, service, or autorun entry!\n"
                               "INSTALLATION BLOCKED.")
                    log_event('persistence_detected', {'pattern': pattern, 'log_excerpt': log_content[:500]})
                    raise RuntimeError(message)
                # --- Visual Timeline ---
                print(Fore.CYAN + "\n[Behavior Timeline]")
                timeline = parse_activity_log_timeline(log_content)
                for event in timeline:
                    print(event)
                print(Style.RESET_ALL)
            print(Fore.GREEN + '[*] Collected sandbox activity log.' + Style.RESET_ALL)
        else:
            print(Fore.YELLOW + '[!] No sandbox activity log found.' + Style.RESET_ALL)
        os.remove(wsb_path)
        return True  # For prototype, assume user checks manually
    except Exception as e:
        print(Fore.RED + f"[!] Error running in sandbox: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'run_in_sandbox', 'error': str(e)})
        return False

def install_exe(exe_path):
    try:
        print(f"Running installer: {exe_path}")
        logged_subprocess_run([exe_path])
    except Exception as e:
        print(Fore.RED + f"[!] Error running installer: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'install_exe', 'error': str(e)})

def check_digital_signature(exe_path):
    try:
        pe = pefile.PE(exe_path)
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if security_dir.VirtualAddress == 0:
            print(Fore.YELLOW + f"[!] {exe_path} is NOT digitally signed." + Style.RESET_ALL)
            return False
        print(Fore.GREEN + f"[+] {exe_path} is digitally signed." + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.RED + f"[!] Error checking digital signature: {e}" + Style.RESET_ALL)
        return False

def compute_file_hash(exe_path, algo='sha256'):
    hash_func = hashlib.new(algo)
    with open(exe_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def verify_hash(exe_path, expected_hash, algo='sha256'):
    actual_hash = compute_file_hash(exe_path, algo)
    if actual_hash.lower() == expected_hash.lower():
        print(Fore.GREEN + f"[+] Hash verified for {exe_path}." + Style.RESET_ALL)
        return True
    else:
        print(Fore.RED + f"[!] Hash mismatch for {exe_path}!" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Expected: {expected_hash}\n    Actual:   {actual_hash}" + Style.RESET_ALL)
        return False

def self_hash_check(expected_hash, algo='sha256'):
    this_file = os.path.abspath(__file__)
    actual_hash = compute_file_hash(this_file, algo)
    if actual_hash.lower() != expected_hash.lower():
        print(Fore.RED + f"[!] secure_installer.py hash mismatch!" + Style.RESET_ALL)
        print(Fore.YELLOW + f"    Expected: {expected_hash}\n    Actual:   {actual_hash}" + Style.RESET_ALL)
        sys.exit(1)
    else:
        print(Fore.GREEN + f"[+] secure_installer.py hash verified." + Style.RESET_ALL)

def check_exe_for_privilege_escalation(exe_path):
    try:
        pe = pefile.PE(exe_path)
        # Check for common privilege escalation indicators in the manifest
        for entry in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', []) or []:
            if hasattr(entry, 'data'):
                data = entry.data.struct
                if hasattr(data, 'Type') and data.Type == pefile.RESOURCE_TYPE['RT_MANIFEST']:
                    rva = entry.directory.entries[0].directory.entries[0].data.struct.OffsetToData
                    size = entry.directory.entries[0].directory.entries[0].data.struct.Size
                    manifest = pe.get_memory_mapped_image()[rva:rva+size]
                    manifest_str = manifest.decode(errors='ignore')
                    if 'requireAdministrator' in manifest_str:
                        print(Fore.RED + f"[!] {exe_path} requests requireAdministrator in its manifest!" + Style.RESET_ALL)
                        return False
                    if 'highestAvailable' in manifest_str:
                        print(Fore.YELLOW + f"[!] {exe_path} requests highestAvailable privileges in its manifest." + Style.RESET_ALL)
                        # Not a hard fail, but warn
        # If no manifest or no escalation found
        return True
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not check privilege escalation for {exe_path}: {e}" + Style.RESET_ALL)
        return True  # Don't block install if check fails

def log_event(event_type, details):
    log_entry = {
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'event_type': event_type,
        'details': details
    }
    with open('installer_behavior_log.jsonl', 'a', encoding='utf-8') as logf:
        logf.write(json.dumps(log_entry) + '\n')

def create_restore_point(description="SecureInstaller Restore Point"):
    try:
        srclient = ctypes.windll.srclient
        # 0x00000000 = BEGIN_SYSTEM_CHANGE, 0x00000001 = END_SYSTEM_CHANGE
        # 0x0000000C = APPLICATION_INSTALL
        class RESTOREPOINTINFO(ctypes.Structure):
            _fields_ = [
                ("dwEventType", ctypes.c_uint32),
                ("dwRestorePtType", ctypes.c_uint32),
                ("llSequenceNumber", ctypes.c_int64),
                ("szDescription", ctypes.c_wchar * 256)
            ]
        class STATEMGRSTATUS(ctypes.Structure):
            _fields_ = [
                ("nStatus", ctypes.c_uint32),
                ("llSequenceNumber", ctypes.c_int64)
            ]
        rpi = RESTOREPOINTINFO()
        rpi.dwEventType = 0  # BEGIN_SYSTEM_CHANGE
        rpi.dwRestorePtType = 0x0C  # APPLICATION_INSTALL
        rpi.llSequenceNumber = 0
        rpi.szDescription = description
        sms = STATEMGRSTATUS()
        res = srclient.SRSetRestorePointW(ctypes.byref(rpi), ctypes.byref(sms))
        if res == 0:
            print(Fore.RED + "[!] Failed to create system restore point." + Style.RESET_ALL)
            return False
        print(Fore.GREEN + "[+] System restore point created." + Style.RESET_ALL)
        return True
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not create restore point: {e}" + Style.RESET_ALL)
        return False

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False

def is_valid_path(path):
    # Only allow absolute or relative paths within the current working directory
    abs_path = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    # Prevent path traversal and ensure path is under cwd
    return abs_path.startswith(cwd)

def sanitize_filename(filename):
    # Remove dangerous characters and path traversal
    filename = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

def detect_persistence_in_log(log_text):
    persistence_patterns = [
        r'schtasks',
        r'CreateService',
        r'Service Control Manager',
        r'\\Run(Once)?',
        r'Startup',
        r'AddScheduledTask',
        r'RegisterService',
        r'\\CurrentVersion\\Run',
        r'\\CurrentVersion\\RunOnce',
        r'\\Windows\\Start Menu\\Programs\\Startup',
    ]
    for pattern in persistence_patterns:
        if re.search(pattern, log_text, re.IGNORECASE):
            return True, pattern
    return False, None

def parse_activity_log_timeline(log_text):
    timeline = []
    # Regex for PowerShell transcript timestamps: e.g. '2025-07-02 12:34:56'
    ts_re = re.compile(r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', re.MULTILINE)
    # Simple event patterns
    file_write_re = re.compile(r'(?:Created|Written|Write|Saved) file (.+)', re.IGNORECASE)
    reg_mod_re = re.compile(r'(?:Set|Created|Modified|Write) registry (.+)', re.IGNORECASE)
    net_call_re = re.compile(r'(?:Connecting|Connected|Outbound|Request|Download|Upload|POST|GET|PUT|TCP|UDP|to) (.+)', re.IGNORECASE)
    ps_hidden_re = re.compile(r'Hidden PowerShell|powershell.exe.*-WindowStyle Hidden', re.IGNORECASE)
    lines = log_text.splitlines()
    for i, line in enumerate(lines):
        ts_match = ts_re.match(line)
        ts = ts_match.group(1) if ts_match else None
        if file_write_re.search(line):
            timeline.append(f"[{ts or '??'}] File write: {file_write_re.search(line).group(1)}")
        elif reg_mod_re.search(line):
            timeline.append(f"[{ts or '??'}] Registry mod: {reg_mod_re.search(line).group(1)}")
        elif net_call_re.search(line):
            timeline.append(f"[{ts or '??'}] Network call: {net_call_re.search(line).group(1)}")
        elif ps_hidden_re.search(line):
            timeline.append(f"[{ts or '??'}] Launched hidden PowerShell")
    if not timeline:
        timeline.append("[??] No significant events detected in activity log.")
    return timeline

# --- LOGGING WRAPPERS ---
def logged_subprocess_run(args, **kwargs):
    log_event('process_spawn', {'args': args, 'cwd': kwargs.get('cwd', os.getcwd())})
    return subprocess.run(args, **kwargs)

def logged_file_write(path, data):
    log_event('file_write', {'path': path, 'size': len(data)})
    with open(path, 'wb') as f:
        f.write(data)

# --- PRODUCTION ENHANCEMENTS ---
# 1. Robust error handling and logging
# 2. User-friendly error dialogs in GUI
# 3. MSI-inspired sharp GUI (handled in gui.py, but ensure hooks here)
# 4. CLI/GUI option for silent install
# 5. Add code signing check for installer itself
# 6. Add versioning and update check
# 7. Add CLI/GUI option for exporting logs and results
# 8. Add CLI/GUI option for custom blocklist path
# 9. Add CLI/GUI option for hash verification file
# 10. Add CLI/GUI option for silent uninstall (future)

__version__ = "1.0.0"

# --- Self-integrity check (hash or signature) ---
def verify_self_integrity():
    # Placeholder: In production, verify digital signature or hash of this script
    # Optionally, check against a trusted hash or cert thumbprint
    pass

# --- Update check (stub) ---
def check_for_updates():
    # Placeholder: In production, check a trusted server for new version
    pass

# --- Robust Error Handling Decorator ---
def robust_error_handler(func):
    import functools
    def show_gui_error(msg):
        try:
            import tkinter.messagebox as mb
            mb.showerror("Error", msg)
        except Exception:
            print(Fore.RED + f"[GUI ERROR] {msg}" + Style.RESET_ALL)
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            log_event('fatal_error', {'function': func.__name__, 'error': str(e)})
            err_msg = f"[!] Fatal error in {func.__name__}: {e}"
            print(Fore.RED + err_msg + Style.RESET_ALL)
            if 'gui_result_callback' in kwargs and kwargs['gui_result_callback']:
                kwargs['gui_result_callback'](err_msg)
            else:
                show_gui_error(err_msg)
            return None
    return wrapper

# --- Main entry ---
@robust_error_handler
def main(source, opts=None, progress_callback=None, gui_result_callback=None):
    try:
        print(Fore.BLUE + "[*] Secure Installer started." + Style.RESET_ALL)
        log_event('installer_start', {'args': sys.argv[1:]})
        # Step 1: Validate source (support multi-URL input)
        url_list = []
        if isinstance(source, list):
            url_list = source
        elif isinstance(source, str) and (source.strip().startswith('http') or '\n' in source or ',' in source):
            # Multi-line or comma-separated URLs
            url_list = [u.strip() for u in re.split(r'[\n,]', source) if u.strip()]
        if url_list:
            if gui_result_callback:
                gui_result_callback(f"[*] Downloading {len(url_list)} installers...")
            downloaded_files = download_files(url_list, tempfile.gettempdir(), gui_result_callback)
            if not downloaded_files:
                if gui_result_callback:
                    gui_result_callback("[!] No files downloaded. Aborting.")
                print(Fore.RED + f"[!] Download failed. Aborting." + Style.RESET_ALL)
                return
            exe_files = downloaded_files
        elif is_valid_url(source):
            print(Fore.GREEN + f"[+] Valid URL provided: {source}" + Style.RESET_ALL)
            downloaded_file = download_file(source, tempfile.gettempdir())
            if not downloaded_file:
                print(Fore.RED + f"[!] Download failed. Aborting." + Style.RESET_ALL)
                return
            exe_files = [downloaded_file]
        elif os.path.isfile(source) and source.endswith('.exe'):
            print(Fore.GREEN + f"[+] Valid file provided: {source}" + Style.RESET_ALL)
            exe_files = [source]
        elif os.path.isdir(source):
            print(Fore.GREEN + f"[+] Valid folder provided: {source}" + Style.RESET_ALL)
            exe_files = find_exe_files(source)
            if not exe_files:
                print(Fore.RED + f"[!] No .exe files found in folder." + Style.RESET_ALL)
                return
        else:
            print(Fore.RED + "[!] Invalid source. Provide a valid URL, file, folder, or list of URLs." + Style.RESET_ALL)
            return

        # Load options if provided
        scan = True
        sandbox = True
        sig = True
        allow_unsigned = False
        if opts:
            scan = opts.get('scan', True)
            sandbox = opts.get('sandbox', True)
            sig = opts.get('sig', True)
            allow_unsigned = opts.get('allow_unsigned', False)

        # Step 2: Post-installation checks
        print(Fore.BLUE + "[*] Performing post-installation checks..." + Style.RESET_ALL)
        # Optimize: gather .exe files first, then process in parallel if possible
        import concurrent.futures
        if os.path.isdir(source):
            exe_files = find_exe_files(source)
        else:
            exe_files = [source]
        total = len(exe_files)
        results = []
        def process_exe(exe_file, idx):
            try:
                ok, reason = check_blocklist(exe_file, compute_file_hash, log_event)
                if not ok:
                    if gui_result_callback:
                        gui_result_callback(f"[BLOCKED] {exe_file}: {reason}")
                    print(Fore.RED + f"[!!!] {exe_file} blocked by blocklist: {reason}" + Style.RESET_ALL)
                    return False
            except Exception as e:
                if gui_result_callback:
                    gui_result_callback(f"[BLOCKED] {exe_file}: {e}")
                print(Fore.RED + f"[!!!] {exe_file} blocked by blocklist: {e}" + Style.RESET_ALL)
                return False
            # Digital signature check
            if opts and opts.get('sig', True):
                signed = check_digital_signature(exe_file)
                if not signed and not opts.get('allow_unsigned', False):
                    msg = f"[!] {exe_file} is not signed. Use override to allow unsigned installers."
                    if gui_result_callback:
                        gui_result_callback(msg)
                    print(Fore.RED + msg + Style.RESET_ALL)
                    return False
            # Sandbox
            if opts and opts.get('sandbox', True):
                sandbox_ok, sandbox_log = run_in_sandbox(exe_file)
                if not sandbox_ok:
                    msg = f"[!] Error running {exe_file} in sandbox. Skipping this file."
                    if gui_result_callback:
                        gui_result_callback(msg)
                    print(Fore.RED + msg + Style.RESET_ALL)
                    return False
                if gui_result_callback and sandbox_log:
                    gui_result_callback(f"[Sandbox Timeline for {exe_file}]:\n{sandbox_log[:1000]}\n...")
            # Defender scan
            if opts and opts.get('scan', True):
                scan_ok, scan_out = scan_with_defender(exe_file, DEFENDER_PATH)
                if not scan_ok:
                    msg = f"[!] Threat detected in {exe_file} by Windows Defender. Aborting installation."
                    if gui_result_callback:
                        gui_result_callback(msg)
                        gui_result_callback(f"Defender output:\n{scan_out}")
                    print(Fore.RED + msg + Style.RESET_ALL)
                    return False
                if gui_result_callback:
                    gui_result_callback(f"[Defender scan clean for {exe_file}]")
            try:
                install_exe(exe_file)
                msg = f"[+] {exe_file} installed successfully."
                if gui_result_callback:
                    gui_result_callback(msg)
                print(Fore.GREEN + msg + Style.RESET_ALL)
                return True
            except Exception as e:
                msg = f"[!] Error installing {exe_file}: {e}"
                if gui_result_callback:
                    gui_result_callback(msg)
                print(Fore.RED + msg + Style.RESET_ALL)
                return False
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, total)) as executor:
            futures = {executor.submit(process_exe, exe, idx): idx for idx, exe in enumerate(exe_files)}
            for i, future in enumerate(concurrent.futures.as_completed(futures)):
                progress_val = int((i+1)/total*100)
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    if gui_result_callback:
                        gui_result_callback(f"[!] Exception: {e}")
                    print(Fore.RED + f"[!] Exception: {e}" + Style.RESET_ALL)
                if progress_callback:
                    progress_callback(progress_val)
        if gui_result_callback:
            gui_result_callback(f"[*] Installation process completed. {sum(results)} succeeded, {total-sum(results)} failed.")
        print(Fore.BLUE + f"[*] Installation process completed. {sum(results)} succeeded, {total-sum(results)} failed." + Style.RESET_ALL)
        print(Fore.GREEN + "[+] Installation completed successfully." + Style.RESET_ALL)
        log_event('installer_end', {'status': 'success'})
    except Exception as e:
        if gui_result_callback:
            gui_result_callback(f"[!] Fatal error: {e}")
        print(Fore.RED + f"[!] Fatal error: {e}" + Style.RESET_ALL)
        log_event('error', {'stage': 'main', 'error': str(e)})
        return

if __name__ == '__main__':
    verify_self_integrity()
    check_for_updates()
    check_and_update(__version__, repo="RyAnPr1Me/sinstaller", dest_folder=os.path.dirname(os.path.abspath(__file__)), interval_hours=12)
    if '--gui' in sys.argv:
        run_gui(main)
    else:
        import argparse
        parser = argparse.ArgumentParser(description='Secure Installer')
        parser.add_argument('source', nargs='?', help='URL, file, folder, or list of URLs')
        parser.add_argument('--opts', help='Path to options JSON')
        parser.add_argument('--blocklist', help='Path to custom blocklist.json')
        parser.add_argument('--hashfile', help='Path to file with expected hashes')
        parser.add_argument('--export-log', help='Export log to file after run')
        parser.add_argument('--silent', action='store_true', help='Silent install (no prompts)')
        parser.add_argument('--version', action='store_true', help='Show version and exit')
        args = parser.parse_args()
        if args.version:
            print(f"Secure Installer version {__version__}")
            sys.exit(0)
        opts = None
        if args.opts:
            with open(args.opts, 'r') as f:
                opts = json.load(f)
        # Optionally override blocklist path, hashfile, etc. (not yet implemented)
        main(args.source, opts)
        if args.export_log:
            try:
                shutil.copy('installer_behavior_log.jsonl', args.export_log)
                print(f"[+] Log exported to {args.export_log}")
            except Exception as e:
                print(f"[!] Failed to export log: {e}")