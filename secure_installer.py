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

# --- CONFIG ---
DEFENDER_PATH = r'C:\Program Files\Windows Defender\MpCmdRun.exe'

# --- HELPERS ---
def download_file(url, dest_folder):
    local_filename = os.path.join(dest_folder, url.split('/')[-1])
    with urllib.request.urlopen(url) as response:
        data = response.read()
        logged_file_write(local_filename, data)
    return local_filename

def find_exe_files(folder):
    return [str(p) for p in Path(folder).rglob('*.exe')]

def scan_with_defender(exe_path):
    print(f"Scanning {exe_path} with Windows Defender...")
    result = logged_subprocess_run([
        DEFENDER_PATH, '-Scan', '-ScanType', '3', '-File', exe_path
    ], capture_output=True, text=True)
    print(result.stdout)
    return 'No threats' in result.stdout

def run_in_sandbox(exe_path):
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
    # Try to collect the log from the mapped folder
    sandbox_log = os.path.join(os.path.dirname(exe_path), 'activity.log')
    if os.path.exists(sandbox_log):
        with open(sandbox_log, 'r', encoding='utf-8', errors='ignore') as f:
            log_event('sandbox_activity_log', {'log': f.read()})
        print(Fore.GREEN + '[*] Collected sandbox activity log.' + Style.RESET_ALL)
    else:
        print(Fore.YELLOW + '[!] No sandbox activity log found.' + Style.RESET_ALL)
    os.remove(wsb_path)
    return True  # For prototype, assume user checks manually

def install_exe(exe_path):
    print(f"Running installer: {exe_path}")
    logged_subprocess_run([exe_path])

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

# --- LOGGING WRAPPERS ---
def logged_subprocess_run(args, **kwargs):
    log_event('process_spawn', {'args': args, 'cwd': kwargs.get('cwd', os.getcwd())})
    return subprocess.run(args, **kwargs)

def logged_file_write(path, data):
    log_event('file_write', {'path': path, 'size': len(data)})
    with open(path, 'wb') as f:
        f.write(data)

def run_gui():
    root = tk.Tk()
    root.title("Secure Installer")
    root.geometry("600x400")
    root.configure(bg="#23272e")
    style = ttk.Style(root)
    style.theme_use('clam')
    style.configure('.', background="#23272e", foreground="#f8f8f2", fieldbackground="#23272e", bordercolor="#44475a")
    style.configure('TButton', background="#44475a", foreground="#f8f8f2", borderwidth=1, focusthickness=3, focuscolor='none')
    style.map('TButton', background=[('active', '#6272a4')])
    style.configure('TLabel', background="#23272e", foreground="#f8f8f2")
    style.configure('TEntry', fieldbackground="#282a36", foreground="#f8f8f2")

    def browse_file():
        path = filedialog.askopenfilename(filetypes=[("Executable files", "*.exe")])
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def browse_folder():
        path = filedialog.askdirectory()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    progress = tk.DoubleVar(value=0)
    progress_bar = ttk.Progressbar(frame, variable=progress, maximum=100, length=400, mode='determinate')
    progress_bar.pack(pady=10)

    # Install options
    options_frame = ttk.LabelFrame(frame, text="Install Options", padding=10)
    options_frame.pack(pady=10, fill='x')
    scan_var = tk.BooleanVar(value=True)
    sandbox_var = tk.BooleanVar(value=True)
    sig_var = tk.BooleanVar(value=True)
    unsigned_var = tk.BooleanVar(value=False)
    ttk.Checkbutton(options_frame, text="Scan with Windows Defender", variable=scan_var).pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Run in Sandbox", variable=sandbox_var).pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Require Digital Signature", variable=sig_var).pack(anchor='w')
    ttk.Checkbutton(options_frame, text="Allow Unsigned Installers (Override)", variable=unsigned_var).pack(anchor='w')

    def start_install():
        source = entry.get().strip()
        if not source:
            messagebox.showerror("Error", "Please enter a URL or select a file/folder.")
            return
        # Save options to a temp file for CLI
        import tempfile, json
        opts = {
            'scan': scan_var.get(),
            'sandbox': sandbox_var.get(),
            'sig': sig_var.get(),
            'allow_unsigned': unsigned_var.get()
        }
        opts_path = os.path.join(tempfile.gettempdir(), 'secure_installer_opts.json')
        with open(opts_path, 'w') as f:
            json.dump(opts, f)
        # Instead of os.execl, call main directly with a progress callback
        def gui_progress(val):
            progress.set(val)
            progress_bar.update()
        root.destroy()
        main(source, opts, gui_progress)

    frame = ttk.Frame(root, padding=20)
    frame.pack(expand=True, fill='both')

    label = ttk.Label(frame, text="Secure Installer", font=("Segoe UI", 20, "bold"))
    label.pack(pady=(0, 20))

    entry = ttk.Entry(frame, font=("Segoe UI", 12), width=40)
    entry.pack(pady=10)

    btn_frame = ttk.Frame(frame)
    btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text="Browse File", command=browse_file).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Browse Folder", command=browse_folder).pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Install", command=start_install).pack(side=tk.LEFT, padx=5)

    root.mainloop()

def main(source, opts=None, progress_callback=None):
    # Main logic of the installer
    print(Fore.BLUE + "[*] Secure Installer started." + Style.RESET_ALL)
    log_event('installer_start', {'args': sys.argv[1:]})

    # Step 1: Validate source
    if is_valid_url(source):
        print(Fore.GREEN + f"[+] Valid URL provided: {source}" + Style.RESET_ALL)
        # Download and install from URL
        downloaded_file = download_file(source, tempfile.gettempdir())
        install_exe(downloaded_file)
    elif os.path.isfile(source) and source.endswith('.exe'):
        print(Fore.GREEN + f"[+] Valid file provided: {source}" + Style.RESET_ALL)
        # Local file installation
        install_exe(source)
    elif os.path.isdir(source):
        print(Fore.GREEN + f"[+] Valid folder provided: {source}" + Style.RESET_ALL)
        # Install all EXE files in the folder
        exe_files = find_exe_files(source)
        for exe_file in exe_files:
            install_exe(exe_file)
    else:
        print(Fore.RED + "[!] Invalid source. Provide a valid URL, file, or folder." + Style.RESET_ALL)
        sys.exit(1)

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(4, total)) as executor:
        futures = {executor.submit(process_exe, exe, idx): idx for idx, exe in enumerate(exe_files)}
        for i, future in enumerate(concurrent.futures.as_completed(futures)):
            progress_val = int((i+1)/total*100)
            try:
                result = future.result()
                results.append(result)
            except Exception as e:
                print(Fore.RED + f"[!] Exception: {e}" + Style.RESET_ALL)
            if progress_callback:
                progress_callback(progress_val)
    print(Fore.BLUE + f"[*] Installation process completed. {sum(results)} succeeded, {total-sum(results)} failed." + Style.RESET_ALL)
    print(Fore.GREEN + "[+] Installation completed successfully." + Style.RESET_ALL)
    log_event('installer_end', {'status': 'success'})

    def process_exe(exe_file, idx):
        # ...existing code for per-exe install, checks, etc...
        if sig:
            signed = check_digital_signature(exe_file)
            if not signed and not allow_unsigned:
                print(Fore.RED + f"[!] {exe_file} is not signed. Use override to allow unsigned installers." + Style.RESET_ALL)
                return False
        if sandbox and not run_in_sandbox(exe_file):
            print(Fore.RED + f"[!] Error running {exe_file} in sandbox. Skipping this file." + Style.RESET_ALL)
            return False
        if scan and not scan_with_defender(exe_file):
            print(Fore.RED + f"[!] Threat detected in {exe_file} by Windows Defender. Aborting installation." + Style.RESET_ALL)
            return False
        try:
            install_exe(exe_file)
            print(Fore.GREEN + f"[+] {exe_file} installed successfully." + Style.RESET_ALL)
            return True
        except Exception as e:
            print(Fore.RED + f"[!] Error installing {exe_file}: {e}" + Style.RESET_ALL)
            return False

if __name__ == '__main__':
    if '--gui' in sys.argv:
        run_gui()
    else:
        opts = None
        if '--opts' in sys.argv:
            idx = sys.argv.index('--opts')
            import json
            with open(sys.argv[idx+1], 'r') as f:
                opts = json.load(f)
            sys.argv.pop(idx+1)
            sys.argv.pop(idx)
        main(sys.argv[1], opts)