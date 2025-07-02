# Blocklist handling for Secure Installer
import json
import pefile
import hashlib
from colorama import Fore, Style

def load_blocklist():
    try:
        with open('blocklist.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('blocked_hashes', []), data.get('blocked_thumbprints', [])
    except Exception as e:
        print(Fore.YELLOW + f"[!] Could not load blocklist: {e}" + Style.RESET_ALL)
        return [], []

BLOCKED_HASHES, BLOCKED_THUMBPRINTS = load_blocklist()

def get_cert_thumbprint(exe_path):
    try:
        pe = pefile.PE(exe_path)
        if not hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
            return None
        for entry in pe.DIRECTORY_ENTRY_SECURITY:
            cert_data = entry.entry.Certificate
            thumbprint = hashlib.sha1(cert_data).hexdigest().upper()
            return thumbprint
    except Exception:
        return None

def check_blocklist(exe_path, compute_file_hash, log_event):
    file_hash = compute_file_hash(exe_path, 'sha256').lower()
    if file_hash in [h.lower() for h in BLOCKED_HASHES]:
        log_event('blocklist_blocked', {'exe': exe_path, 'reason': 'hash', 'hash': file_hash})
        return False, f"Blocked by hash: {file_hash}"
    thumbprint = get_cert_thumbprint(exe_path)
    if thumbprint and thumbprint.upper() in [t.upper() for t in BLOCKED_THUMBPRINTS]:
        log_event('blocklist_blocked', {'exe': exe_path, 'reason': 'thumbprint', 'thumbprint': thumbprint})
        return False, f"Blocked by certificate thumbprint: {thumbprint}"
    return True, None
