# Utility functions for Secure Installer
import os
import hashlib
import re
from urllib.parse import urlparse

def compute_file_hash(exe_path, algo='sha256'):
    hash_func = hashlib.new(algo)
    with open(exe_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    return hash_func.hexdigest()

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False

def is_valid_path(path):
    abs_path = os.path.abspath(path)
    cwd = os.path.abspath(os.getcwd())
    return abs_path.startswith(cwd)

def sanitize_filename(filename):
    filename = os.path.basename(filename)
    return re.sub(r'[^a-zA-Z0-9._-]', '_', filename)
