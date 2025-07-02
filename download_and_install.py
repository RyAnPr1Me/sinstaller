import os
import sys
import subprocess
import tempfile
import shutil
import urllib.request
import zipfile

GITHUB_REPO = "https://github.com/RyAnPr1Me/sinstaller/archive/refs/heads/main.zip"


def download_and_extract_github_repo(repo_url, extract_to):
    print(f"Downloading {repo_url} ...")
    zip_path = os.path.join(tempfile.gettempdir(), "repo.zip")
    urllib.request.urlretrieve(repo_url, zip_path)
    print(f"Extracting to {extract_to} ...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)
    os.remove(zip_path)
    # Find the top-level extracted folder
    for name in os.listdir(extract_to):
        if os.path.isdir(os.path.join(extract_to, name)):
            return os.path.join(extract_to, name)
    return extract_to

def pip_install_requirements(folder):
    req_path = os.path.join(folder, 'requirements.txt')
    if os.path.exists(req_path):
        print("Installing requirements...")
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req_path])
    else:
        print("No requirements.txt found, skipping pip install.")

def run_installer(folder):
    main_py = os.path.join(folder, 'secure_installer.py')
    if os.path.exists(main_py):
        print("Launching Secure Installer GUI...")
        subprocess.Popen([sys.executable, main_py, '--gui'])
    else:
        print("secure_installer.py not found in repo!")

def main():
    temp_dir = tempfile.mkdtemp()
    try:
        repo_folder = download_and_extract_github_repo(GITHUB_REPO, temp_dir)
        pip_install_requirements(repo_folder)
        run_installer(repo_folder)
    finally:
        print(f"Temporary files are in: {temp_dir}")
        # Optionally: shutil.rmtree(temp_dir)

if __name__ == "__main__":
    main()
