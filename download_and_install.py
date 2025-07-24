import os
import sys
import subprocess
import tempfile
import shutil
import urllib.request
import zipfile

GITHUB_REPO = "https://github.com/RyAnPr1Me/sinstaller/archive/refs/heads/main.zip"
INSTALL_DIR = os.path.join(os.path.expanduser("~"), "AppData", "Local", "SecureInstaller")


def download_with_progress(url, dest):
    def reporthook(block_num, block_size, total_size):
        downloaded = block_num * block_size
        percent = min(100, int(downloaded * 100 / (total_size or 1)))
        bar = ('#' * (percent // 2)).ljust(50)
        sys.stdout.write(f'\r[Downloading] |{bar}| {percent}%')
        sys.stdout.flush()
        if percent == 100:
            print()  # Newline after complete
    urllib.request.urlretrieve(url, dest, reporthook)

def is_installed():
    exe_path = os.path.join(INSTALL_DIR, "secure_installer.exe")
    py_path = os.path.join(INSTALL_DIR, "secure_installer.py")
    return os.path.exists(exe_path) or os.path.exists(py_path)

def download_and_extract_github_repo(repo_url, extract_to):
    if is_installed():
        print(f"Secure Installer already installed at {INSTALL_DIR}. Skipping download.")
        return INSTALL_DIR
    print(f"Downloading {repo_url} ...")
    zip_path = os.path.join(tempfile.gettempdir(), "repo.zip")
    try:
        download_with_progress(repo_url, zip_path)
    except Exception as e:
        show_popup("Download Error", f"Failed to download repo: {e}")
        if os.path.exists(zip_path):
            os.remove(zip_path)
        raise
    print(f"Extracting to {extract_to} ...")
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        os.remove(zip_path)
    except Exception as e:
        show_popup("Extract Error", f"Failed to extract repo: {e}")
        if os.path.exists(zip_path):
            os.remove(zip_path)
        raise
    # Find the top-level extracted folder
    for name in os.listdir(extract_to):
        if os.path.isdir(os.path.join(extract_to, name)):
            src = os.path.join(extract_to, name)
            if not os.path.exists(INSTALL_DIR):
                shutil.move(src, INSTALL_DIR)
            else:
                for item in os.listdir(src):
                    s = os.path.join(src, item)
                    d = os.path.join(INSTALL_DIR, item)
                    if os.path.isdir(s):
                        shutil.copytree(s, d, dirs_exist_ok=True)
                    else:
                        shutil.copy2(s, d)
                shutil.rmtree(src, ignore_errors=True)
            return INSTALL_DIR
    return extract_to

def show_popup(title, message):
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, message, title, 0x40)
    except Exception:
        print(f"{title}: {message}")

def pip_install_requirements(folder):
    req_path = os.path.join(folder, 'requirements.txt')
    if os.path.exists(req_path):
        print("Installing requirements...")
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req_path])
        except Exception as e:
            show_popup("Dependency Install Error", f"Failed to install requirements: {e}")
            raise
    else:
        print("No requirements.txt found, skipping pip install.")

def run_installer(folder):
    main_py = os.path.join(folder, 'secure_installer.py')
    main_exe = os.path.join(folder, 'secure_installer.exe')
    if os.path.exists(main_exe):
        print("Launching Secure Installer EXE...")
        try:
            proc = subprocess.Popen([main_exe, '--gui'])
            create_desktop_shortcut(folder)
            shortcut_path = get_desktop_shortcut_path()
            if os.path.exists(shortcut_path):
                show_popup("Success", f"Desktop shortcut created at:\n{shortcut_path}")
            else:
                show_popup("Shortcut Error", "Failed to create desktop shortcut.")
            return True
        except Exception as e:
            show_popup("Launch Error", f"Failed to launch Secure Installer EXE: {e}")
            return False
    elif os.path.exists(main_py):
        print("Launching Secure Installer GUI...")
        python_exe = sys.executable
        if not python_exe or not os.path.exists(python_exe):
            for p in os.environ["PATH"].split(os.pathsep):
                candidate = os.path.join(p, "pythonw.exe")
                if os.path.exists(candidate):
                    python_exe = candidate
                    break
        if not python_exe or not os.path.exists(python_exe):
            show_popup("Python Error", "Could not find a working Python interpreter to launch the installer.")
            return False
        try:
            proc = subprocess.Popen([python_exe, main_py, '--gui'])
            create_desktop_shortcut(folder)
            shortcut_path = get_desktop_shortcut_path()
            if os.path.exists(shortcut_path):
                show_popup("Success", f"Desktop shortcut created at:\n{shortcut_path}")
            else:
                show_popup("Shortcut Error", "Failed to create desktop shortcut.")
            return True
        except Exception as e:
            show_popup("Launch Error", f"Failed to launch Secure Installer: {e}")
            return False
    else:
        show_popup("File Error", "secure_installer.py or .exe not found in repo!")
        return False

def get_desktop_shortcut_path():
    try:
        import winshell
        desktop = winshell.desktop()
        return os.path.join(desktop, "Secure Installer.lnk")
    except Exception as e:
        show_popup("Shortcut Error", f"Failed to determine desktop shortcut path: {e}")
        return None

def create_desktop_shortcut(installer_folder):
    shortcut_path = get_desktop_shortcut_path()
    if not shortcut_path:
        return
    try:
        from win32com.client import Dispatch
        target = None
        arguments = None
        exe_candidate = os.path.join(installer_folder, "secure_installer.exe")
        py_candidate = os.path.join(installer_folder, "secure_installer.py")
        if os.path.exists(exe_candidate):
            target = exe_candidate
            arguments = "--gui"
        elif os.path.exists(py_candidate):
            target = sys.executable
            arguments = f'"{py_candidate}" --gui'
        else:
            show_popup("Shortcut Error", "No valid Secure Installer executable or script found for shortcut.")
            return
        icon_path = os.path.join(installer_folder, "icon.ico")
        if not os.path.exists(icon_path):
            icon_path = target
        shell = Dispatch('WScript.Shell')
        shortcut = shell.CreateShortCut(shortcut_path)
        shortcut.Targetpath = target
        shortcut.Arguments = arguments
        shortcut.WorkingDirectory = installer_folder
        shortcut.IconLocation = icon_path
        shortcut.save()
        print(f"Desktop shortcut created at: {shortcut_path}")
    except Exception as e:
        show_popup("Shortcut Error", f"Failed to create desktop shortcut: {e}")

def main():
    temp_dir = tempfile.mkdtemp()
    repo_folder = None
    try:
        repo_folder = download_and_extract_github_repo(GITHUB_REPO, temp_dir)
        pip_install_requirements(repo_folder)
        success = run_installer(repo_folder)
        if not success:
            raise Exception("Installer failed to launch or shortcut failed.")
    except Exception as e:
        show_popup("Fatal Error", f"Error: {e}")
        import traceback
        traceback.print_exc()
        if repo_folder and os.path.exists(repo_folder) and repo_folder != INSTALL_DIR:
            print(f"Cleaning up {repo_folder} ...")
            shutil.rmtree(repo_folder, ignore_errors=True)
        elif os.path.exists(temp_dir):
            print(f"Cleaning up {temp_dir} ...")
            shutil.rmtree(temp_dir, ignore_errors=True)
        sys.exit(1)
    finally:
        # Always clean up temp files
        if repo_folder and os.path.exists(repo_folder) and repo_folder != INSTALL_DIR:
            print(f"Cleaning up {repo_folder} ...")
            shutil.rmtree(repo_folder, ignore_errors=True)
        if os.path.exists(temp_dir):
            print(f"Cleaning up {temp_dir} ...")
            shutil.rmtree(temp_dir, ignore_errors=True)

if __name__ == "__main__":
    main()
