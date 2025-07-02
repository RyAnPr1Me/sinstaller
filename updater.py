import os
import sys
import urllib.request
import json
import time
import threading
from colorama import Fore, Style

def get_latest_github_release(repo="RyAnPr1Me/sinstaller"):
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with urllib.request.urlopen(url) as response:
            data = json.loads(response.read().decode())
        return data.get('tag_name'), data.get('assets', []), data.get('html_url')
    except Exception as e:
        print(Fore.YELLOW + f"[Updater] Could not fetch latest release: {e}" + Style.RESET_ALL)
        return None, [], None

def download_release_asset(asset_url, dest_folder):
    try:
        local_filename = os.path.join(dest_folder, asset_url.split('/')[-1])
        with urllib.request.urlopen(asset_url) as response:
            with open(local_filename, 'wb') as out_file:
                out_file.write(response.read())
        return local_filename
    except Exception as e:
        print(Fore.RED + f"[Updater] Failed to download asset: {e}" + Style.RESET_ALL)
        return None

def check_and_update(current_version, repo="RyAnPr1Me/sinstaller", dest_folder=".", interval_hours=24):
    def updater():
        while True:
            print(Fore.BLUE + "[Updater] Checking for updates..." + Style.RESET_ALL)
            tag, assets, url = get_latest_github_release(repo)
            if tag and tag.lstrip('v') > current_version.lstrip('v'):
                print(Fore.GREEN + f"[Updater] New version {tag} available! Downloading..." + Style.RESET_ALL)
                for asset in assets:
                    if asset.get('name', '').endswith('.exe'):
                        asset_url = asset['browser_download_url']
                        local_file = download_release_asset(asset_url, dest_folder)
                        if local_file:
                            print(Fore.GREEN + f"[Updater] Downloaded: {local_file}" + Style.RESET_ALL)
                            # Purge old .exe files except the new one
                            for f in os.listdir(dest_folder):
                                if f.endswith('.exe') and f != os.path.basename(local_file):
                                    try:
                                        os.remove(os.path.join(dest_folder, f))
                                        print(Fore.YELLOW + f"[Updater] Removed old: {f}" + Style.RESET_ALL)
                                    except Exception as e:
                                        print(Fore.RED + f"[Updater] Failed to remove {f}: {e}" + Style.RESET_ALL)
                # Optionally, prompt user to restart or auto-replace
            else:
                print(Fore.BLUE + f"[Updater] No new version found. Current: {current_version}, Latest: {tag}" + Style.RESET_ALL)
            time.sleep(interval_hours * 3600)
    t = threading.Thread(target=updater, daemon=True)
    t.start()
