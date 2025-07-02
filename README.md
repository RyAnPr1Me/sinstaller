# Secure Installer Prototype

This project is a Python-based secure installer for Windows. It allows you to install applications from URLs or folders, scans executables for viruses, runs them in a sandbox, and only installs if they are safe.

## Features
- Accepts installer sources: direct download links or local folders
- Detects `.exe` files in folders
- Virus scans using Windows Defender
- Runs installers in Windows Sandbox
- Installs only if safe

## Requirements
- Windows 10/11 Pro/Enterprise (for Windows Sandbox)
- Python 3.8+
- Windows Defender enabled

## Usage
1. Run the CLI tool and provide a URL or folder path.
2. Follow prompts to scan, sandbox, and install applications securely.

## Note
This is a prototype. Use with caution and review the code before running installers on your system.
