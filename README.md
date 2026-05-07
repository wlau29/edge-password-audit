# Edge Saved Passwords Memory Audit

Python port of [EdgeSavedPasswordsDumper](https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper) by L1v1ng0ffTh3L4N.

The original C# tool demonstrated that Microsoft Edge stores autofill credentials in cleartext in process memory. This Python rewrite uses `ctypes` for Win32 API calls and `psutil` for process enumeration.

> **Warning:** The original C# binary is flagged by Microsoft Defender. This Python implementation is a clean rewrite that avoids that detection.

## Purpose

Authorized security auditing on Windows systems (e.g., terminal server hardening). Demonstrates that any process with `PROCESS_VM_READ` access can extract saved passwords from Edge's memory space.

## Requirements

- **Windows** with Microsoft Edge installed
- Python 3.10+
- `psutil` — `pip install -r requirements.txt`

## Privileges

Admin is **optional**:

| Mode | Behavior |
|------|----------|
| **Non-admin** | Scans only the current user's Edge processes |
| **Admin** | Scans all users' Edge processes (terminal server scenario) |

## Usage

```powershell
# Non-admin (current user only)
python edge_password_audit.py
```

```powershell
# Admin (all users, e.g. terminal server audit)
Start-Process powershell -Verb RunAs -ArgumentList "python edge_password_audit.py"
```

```powershell
# Debug mode (show broader pattern matches)
python edge_password_audit.py --debug
```

## What it does

1. Checks for elevated privileges (non-blocking — just determines scope)
2. Enumerates root `msedge.exe` processes (skips child processes)
3. Walks each process's virtual memory page-by-page
4. Searches readable memory for the cleartext credential byte pattern (`https? <username> <password>`)
5. Extracts associated URLs where possible
6. Deduplicates and prints results

## Original source

This is a Python rewrite of: **https://github.com/L1v1ng0ffTh3L4N/EdgeSavedPasswordsDumper**

See the original repo for the full disclaimer and context.

## Disclaimer

For **authorized security auditing only**. The author assumes no liability for misuse. You are solely responsible for ensuring your use complies with applicable laws and policies.
