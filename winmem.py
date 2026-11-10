# -*- coding: utf-8 -*-
"""
winmem.py - Windows 进程内存读写封装 (ctypes, 无第三方依赖)
需要 64 位 Python。可扫描 32 位 / 64 位目标进程。
"""
import sys
import ctypes
import ctypes.wintypes as wt

IS_WINDOWS = sys.platform == "win32"

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
ACCESS = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
MEM_MAPPED = 0x40000
MEM_IMAGE = 0x1000000

PAGE_GUARD = 0x100
PAGE_NOACCESS = 0x01
WRITABLE_MASK = 0x04 | 0x08 | 0x40 | 0x80   # RW / WC / ERW / EWC

TH32CS_SNAPPROCESS = 0x00000002
MAX_USER_ADDR = 0x7FFFFFFFFFFF
CHUNK = 64 * 1024 * 1024        # 大区域按 64MB 切块


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


if IS_WINDOWS:
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    k32.OpenProcess.restype = wt.HANDLE
    k32.CloseHandle.argtypes = [wt.HANDLE]
    k32.CloseHandle.restype = wt.BOOL
    k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = wt.BOOL
    k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.WriteProcessMemory.restype = wt.BOOL
    k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p,
                                   ctypes.POINTER(MEMORY_BASIC_INFORMATION64), ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32FirstW.restype = wt.BOOL
    k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.restype = wt.BOOL
else:
    k32 = None


def list_processes():
    """返回 [(pid, exe_name)]"""
    if not IS_WINDOWS:
        return []
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    out = []
    if not snap or snap == wt.HANDLE(-1).value:
        return out
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = k32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            out.append((pe.th32ProcessID, pe.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        k32.CloseHandle(snap)
    return sorted(out, key=lambda x: x[1].lower())


class Process:
    def __init__(self, pid):
        if not IS_WINDOWS:
            raise OSError("仅支持 Windows")
        if ctypes.sizeof(ctypes.c_void_p) != 8:
            raise OSError("请使用 64 位 Python")
        self.pid = pid
        self.handle = k32.OpenProcess(ACCESS, False, pid)
        if not self.handle:
            err = ctypes.get_last_error()
            raise OSError(f"OpenProcess 失败 (错误码 {err})。若为 5 表示权限不足：目标进程以管理员运行或受保护。")

    def close(self):
        if self.handle:
            k32.CloseHandle(self.handle)
            self.handle = None

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        n = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
        if not ok and n.value == 0:
            return None
        return buf.raw[:n.value]

    def write(self, addr, data: bytes):
        n = ctypes.c_size_t(0)
        ok = k32.WriteProcessMemory(self.handle, ctypes.c_void_p(addr), data, len(data), ctypes.byref(n))
        return bool(ok) and n.value == len(data)

    def regions(self, include_mapped=False, include_image=True):
        """枚举可写的已提交内存区域，返回 [(base, size)]，大区域切块"""
        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        out = []
        types = {MEM_PRIVATE}
        if include_image:
            types.add(MEM_IMAGE)
        if include_mapped:
            types.add(MEM_MAPPED)
        while addr < MAX_USER_ADDR:
            r = k32.VirtualQueryEx(self.handle, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if r == 0:
                break
            base, size = mbi.BaseAddress, mbi.RegionSize
            if size == 0:
                break
            if (mbi.State == MEM_COMMIT and mbi.Type in types
                    and (mbi.Protect & WRITABLE_MASK)
                    and not (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))):
                off = 0
                while off < size:
                    n = min(CHUNK, size - off)
                    out.append((base + off, n))
                    off += n
            addr = base + size
        return out
