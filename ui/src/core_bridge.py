"""
Most do biblioteki C++ casm_core.dll
"""

import ctypes
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
import logging

log = logging.getLogger("CASM.Bridge")


class CasmError(Exception):
    pass

class ProcessNotFoundError(CasmError):
    pass

class AccessDeniedError(CasmError):
    pass

class HookError(CasmError):
    pass


# error codes
CASM_OK = 0
CASM_ERR_NOT_INITIALIZED = -1
CASM_ERR_INVALID_PARAM = -2
CASM_ERR_NOT_FOUND = -3
CASM_ERR_ACCESS_DENIED = -4
CASM_ERR_INSUFFICIENT_BUFF = -5
CASM_ERR_ALREADY_HIDDEN = -6
CASM_ERR_NOT_HIDDEN = -7
CASM_ERR_HOOK_FAILED = -8
CASM_ERR_SYSTEM = -9

# priorities
PRIORITY_IDLE = 0x40
PRIORITY_BELOW_NORMAL = 0x4000
PRIORITY_NORMAL = 0x20
PRIORITY_ABOVE_NORMAL = 0x8000
PRIORITY_HIGH = 0x80
PRIORITY_REALTIME = 0x100


class CasmProcessInfo(ctypes.Structure):
    _fields_ = [
        ("pid", wintypes.DWORD),
        ("parentPid", wintypes.DWORD),
        ("name", wintypes.WCHAR * 260),
        ("path", wintypes.WCHAR * 520),
        ("threadCount", wintypes.DWORD),
        ("priority", ctypes.c_int),
        ("state", ctypes.c_int),
        ("memoryUsage", ctypes.c_uint64),
        ("cpuUsage", ctypes.c_double),
        ("creationTime", ctypes.c_uint64),
        ("isHidden", ctypes.c_int),
        ("isSystem", ctypes.c_int),
    ]


class CasmMemoryInfo(ctypes.Structure):
    _fields_ = [
        ("totalPhysical", ctypes.c_uint64),
        ("availablePhysical", ctypes.c_uint64),
        ("totalVirtual", ctypes.c_uint64),
        ("availableVirtual", ctypes.c_uint64),
        ("memoryLoad", ctypes.c_uint32),
    ]


@dataclass
class ProcessInfo:
    pid: int
    parent_pid: int
    name: str
    path: str
    thread_count: int
    priority: int
    state: int
    memory_usage: int
    cpu_usage: float
    creation_time: int
    is_hidden: bool
    is_system: bool
    
    @classmethod
    def from_c(cls, c) -> 'ProcessInfo':
        return cls(
            pid=c.pid, parent_pid=c.parentPid, name=c.name, path=c.path,
            thread_count=c.threadCount, priority=c.priority, state=c.state,
            memory_usage=c.memoryUsage, cpu_usage=c.cpuUsage,
            creation_time=c.creationTime, is_hidden=bool(c.isHidden),
            is_system=bool(c.isSystem)
        )
    
    @property
    def priority_name(self) -> str:
        names = {
            PRIORITY_IDLE: "Bezczynny",
            PRIORITY_BELOW_NORMAL: "Ponizej normalnego",
            PRIORITY_NORMAL: "Normalny",
            PRIORITY_ABOVE_NORMAL: "Powyzej normalnego",
            PRIORITY_HIGH: "Wysoki",
            PRIORITY_REALTIME: "Realtime",
        }
        return names.get(self.priority, "?")
    
    @property
    def memory_formatted(self) -> str:
        return format_bytes(self.memory_usage)


@dataclass
class MemoryInfo:
    total: int
    available: int
    used: int
    percent: float
    
    @classmethod
    def from_c(cls, c) -> 'MemoryInfo':
        return cls(
            total=c.totalPhysical,
            available=c.availablePhysical,
            used=c.totalPhysical - c.availablePhysical,
            percent=c.memoryLoad
        )


def format_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} PB"


def _check_err(result: int, op: str = ""):
    if result == CASM_OK:
        return
    errors = {
        CASM_ERR_NOT_INITIALIZED: (CasmError, "Not initialized"),
        CASM_ERR_INVALID_PARAM: (ValueError, "Invalid param"),
        CASM_ERR_NOT_FOUND: (ProcessNotFoundError, "Not found"),
        CASM_ERR_ACCESS_DENIED: (AccessDeniedError, "Access denied"),
        CASM_ERR_ALREADY_HIDDEN: (CasmError, "Already hidden"),
        CASM_ERR_NOT_HIDDEN: (CasmError, "Not hidden"),
        CASM_ERR_HOOK_FAILED: (HookError, "Hook failed"),
        CASM_ERR_SYSTEM: (OSError, "System error"),
    }
    exc, msg = errors.get(result, (CasmError, "Unknown error"))
    raise exc(f"{op}: {msg}" if op else msg)


class CoreBridge:
    """Most do casm_core.dll"""
    
    def __init__(self, dll_path: Optional[str] = None):
        self._lib = None
        self._init = False
        
        if dll_path is None:
            dll_path = self._find_dll()
        
        if dll_path is None:
            log.warning("DLL nie znaleziony - tryb demo")
            return
        
        try:
            self._lib = ctypes.CDLL(dll_path)
            self._setup()
        except OSError as e:
            raise FileNotFoundError(f"Cannot load DLL: {e}")
        
        result = self._lib.casm_init()
        if result != CASM_OK:
            _check_err(result, "init")
        
        self._init = True
        log.info(f"CoreBridge ready: {dll_path}")
    
    def _find_dll(self) -> Optional[str]:
        paths = [
            Path(__file__).parent.parent.parent / "build" / "Release" / "casm_core.dll",
            Path(__file__).parent.parent.parent / "build" / "Debug" / "casm_core.dll",
            Path(__file__).parent.parent.parent / "build" / "casm_core.dll",
            Path(__file__).parent / "casm_core.dll",
        ]
        for p in paths:
            if p.exists():
                return str(p)
        return None
    
    def _setup(self):
        if not self._lib:
            return
        self._lib.casm_get_version.restype = ctypes.c_char_p
        self._lib.casm_is_initialized.restype = ctypes.c_int
        self._lib.casm_is_admin.restype = ctypes.c_int
        self._lib.casm_get_process_count.argtypes = [ctypes.POINTER(ctypes.c_int)]
        self._lib.casm_enumerate_processes.argtypes = [
            ctypes.POINTER(CasmProcessInfo), ctypes.c_int, ctypes.POINTER(ctypes.c_int)
        ]
        self._lib.casm_get_process_info.argtypes = [wintypes.DWORD, ctypes.POINTER(CasmProcessInfo)]
        self._lib.casm_terminate_process.argtypes = [wintypes.DWORD, ctypes.c_int]
        self._lib.casm_suspend_process.argtypes = [wintypes.DWORD]
        self._lib.casm_resume_process.argtypes = [wintypes.DWORD]
        self._lib.casm_set_priority.argtypes = [wintypes.DWORD, ctypes.c_int]
        self._lib.casm_set_affinity.argtypes = [wintypes.DWORD, ctypes.c_ulonglong]
        self._lib.casm_hide_process.argtypes = [wintypes.DWORD]
        self._lib.casm_unhide_process.argtypes = [wintypes.DWORD]
        self._lib.casm_is_process_hidden.argtypes = [wintypes.DWORD, ctypes.POINTER(ctypes.c_int)]
        self._lib.casm_get_cpu_usage.argtypes = [ctypes.POINTER(ctypes.c_double)]
        self._lib.casm_get_memory_info.argtypes = [ctypes.POINTER(CasmMemoryInfo)]
    
    def __del__(self):
        self.cleanup()
    
    def cleanup(self):
        if self._lib and self._init:
            self._lib.casm_cleanup()
            self._init = False
    
    def get_version(self) -> str:
        if not self._lib:
            return "0.0.0 (demo)"
        return self._lib.casm_get_version().decode('utf-8')
    
    def is_admin(self) -> bool:
        if not self._lib:
            return False
        return bool(self._lib.casm_is_admin())
    
    def enumerate_processes(self) -> List[ProcessInfo]:
        if not self._lib:
            return self._demo_procs()
        
        count = ctypes.c_int()
        self._lib.casm_get_process_count(ctypes.byref(count))
        
        buf_size = count.value + 50
        buf = (CasmProcessInfo * buf_size)()
        actual = ctypes.c_int()
        
        result = self._lib.casm_enumerate_processes(buf, buf_size, ctypes.byref(actual))
        _check_err(result, "enumerate")
        
        return [ProcessInfo.from_c(buf[i]) for i in range(actual.value)]
    
    def get_process_info(self, pid: int) -> Optional[ProcessInfo]:
        if not self._lib:
            return None
        info = CasmProcessInfo()
        result = self._lib.casm_get_process_info(pid, ctypes.byref(info))
        if result == CASM_ERR_NOT_FOUND:
            return None
        _check_err(result)
        return ProcessInfo.from_c(info)
    
    def find_by_name(self, name: str) -> List[ProcessInfo]:
        procs = self.enumerate_processes()
        name = name.lower()
        return [p for p in procs if name in p.name.lower()]
    
    def terminate_process(self, pid: int, force: bool = False) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_terminate_process(pid, 1 if force else 0)
        _check_err(result, "terminate")
        return True
    
    def suspend_process(self, pid: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_suspend_process(pid)
        _check_err(result, "suspend")
        return True
    
    def resume_process(self, pid: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_resume_process(pid)
        _check_err(result, "resume")
        return True
    
    def set_priority(self, pid: int, priority: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_set_priority(pid, priority)
        _check_err(result, "set_priority")
        return True
    
    def set_affinity(self, pid: int, mask: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_set_affinity(pid, mask)
        _check_err(result, "set_affinity")
        return True
    
    def hide_process(self, pid: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_hide_process(pid)
        _check_err(result, "hide")
        return True
    
    def unhide_process(self, pid: int) -> bool:
        if not self._lib:
            return False
        result = self._lib.casm_unhide_process(pid)
        _check_err(result, "unhide")
        return True
    
    def is_hidden(self, pid: int) -> bool:
        if not self._lib:
            return False
        val = ctypes.c_int()
        self._lib.casm_is_process_hidden(pid, ctypes.byref(val))
        return bool(val.value)
    
    def get_hidden_pids(self) -> List[int]:
        if not self._lib:
            return []
        buf = (wintypes.DWORD * 256)()
        cnt = ctypes.c_int()
        self._lib.casm_get_hidden_processes(buf, 256, ctypes.byref(cnt))
        return [buf[i] for i in range(cnt.value)]
    
    def get_cpu_usage(self) -> float:
        if not self._lib:
            return 0.0
        val = ctypes.c_double()
        self._lib.casm_get_cpu_usage(ctypes.byref(val))
        return val.value
    
    def get_memory_info(self) -> MemoryInfo:
        if not self._lib:
            return MemoryInfo(16*1024**3, 8*1024**3, 8*1024**3, 50.0)
        info = CasmMemoryInfo()
        self._lib.casm_get_memory_info(ctypes.byref(info))
        return MemoryInfo.from_c(info)
    
    def _demo_procs(self) -> List[ProcessInfo]:
        # dane demo gdy brak DLL
        return [
            ProcessInfo(0, 0, "System Idle", "", 4, PRIORITY_NORMAL, 0, 0, 0, 0, False, True),
            ProcessInfo(4, 0, "System", "", 128, PRIORITY_HIGH, 0, 200000, 0.1, 0, False, True),
            ProcessInfo(1234, 4, "explorer.exe", "C:\\Windows\\explorer.exe",
                        50, PRIORITY_NORMAL, 0, 80000000, 1.5, 0, False, False),
            ProcessInfo(5678, 1234, "chrome.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe",
                        30, PRIORITY_NORMAL, 0, 450000000, 5.2, 0, False, False),
        ]
