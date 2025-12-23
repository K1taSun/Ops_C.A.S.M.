# API Reference

## C API (casm_core.dll)

### Init/cleanup

```c
int casm_init(void);        // 0 = ok
void casm_cleanup(void);
const char* casm_get_version(void);
int casm_is_initialized(void);
int casm_is_admin(void);
```

### Procesy

```c
int casm_get_process_count(int* count);
int casm_enumerate_processes(CasmProcessInfo* buf, int size, int* actual);
int casm_get_process_info(DWORD pid, CasmProcessInfo* info);

int casm_terminate_process(DWORD pid, int force);
int casm_suspend_process(DWORD pid);
int casm_resume_process(DWORD pid);

int casm_set_priority(DWORD pid, int priority);
int casm_get_priority(DWORD pid, int* priority);
int casm_set_affinity(DWORD pid, DWORD_PTR mask);
int casm_get_affinity(DWORD pid, DWORD_PTR* proc, DWORD_PTR* sys);
```

### Ukrywanie

```c
int casm_hide_process(DWORD pid);
int casm_unhide_process(DWORD pid);
int casm_is_process_hidden(DWORD pid, int* result);
int casm_get_hidden_processes(DWORD* buf, int size, int* actual);
int casm_unhide_all(int* count);
```

### System

```c
int casm_get_cpu_usage(double* usage);
int casm_get_memory_info(CasmMemoryInfo* info);
int casm_get_uptime(uint64_t* seconds);
```

## Struktury

```c
typedef struct {
    DWORD pid;
    DWORD parentPid;
    wchar_t name[260];
    wchar_t path[520];
    DWORD threadCount;
    int priority;
    int state;
    uint64_t memoryUsage;
    double cpuUsage;
    uint64_t creationTime;
    int isHidden;
    int isSystem;
} CasmProcessInfo;

typedef struct {
    uint64_t totalPhysical;
    uint64_t availablePhysical;
    uint64_t totalVirtual;
    uint64_t availableVirtual;
    uint32_t memoryLoad;
} CasmMemoryInfo;
```

## Kody bledow

```c
#define CASM_OK                     0
#define CASM_ERR_NOT_INITIALIZED   -1
#define CASM_ERR_INVALID_PARAM     -2
#define CASM_ERR_NOT_FOUND         -3
#define CASM_ERR_ACCESS_DENIED     -4
#define CASM_ERR_INSUFFICIENT_BUFF -5
#define CASM_ERR_ALREADY_HIDDEN    -6
#define CASM_ERR_NOT_HIDDEN        -7
#define CASM_ERR_HOOK_FAILED       -8
#define CASM_ERR_SYSTEM            -9
```

## Priorytety

```c
#define CASM_PRIORITY_IDLE          0x40
#define CASM_PRIORITY_BELOW_NORMAL  0x4000
#define CASM_PRIORITY_NORMAL        0x20
#define CASM_PRIORITY_ABOVE_NORMAL  0x8000
#define CASM_PRIORITY_HIGH          0x80
#define CASM_PRIORITY_REALTIME      0x100
```

## Python API

```python
from core_bridge import CoreBridge, ProcessInfo

bridge = CoreBridge()  # lub CoreBridge("path/to/casm_core.dll")

# procesy
procs = bridge.enumerate_processes()  # -> List[ProcessInfo]
info = bridge.get_process_info(pid)   # -> Optional[ProcessInfo]

bridge.terminate_process(pid, force=True)
bridge.suspend_process(pid)
bridge.resume_process(pid)
bridge.set_priority(pid, PRIORITY_HIGH)
bridge.set_affinity(pid, 0b0101)

# ukrywanie
bridge.hide_process(pid)
bridge.unhide_process(pid)
bridge.is_hidden(pid)  # -> bool

# system
cpu = bridge.get_cpu_usage()  # -> float (0-100)
mem = bridge.get_memory_info()  # -> MemoryInfo

bridge.cleanup()
```
