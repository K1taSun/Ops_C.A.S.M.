#include "../include/types.h"
#include "../include/process_manager.h"
#include "../include/process_hider.h"
#include "../include/system_info.h"

#include <cstring>
#include <memory>

#define CASM_VERSION_MAJOR 0
#define CASM_VERSION_MINOR 1
#define CASM_VERSION_PATCH 0

static std::unique_ptr<casm::ProcessManager> g_procMgr;
static bool g_init = false;

static void procInfoToC(const casm::ProcessInfo& src, CasmProcessInfo* dst) {
    dst->pid = src.pid;
    dst->parentPid = src.parentPid;
    wcsncpy(dst->name, src.name.c_str(), 259);
    dst->name[259] = 0;
    wcsncpy(dst->path, src.path.c_str(), 519);
    dst->path[519] = 0;
    dst->threadCount = src.threadCount;
    dst->priority = static_cast<int>(src.priority);
    dst->state = static_cast<int>(src.state);
    dst->memoryUsage = src.memoryUsage;
    dst->cpuUsage = src.cpuUsage;
    dst->creationTime = src.creationTime;
    dst->isHidden = src.isHidden ? 1 : 0;
    dst->isSystem = src.isSystem ? 1 : 0;
}

static int errToC(casm::ErrorCode code) {
    switch (code) {
        case casm::ErrorCode::OK: return CASM_OK;
        case casm::ErrorCode::NotInitialized: return CASM_ERR_NOT_INITIALIZED;
        case casm::ErrorCode::InvalidParam: return CASM_ERR_INVALID_PARAM;
        case casm::ErrorCode::NotFound: return CASM_ERR_NOT_FOUND;
        case casm::ErrorCode::AccessDenied: return CASM_ERR_ACCESS_DENIED;
        case casm::ErrorCode::InsufficientBuffer: return CASM_ERR_INSUFFICIENT_BUFF;
        case casm::ErrorCode::AlreadyHidden: return CASM_ERR_ALREADY_HIDDEN;
        case casm::ErrorCode::NotHidden: return CASM_ERR_NOT_HIDDEN;
        case casm::ErrorCode::HookFailed: return CASM_ERR_HOOK_FAILED;
        case casm::ErrorCode::SystemError: return CASM_ERR_SYSTEM;
        default: return CASM_ERR_UNKNOWN;
    }
}

extern "C" {

CASM_API int casm_init(void) {
    if (g_init) return CASM_OK;
    
    try {
        g_procMgr = std::make_unique<casm::ProcessManager>();
        casm::ProcessManager::enableDebugPrivilege();
        casm::getGlobalHider().initialize(casm::HideMethod::InlineHook);
        g_init = true;
        return CASM_OK;
    } catch (...) {
        return CASM_ERR_SYSTEM;
    }
}

CASM_API void casm_cleanup(void) {
    if (!g_init) return;
    casm::getGlobalHider().shutdown();
    g_procMgr.reset();
    g_init = false;
}

CASM_API const char* casm_get_version(void) {
    static char ver[32];
    snprintf(ver, sizeof(ver), "%d.%d.%d", 
             CASM_VERSION_MAJOR, CASM_VERSION_MINOR, CASM_VERSION_PATCH);
    return ver;
}

CASM_API int casm_is_initialized(void) {
    return g_init ? 1 : 0;
}

CASM_API int casm_is_admin(void) {
    return casm::ProcessManager::isRunningAsAdmin() ? 1 : 0;
}

CASM_API int casm_get_process_count(int* count) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!count) return CASM_ERR_INVALID_PARAM;
    try {
        *count = static_cast<int>(g_procMgr->getProcessCount());
        return CASM_OK;
    } catch (...) {
        return CASM_ERR_SYSTEM;
    }
}

CASM_API int casm_enumerate_processes(CasmProcessInfo* buf, int bufSize, int* actualCount) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!buf || !actualCount) return CASM_ERR_INVALID_PARAM;
    
    try {
        auto procs = g_procMgr->enumerateProcesses();
        *actualCount = static_cast<int>(procs.size());
        
        int cnt = (bufSize < *actualCount) ? bufSize : *actualCount;
        for (int i = 0; i < cnt; i++) {
            procs[i].isHidden = casm::getGlobalHider().isProcessHidden(procs[i].pid);
            procInfoToC(procs[i], &buf[i]);
        }
        
        return (bufSize < *actualCount) ? CASM_ERR_INSUFFICIENT_BUFF : CASM_OK;
    } catch (...) {
        return CASM_ERR_SYSTEM;
    }
}

CASM_API int casm_get_process_info(DWORD pid, CasmProcessInfo* info) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!info) return CASM_ERR_INVALID_PARAM;
    
    try {
        auto proc = g_procMgr->getProcessById(pid);
        if (!proc) return CASM_ERR_NOT_FOUND;
        
        proc->isHidden = casm::getGlobalHider().isProcessHidden(pid);
        procInfoToC(*proc, info);
        return CASM_OK;
    } catch (...) {
        return CASM_ERR_SYSTEM;
    }
}

CASM_API int casm_terminate_process(DWORD pid, int force) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (g_procMgr->terminateProcess(pid, 0, force != 0)) return CASM_OK;
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_suspend_process(DWORD pid) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (g_procMgr->suspendProcess(pid)) return CASM_OK;
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_resume_process(DWORD pid) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (g_procMgr->resumeProcess(pid)) return CASM_OK;
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_set_priority(DWORD pid, int priority) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (g_procMgr->setPriority(pid, static_cast<casm::ProcessPriority>(priority))) return CASM_OK;
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_get_priority(DWORD pid, int* priority) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!priority) return CASM_ERR_INVALID_PARAM;
    auto p = g_procMgr->getPriority(pid);
    if (p) { *priority = static_cast<int>(*p); return CASM_OK; }
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_set_affinity(DWORD pid, DWORD_PTR mask) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (g_procMgr->setAffinity(pid, mask)) return CASM_OK;
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_get_affinity(DWORD pid, DWORD_PTR* procMask, DWORD_PTR* sysMask) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!procMask || !sysMask) return CASM_ERR_INVALID_PARAM;
    auto a = g_procMgr->getAffinity(pid);
    if (a) { *procMask = a->first; *sysMask = a->second; return CASM_OK; }
    return errToC(g_procMgr->getLastError());
}

CASM_API int casm_hide_process(DWORD pid) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (casm::getGlobalHider().hideProcess(pid)) return CASM_OK;
    return errToC(casm::getGlobalHider().getLastError());
}

CASM_API int casm_unhide_process(DWORD pid) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (casm::getGlobalHider().unhideProcess(pid)) return CASM_OK;
    return errToC(casm::getGlobalHider().getLastError());
}

CASM_API int casm_is_process_hidden(DWORD pid, int* result) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!result) return CASM_ERR_INVALID_PARAM;
    *result = casm::getGlobalHider().isProcessHidden(pid) ? 1 : 0;
    return CASM_OK;
}

CASM_API int casm_get_hidden_processes(DWORD* buf, int bufSize, int* actualCount) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    if (!buf || !actualCount) return CASM_ERR_INVALID_PARAM;
    
    auto hidden = casm::getGlobalHider().getHiddenProcesses();
    *actualCount = static_cast<int>(hidden.size());
    int cnt = (bufSize < *actualCount) ? bufSize : *actualCount;
    for (int i = 0; i < cnt; i++) buf[i] = hidden[i];
    return (bufSize < *actualCount) ? CASM_ERR_INSUFFICIENT_BUFF : CASM_OK;
}

CASM_API int casm_unhide_all(int* count) {
    if (!g_init) return CASM_ERR_NOT_INITIALIZED;
    size_t n = casm::getGlobalHider().unhideAll();
    if (count) *count = static_cast<int>(n);
    return CASM_OK;
}

CASM_API int casm_get_cpu_usage(double* usage) {
    if (!usage) return CASM_ERR_INVALID_PARAM;
    *usage = casm::getGlobalSystemInfo().getCpuUsage();
    return CASM_OK;
}

CASM_API int casm_get_memory_info(CasmMemoryInfo* info) {
    if (!info) return CASM_ERR_INVALID_PARAM;
    auto m = casm::getGlobalSystemInfo().getMemoryInfo();
    info->totalPhysical = m.totalPhysical;
    info->availablePhysical = m.availablePhysical;
    info->totalVirtual = m.totalVirtual;
    info->availableVirtual = m.availableVirtual;
    info->memoryLoad = m.memoryLoad;
    return CASM_OK;
}

CASM_API int casm_get_process_count_system(int* count) {
    if (!count) return CASM_ERR_INVALID_PARAM;
    *count = static_cast<int>(casm::getGlobalSystemInfo().getProcessCount());
    return CASM_OK;
}

CASM_API int casm_get_uptime(uint64_t* seconds) {
    if (!seconds) return CASM_ERR_INVALID_PARAM;
    *seconds = casm::getGlobalSystemInfo().getSystemUptime();
    return CASM_OK;
}

}
