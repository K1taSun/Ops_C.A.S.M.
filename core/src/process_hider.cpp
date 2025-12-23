#include "../include/process_hider.h"
#include "../include/process_manager.h"

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#endif

#include <algorithm>
#include <sstream>
#include <cstring>

namespace casm {

#ifdef _WIN32

#define SystemProcessInformation 5

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_PROCESS_INFO {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    ULONG BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

#endif

class ProcessHider::Impl {
public:
    Impl() : origNtQuerySysInfo(nullptr), hookInstalled(false) {}
    
#ifdef _WIN32
    pNtQuerySystemInformation origNtQuerySysInfo;
    BYTE origBytes[16];
    BYTE* hookAddr;
    bool hookInstalled;
    
    void* getNtQueryAddr() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return nullptr;
        return GetProcAddress(ntdll, "NtQuerySystemInformation");
    }
#endif
};

// globalne dla hooka
static std::set<DWORD>* g_hiddenPids = nullptr;
static std::mutex* g_hiddenMtx = nullptr;

#ifdef _WIN32
// hooked function - filtruje ukryte procesy z listy
static NTSTATUS NTAPI HookedNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
) {
    // wywolaj oryginal (w prawdziwej impl przez trampoline)
    static pNtQuerySystemInformation orig = 
        (pNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation");
    
    NTSTATUS status = orig(SystemInformationClass, SystemInformation, 
                           SystemInformationLength, ReturnLength);
    
    if (SystemInformationClass == SystemProcessInformation && 
        NT_SUCCESS(status) && g_hiddenPids && g_hiddenMtx) {
        
        std::lock_guard<std::mutex> lock(*g_hiddenMtx);
        
        if (!g_hiddenPids->empty()) {
            PSYSTEM_PROCESS_INFO curr = (PSYSTEM_PROCESS_INFO)SystemInformation;
            PSYSTEM_PROCESS_INFO prev = nullptr;
            
            while (true) {
                DWORD pid = (DWORD)(ULONG_PTR)curr->ProcessId;
                
                if (g_hiddenPids->count(pid)) {
                    // ukryj - pomin w liscie
                    if (prev) {
                        if (curr->NextEntryOffset == 0) {
                            prev->NextEntryOffset = 0;
                        } else {
                            prev->NextEntryOffset += curr->NextEntryOffset;
                        }
                    } else {
                        if (curr->NextEntryOffset != 0) {
                            memmove(SystemInformation,
                                    (BYTE*)curr + curr->NextEntryOffset,
                                    SystemInformationLength - curr->NextEntryOffset);
                            continue;
                        }
                    }
                }
                
                if (curr->NextEntryOffset == 0) break;
                
                prev = curr;
                curr = (PSYSTEM_PROCESS_INFO)((BYTE*)curr + curr->NextEntryOffset);
            }
        }
    }
    
    return status;
}
#endif

ProcessHider::ProcessHider()
    : pImpl(std::make_unique<Impl>()),
      initialized_(false),
      activeMethod_(HideMethod::None),
      lastError_(ErrorCode::OK),
      callback_(nullptr) {
    
    if (!g_hiddenPids) g_hiddenPids = &hiddenPids_;
    if (!g_hiddenMtx) g_hiddenMtx = &mtx_;
}

ProcessHider::~ProcessHider() {
    shutdown();
    if (g_hiddenPids == &hiddenPids_) g_hiddenPids = nullptr;
    if (g_hiddenMtx == &mtx_) g_hiddenMtx = nullptr;
}

ErrorCode ProcessHider::initialize(HideMethod method) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (initialized_) return ErrorCode::OK;
    
    if (!ProcessManager::isRunningAsAdmin()) {
        setLastError(ErrorCode::AccessDenied);
        return ErrorCode::AccessDenied;
    }
    
    if (!ProcessManager::enableDebugPrivilege()) {
        setLastError(ErrorCode::AccessDenied);
        return ErrorCode::AccessDenied;
    }
    
    bool ok = false;
    switch (method) {
        case HideMethod::InlineHook:
            ok = installInlineHook();
            break;
        case HideMethod::PebUnlink:
            ok = true;  // per-process, bez globalnego hooka
            break;
        case HideMethod::Dkom:
            // wymaga kernel drivera
            setLastError(ErrorCode::SystemError);
            return ErrorCode::SystemError;
        case HideMethod::None:
            ok = true;
            break;
    }
    
    if (ok) {
        initialized_ = true;
        activeMethod_ = method;
        setLastError(ErrorCode::OK);
        return ErrorCode::OK;
    }
    
    setLastError(ErrorCode::HookFailed);
    return ErrorCode::HookFailed;
}

void ProcessHider::shutdown() {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (!initialized_) return;
    
    hiddenPids_.clear();
    
    if (activeMethod_ == HideMethod::InlineHook) {
        uninstallInlineHook();
    }
    
    initialized_ = false;
    activeMethod_ = HideMethod::None;
}

bool ProcessHider::isInitialized() const {
    return initialized_;
}

bool ProcessHider::hideProcess(DWORD pid) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (!initialized_ && activeMethod_ != HideMethod::None) {
        setLastError(ErrorCode::NotInitialized);
        return false;
    }
    
    if (pid == 0 || pid == 4) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    if (hiddenPids_.count(pid)) {
        setLastError(ErrorCode::AlreadyHidden);
        return false;
    }
    
    hiddenPids_.insert(pid);
    
    if (activeMethod_ == HideMethod::PebUnlink) {
        if (!unlinkFromPeb(pid)) {
            hiddenPids_.erase(pid);
            return false;
        }
    }
    
    notifyStateChange(pid, true);
    setLastError(ErrorCode::OK);
    return true;
}

bool ProcessHider::unhideProcess(DWORD pid) {
    std::lock_guard<std::mutex> lock(mtx_);
    
    auto it = hiddenPids_.find(pid);
    if (it == hiddenPids_.end()) {
        setLastError(ErrorCode::NotHidden);
        return false;
    }
    
    if (activeMethod_ == HideMethod::PebUnlink) {
        relinkToPeb(pid);
    }
    
    hiddenPids_.erase(it);
    notifyStateChange(pid, false);
    setLastError(ErrorCode::OK);
    return true;
}

bool ProcessHider::toggleHide(DWORD pid) {
    return isProcessHidden(pid) ? unhideProcess(pid) : hideProcess(pid);
}

size_t ProcessHider::unhideAll() {
    std::lock_guard<std::mutex> lock(mtx_);
    
    size_t cnt = hiddenPids_.size();
    
    for (DWORD pid : hiddenPids_) {
        if (activeMethod_ == HideMethod::PebUnlink) {
            relinkToPeb(pid);
        }
        notifyStateChange(pid, false);
    }
    
    hiddenPids_.clear();
    return cnt;
}

bool ProcessHider::isProcessHidden(DWORD pid) const {
    std::lock_guard<std::mutex> lock(mtx_);
    return hiddenPids_.count(pid) > 0;
}

std::vector<DWORD> ProcessHider::getHiddenProcesses() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return std::vector<DWORD>(hiddenPids_.begin(), hiddenPids_.end());
}

size_t ProcessHider::getHiddenCount() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return hiddenPids_.size();
}

HideMethod ProcessHider::getActiveMethod() const {
    return activeMethod_;
}

bool ProcessHider::isMethodAvailable(HideMethod method) const {
    switch (method) {
        case HideMethod::None: return true;
        case HideMethod::InlineHook:
        case HideMethod::PebUnlink:
            return ProcessManager::isRunningAsAdmin();
        case HideMethod::Dkom:
            return false;  // wymaga drivera
    }
    return false;
}

std::vector<HideMethod> ProcessHider::getAvailableMethods() const {
    std::vector<HideMethod> methods;
    methods.push_back(HideMethod::None);
    if (isMethodAvailable(HideMethod::InlineHook)) methods.push_back(HideMethod::InlineHook);
    if (isMethodAvailable(HideMethod::PebUnlink)) methods.push_back(HideMethod::PebUnlink);
    if (isMethodAvailable(HideMethod::Dkom)) methods.push_back(HideMethod::Dkom);
    return methods;
}

bool ProcessHider::setHideMethod(HideMethod method) {
    if (!isMethodAvailable(method)) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    unhideAll();
    
    if (activeMethod_ == HideMethod::InlineHook) {
        uninstallInlineHook();
    }
    
    return initialize(method) == ErrorCode::OK;
}

void ProcessHider::setStateChangeCallback(HideStateCallback cb) {
    callback_ = cb;
}

void ProcessHider::clearStateChangeCallback() {
    callback_ = nullptr;
}

ErrorCode ProcessHider::getLastError() const {
    return lastError_;
}

std::string ProcessHider::getLastErrorMessage() const {
    return errorCodeToString(lastError_);
}

bool ProcessHider::areHooksActive() const {
    return initialized_ && pImpl->hookInstalled;
}

std::string ProcessHider::getDiagnostics() const {
    std::stringstream ss;
    ss << "ProcessHider status\n";
    ss << "  initialized: " << (initialized_ ? "yes" : "no") << "\n";
    ss << "  method: " << static_cast<int>(activeMethod_) << "\n";
    ss << "  hooks active: " << (areHooksActive() ? "yes" : "no") << "\n";
    ss << "  hidden count: " << hiddenPids_.size() << "\n";
    ss << "  admin: " << (ProcessManager::isRunningAsAdmin() ? "yes" : "no") << "\n";
    return ss.str();
}

void ProcessHider::setLastError(ErrorCode code) {
    lastError_ = code;
}

void ProcessHider::notifyStateChange(DWORD pid, bool hidden) {
    if (callback_) callback_(pid, hidden);
}

bool ProcessHider::installInlineHook() {
#ifdef _WIN32
    // uproszczona wersja - w prawdziwej impl trzeba:
    // 1. VirtualProtect na PAGE_EXECUTE_READWRITE
    // 2. backup oryginalnych bajtow
    // 3. wpisac jmp do naszej funkcji
    // 4. stworzyc trampoline do wywolania oryginalu
    
    void* target = pImpl->getNtQueryAddr();
    if (!target) return false;
    
    pImpl->hookAddr = (BYTE*)target;
    
    DWORD oldProt;
    if (!VirtualProtect(target, 16, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    
    memcpy(pImpl->origBytes, target, 16);
    
    // tu byloby wpisanie hooka...
    // na razie tylko zaznaczamy ze "zainstalowany"
    
    VirtualProtect(target, 16, oldProt, &oldProt);
    pImpl->hookInstalled = true;
    
    return true;
#else
    return false;
#endif
}

bool ProcessHider::uninstallInlineHook() {
#ifdef _WIN32
    if (!pImpl->hookInstalled) return true;
    
    DWORD oldProt;
    if (!VirtualProtect(pImpl->hookAddr, 16, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }
    
    memcpy(pImpl->hookAddr, pImpl->origBytes, 16);
    
    VirtualProtect(pImpl->hookAddr, 16, oldProt, &oldProt);
    pImpl->hookInstalled = false;
    
    return true;
#else
    return false;
#endif
}

bool ProcessHider::unlinkFromPeb(DWORD pid) {
    // TODO: wymaga NtQueryInformationProcess + modyfikacji LDR_DATA_TABLE_ENTRY
    return true;
}

bool ProcessHider::relinkToPeb(DWORD pid) {
    // TODO
    return true;
}

ProcessHider& getGlobalHider() {
    static ProcessHider instance;
    return instance;
}

} // namespace casm
