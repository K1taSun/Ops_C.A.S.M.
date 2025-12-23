#include "../include/process_manager.h"

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")
#endif

#include <algorithm>
#include <stdexcept>
#include <sstream>

namespace casm {

class ProcessManager::Impl {
public:
    Impl() : debugPrivEnabled(false) {}
    
    bool debugPrivEnabled;
    
#ifdef _WIN32
    typedef NTSTATUS(NTAPI* pNtSuspendProcess)(HANDLE);
    typedef NTSTATUS(NTAPI* pNtResumeProcess)(HANDLE);
    
    pNtSuspendProcess NtSuspendProcess = nullptr;
    pNtResumeProcess NtResumeProcess = nullptr;
    
    bool initNtFuncs() {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) return false;
        
        NtSuspendProcess = (pNtSuspendProcess)GetProcAddress(ntdll, "NtSuspendProcess");
        NtResumeProcess = (pNtResumeProcess)GetProcAddress(ntdll, "NtResumeProcess");
        
        return NtSuspendProcess && NtResumeProcess;
    }
#endif
};

ProcessManager::ProcessManager() 
    : pImpl(std::make_unique<Impl>()), lastError_(ErrorCode::OK) {
#ifdef _WIN32
    pImpl->initNtFuncs();
#endif
}

ProcessManager::~ProcessManager() = default;

std::vector<ProcessInfo> ProcessManager::enumerateProcesses() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<ProcessInfo> procs;
    
#ifdef _WIN32
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        setLastError(ErrorCode::SystemError);
        throw std::runtime_error("CreateToolhelp32Snapshot failed");
    }
    
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.parentPid = pe.th32ParentProcessID;
            info.name = pe.szExeFile;
            info.threadCount = pe.cntThreads;
            
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                        FALSE, pe.th32ProcessID);
            if (hProc) {
                wchar_t path[MAX_PATH] = {0};
                if (GetModuleFileNameExW(hProc, NULL, path, MAX_PATH)) {
                    info.path = path;
                }
                
                DWORD prio = GetPriorityClass(hProc);
                info.priority = static_cast<ProcessPriority>(prio);
                
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc))) {
                    info.memoryUsage = pmc.WorkingSetSize;
                }
                
                FILETIME ct, et, kt, ut;
                if (GetProcessTimes(hProc, &ct, &et, &kt, &ut)) {
                    ULARGE_INTEGER li;
                    li.LowPart = ct.dwLowDateTime;
                    li.HighPart = ct.dwHighDateTime;
                    info.creationTime = li.QuadPart;
                }
                
                CloseHandle(hProc);
                info.state = ProcessState::Running;
            } else {
                info.state = ProcessState::Unknown;
            }
            
            info.isSystem = (pe.th32ProcessID == 0 || pe.th32ProcessID == 4);
            procs.push_back(info);
            
        } while (Process32NextW(snap, &pe));
    }
    
    CloseHandle(snap);
#endif
    
    setLastError(ErrorCode::OK);
    return procs;
}

std::optional<ProcessInfo> ProcessManager::getProcessById(DWORD pid) {
    auto procs = enumerateProcesses();
    for (const auto& p : procs) {
        if (p.pid == pid) return p;
    }
    setLastError(ErrorCode::NotFound);
    return std::nullopt;
}

std::vector<ProcessInfo> ProcessManager::findProcessesByName(
    const std::wstring& name, bool caseSensitive) {
    
    auto procs = enumerateProcesses();
    std::vector<ProcessInfo> result;
    
    std::wstring search = name;
    if (!caseSensitive) {
        std::transform(search.begin(), search.end(), search.begin(), ::towlower);
    }
    
    for (const auto& p : procs) {
        std::wstring pname = p.name;
        if (!caseSensitive) {
            std::transform(pname.begin(), pname.end(), pname.begin(), ::towlower);
        }
        if (pname.find(search) != std::wstring::npos) {
            result.push_back(p);
        }
    }
    
    return result;
}

std::map<DWORD, std::vector<DWORD>> ProcessManager::getProcessTree() {
    auto procs = enumerateProcesses();
    std::map<DWORD, std::vector<DWORD>> tree;
    for (const auto& p : procs) {
        tree[p.parentPid].push_back(p.pid);
    }
    return tree;
}

std::wstring ProcessManager::getProcessPath(DWORD pid) {
    auto info = getProcessById(pid);
    return info ? info->path : L"";
}

size_t ProcessManager::getProcessCount() {
    return enumerateProcesses().size();
}

bool ProcessManager::terminateProcess(DWORD pid, UINT exitCode, bool force) {
    std::lock_guard<std::mutex> lock(mtx_);
    
#ifdef _WIN32
    // nie zabijaj Systemu
    if (pid == 0 || pid == 4) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    DWORD access = PROCESS_TERMINATE;
    if (!force) access |= PROCESS_QUERY_INFORMATION;
    
    HANDLE hProc = OpenProcess(access, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    BOOL ok = TerminateProcess(hProc, exitCode);
    CloseHandle(hProc);
    
    if (ok) {
        setLastError(ErrorCode::OK);
        return true;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return false;
}

bool ProcessManager::suspendProcess(DWORD pid) {
    std::lock_guard<std::mutex> lock(mtx_);
    
#ifdef _WIN32
    if (!pImpl->NtSuspendProcess) {
        setLastError(ErrorCode::SystemError);
        return false;
    }
    
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    NTSTATUS st = pImpl->NtSuspendProcess(hProc);
    CloseHandle(hProc);
    
    if (st == 0) {
        setLastError(ErrorCode::OK);
        return true;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return false;
}

bool ProcessManager::resumeProcess(DWORD pid) {
    std::lock_guard<std::mutex> lock(mtx_);
    
#ifdef _WIN32
    if (!pImpl->NtResumeProcess) {
        setLastError(ErrorCode::SystemError);
        return false;
    }
    
    HANDLE hProc = OpenProcess(PROCESS_SUSPEND_RESUME, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    NTSTATUS st = pImpl->NtResumeProcess(hProc);
    CloseHandle(hProc);
    
    if (st == 0) {
        setLastError(ErrorCode::OK);
        return true;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return false;
}

DWORD ProcessManager::restartProcess(DWORD pid) {
#ifdef _WIN32
    auto info = getProcessById(pid);
    if (!info || info->path.empty()) {
        setLastError(ErrorCode::NotFound);
        return 0;
    }
    
    std::wstring path = info->path;
    
    if (!terminateProcess(pid, 0, true)) {
        return 0;
    }
    
    Sleep(500);  // daj czas na zamkniecie
    
    STARTUPINFOW si = {0};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessW(path.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        DWORD newPid = pi.dwProcessId;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        setLastError(ErrorCode::OK);
        return newPid;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return 0;
}

bool ProcessManager::setPriority(DWORD pid, ProcessPriority priority) {
    std::lock_guard<std::mutex> lock(mtx_);
    
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    BOOL ok = SetPriorityClass(hProc, static_cast<DWORD>(priority));
    CloseHandle(hProc);
    
    if (ok) {
        setLastError(ErrorCode::OK);
        return true;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return false;
}

std::optional<ProcessPriority> ProcessManager::getPriority(DWORD pid) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return std::nullopt;
    }
    
    DWORD prio = GetPriorityClass(hProc);
    CloseHandle(hProc);
    
    if (prio != 0) {
        setLastError(ErrorCode::OK);
        return static_cast<ProcessPriority>(prio);
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return std::nullopt;
}

bool ProcessManager::setAffinity(DWORD pid, DWORD_PTR mask) {
    std::lock_guard<std::mutex> lock(mtx_);
    
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return false;
    }
    
    BOOL ok = SetProcessAffinityMask(hProc, mask);
    CloseHandle(hProc);
    
    if (ok) {
        setLastError(ErrorCode::OK);
        return true;
    }
#endif
    
    setLastError(ErrorCode::SystemError);
    return false;
}

std::optional<std::pair<DWORD_PTR, DWORD_PTR>> ProcessManager::getAffinity(DWORD pid) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) {
        setLastError(ErrorCode::AccessDenied);
        return std::nullopt;
    }
    
    DWORD_PTR procMask, sysMask;
    if (GetProcessAffinityMask(hProc, &procMask, &sysMask)) {
        CloseHandle(hProc);
        setLastError(ErrorCode::OK);
        return std::make_pair(procMask, sysMask);
    }
    CloseHandle(hProc);
#endif
    
    setLastError(ErrorCode::SystemError);
    return std::nullopt;
}

bool ProcessManager::canAccessProcess(DWORD pid, DWORD desiredAccess) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(desiredAccess, FALSE, pid);
    if (hProc) {
        CloseHandle(hProc);
        return true;
    }
#endif
    return false;
}

bool ProcessManager::enableDebugPrivilege() {
#ifdef _WIN32
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), 
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }
    
    TOKEN_PRIVILEGES tp;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return false;
    }
    
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    
    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(hToken);
    
    return ok && GetLastError() == ERROR_SUCCESS;
#else
    return false;
#endif
}

bool ProcessManager::isRunningAsAdmin() {
#ifdef _WIN32
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    
    return isAdmin != FALSE;
#else
    return false;
#endif
}

ProcessResourceUsage ProcessManager::getProcessResources(DWORD pid) {
    ProcessResourceUsage usage;
    
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (hProc) {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(hProc, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            usage.workingSetSize = pmc.WorkingSetSize;
            usage.privateBytes = pmc.PrivateUsage;
        }
        
        IO_COUNTERS io;
        if (GetProcessIoCounters(hProc, &io)) {
            usage.ioRead = io.ReadTransferCount;
            usage.ioWrite = io.WriteTransferCount;
        }
        
        DWORD handles;
        if (GetProcessHandleCount(hProc, &handles)) {
            usage.handleCount = handles;
        }
        
        CloseHandle(hProc);
    }
#endif
    
    return usage;
}

bool ProcessManager::isProcess64Bit(DWORD pid) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    
    BOOL wow64 = FALSE;
    IsWow64Process(hProc, &wow64);
    CloseHandle(hProc);
    
    return !wow64;  // jesli NIE jest wow64, to jest 64bit (zakladajac 64bit Windows)
#else
    return false;
#endif
}

bool ProcessManager::isProcessRunning(DWORD pid) {
#ifdef _WIN32
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) return false;
    
    DWORD exitCode;
    if (GetExitCodeProcess(hProc, &exitCode)) {
        CloseHandle(hProc);
        return exitCode == STILL_ACTIVE;
    }
    CloseHandle(hProc);
#endif
    return false;
}

std::wstring ProcessManager::getCommandLine(DWORD pid) {
    // TODO: wymaga NtQueryInformationProcess i dostepu do PEB
    return L"";
}

ErrorCode ProcessManager::getLastError() const {
    return lastError_;
}

std::string ProcessManager::getLastErrorMessage() const {
    return errorCodeToString(lastError_);
}

void ProcessManager::setLastError(ErrorCode code) {
    lastError_ = code;
}

HANDLE ProcessManager::openProcess(DWORD pid, DWORD access) {
#ifdef _WIN32
    return OpenProcess(access, FALSE, pid);
#else
    return nullptr;
#endif
}

void ProcessManager::closeProcess(HANDLE handle) {
#ifdef _WIN32
    if (handle) CloseHandle(handle);
#endif
}

} // namespace casm
