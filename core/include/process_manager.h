#ifndef CASM_PROCESS_MANAGER_H
#define CASM_PROCESS_MANAGER_H

#include "types.h"

#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace casm {

class CASM_API ProcessManager {
public:
    ProcessManager();
    ~ProcessManager();

    ProcessManager(const ProcessManager&) = delete;
    ProcessManager& operator=(const ProcessManager&) = delete;
    
    // pobieranie listy procesow
    std::vector<ProcessInfo> enumerateProcesses();
    std::optional<ProcessInfo> getProcessById(DWORD pid);
    std::vector<ProcessInfo> findProcessesByName(const std::wstring& name, bool caseSensitive = false);
    std::map<DWORD, std::vector<DWORD>> getProcessTree();
    std::wstring getProcessPath(DWORD pid);
    size_t getProcessCount();
    
    // zarzadzanie
    bool terminateProcess(DWORD pid, UINT exitCode = 0, bool force = false);
    bool suspendProcess(DWORD pid);
    bool resumeProcess(DWORD pid);
    DWORD restartProcess(DWORD pid);
    
    // modyfikacja
    bool setPriority(DWORD pid, ProcessPriority priority);
    std::optional<ProcessPriority> getPriority(DWORD pid);
    bool setAffinity(DWORD pid, DWORD_PTR affinityMask);
    std::optional<std::pair<DWORD_PTR, DWORD_PTR>> getAffinity(DWORD pid);
    
    // uprawnienia
    bool canAccessProcess(DWORD pid, DWORD desiredAccess);
    static bool enableDebugPrivilege();
    static bool isRunningAsAdmin();
    
    // info o procesie
    ProcessResourceUsage getProcessResources(DWORD pid);
    bool isProcess64Bit(DWORD pid);
    bool isProcessRunning(DWORD pid);
    std::wstring getCommandLine(DWORD pid);  // TODO: zaimplementowac
    
    ErrorCode getLastError() const;
    std::string getLastErrorMessage() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    mutable std::mutex mtx_;
    ErrorCode lastError_;
    
    HANDLE openProcess(DWORD pid, DWORD access);
    void closeProcess(HANDLE handle);
    void setLastError(ErrorCode code);
};

} // namespace casm

#endif
