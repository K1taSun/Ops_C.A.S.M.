#ifndef CASM_PROCESS_HIDER_H
#define CASM_PROCESS_HIDER_H

#include "types.h"
#include <vector>
#include <set>
#include <memory>
#include <mutex>
#include <functional>

namespace casm {

using HideStateCallback = std::function<void(DWORD pid, bool hidden)>;

/*
 * Ukrywanie procesow przed innymi aplikacjami.
 * Techniki:
 *  - InlineHook: hookowanie NtQuerySystemInformation
 *  - PebUnlink: usuwanie z listy PEB
 *  - Dkom: modyfikacja struktur kernela (wymaga drivera)
 * 
 * UWAGA: wymaga admina, moze byc wykrywane przez AV
 */
class CASM_API ProcessHider {
public:
    ProcessHider();
    ~ProcessHider();
    
    ProcessHider(const ProcessHider&) = delete;
    ProcessHider& operator=(const ProcessHider&) = delete;
    
    ErrorCode initialize(HideMethod method = HideMethod::InlineHook);
    void shutdown();
    bool isInitialized() const;
    
    bool hideProcess(DWORD pid);
    bool unhideProcess(DWORD pid);
    bool toggleHide(DWORD pid);
    size_t unhideAll();
    
    bool isProcessHidden(DWORD pid) const;
    std::vector<DWORD> getHiddenProcesses() const;
    size_t getHiddenCount() const;
    
    HideMethod getActiveMethod() const;
    bool isMethodAvailable(HideMethod method) const;
    std::vector<HideMethod> getAvailableMethods() const;
    bool setHideMethod(HideMethod method);
    
    void setStateChangeCallback(HideStateCallback callback);
    void clearStateChangeCallback();
    
    ErrorCode getLastError() const;
    std::string getLastErrorMessage() const;
    bool areHooksActive() const;
    std::string getDiagnostics() const;

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    bool initialized_;
    HideMethod activeMethod_;
    std::set<DWORD> hiddenPids_;
    mutable std::mutex mtx_;
    ErrorCode lastError_;
    HideStateCallback callback_;
    
    void setLastError(ErrorCode code);
    void notifyStateChange(DWORD pid, bool hidden);
    
    bool installInlineHook();
    bool uninstallInlineHook();
    bool unlinkFromPeb(DWORD pid);
    bool relinkToPeb(DWORD pid);
};

CASM_API ProcessHider& getGlobalHider();

} // namespace casm

#endif
