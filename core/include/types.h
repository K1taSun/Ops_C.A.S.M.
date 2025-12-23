#ifndef CASM_TYPES_H
#define CASM_TYPES_H

#ifdef _WIN32
    #define WIN32_LEAN_AND_MEAN
    #include <windows.h>
#else
    typedef unsigned long DWORD;
    typedef unsigned long long DWORD_PTR;
    typedef unsigned int UINT;
    typedef void* HANDLE;
    typedef long long FILETIME;
#endif

#include <string>
#include <vector>
#include <cstdint>

#ifdef _WIN32
    #ifdef CASM_EXPORTS
        #define CASM_API __declspec(dllexport)
    #else
        #define CASM_API __declspec(dllimport)
    #endif
#else
    #define CASM_API
#endif

namespace casm {

enum class ProcessPriority : int {
    Idle = 0x40,
    BelowNormal = 0x4000,
    Normal = 0x20,
    AboveNormal = 0x8000,
    High = 0x80,
    Realtime = 0x100
};

enum class HideMethod : int {
    None = 0,
    InlineHook = 1,
    PebUnlink = 2,
    Dkom = 3  // wymaga driver
};

enum class ProcessState : int {
    Running = 0,
    Suspended = 1,
    Terminated = 2,
    Unknown = -1
};

struct ProcessInfo {
    DWORD pid;
    DWORD parentPid;
    std::wstring name;
    std::wstring path;
    DWORD threadCount;
    ProcessPriority priority;
    ProcessState state;
    uint64_t memoryUsage;
    double cpuUsage;
    uint64_t creationTime;
    bool isHidden;
    bool isSystem;
    
    ProcessInfo() :
        pid(0), parentPid(0), threadCount(0),
        priority(ProcessPriority::Normal),
        state(ProcessState::Unknown),
        memoryUsage(0), cpuUsage(0.0), creationTime(0),
        isHidden(false), isSystem(false) {}
};

struct MemoryInfo {
    uint64_t totalPhysical;
    uint64_t availablePhysical;
    uint64_t totalVirtual;
    uint64_t availableVirtual;
    uint32_t memoryLoad;
    
    MemoryInfo() : totalPhysical(0), availablePhysical(0),
        totalVirtual(0), availableVirtual(0), memoryLoad(0) {}
};

struct CPUInfo {
    std::string vendor;
    std::string brand;
    uint32_t coreCount;
    uint32_t threadCount;
    uint32_t currentMHz;
    uint32_t maxMHz;
    
    CPUInfo() : coreCount(0), threadCount(0), currentMHz(0), maxMHz(0) {}
};

struct OSInfo {
    std::wstring name;
    uint32_t majorVersion;
    uint32_t minorVersion;
    uint32_t buildNumber;
    bool is64Bit;
    
    OSInfo() : majorVersion(0), minorVersion(0), buildNumber(0), is64Bit(false) {}
};

struct ProcessResourceUsage {
    double cpuPercent;
    uint64_t workingSetSize;
    uint64_t privateBytes;
    uint64_t virtualSize;
    uint64_t ioRead;
    uint64_t ioWrite;
    uint32_t handleCount;
    uint32_t threadCount;
    
    ProcessResourceUsage() : cpuPercent(0.0), workingSetSize(0),
        privateBytes(0), virtualSize(0), ioRead(0), ioWrite(0),
        handleCount(0), threadCount(0) {}
};

enum class ErrorCode : int {
    OK = 0,
    NotInitialized = -1,
    InvalidParam = -2,
    NotFound = -3,
    AccessDenied = -4,
    InsufficientBuffer = -5,
    AlreadyHidden = -6,
    NotHidden = -7,
    HookFailed = -8,
    SystemError = -9,
    Unknown = -99
};

inline const char* errorCodeToString(ErrorCode code) {
    switch (code) {
        case ErrorCode::OK: return "OK";
        case ErrorCode::NotInitialized: return "Not initialized";
        case ErrorCode::InvalidParam: return "Invalid param";
        case ErrorCode::NotFound: return "Not found";
        case ErrorCode::AccessDenied: return "Access denied";
        case ErrorCode::InsufficientBuffer: return "Buffer too small";
        case ErrorCode::AlreadyHidden: return "Already hidden";
        case ErrorCode::NotHidden: return "Not hidden";
        case ErrorCode::HookFailed: return "Hook failed";
        case ErrorCode::SystemError: return "System error";
        default: return "Unknown";
    }
}

} // namespace casm

// C API
extern "C" {

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

#define CASM_PRIORITY_IDLE          0x40
#define CASM_PRIORITY_BELOW_NORMAL  0x4000
#define CASM_PRIORITY_NORMAL        0x20
#define CASM_PRIORITY_ABOVE_NORMAL  0x8000
#define CASM_PRIORITY_HIGH          0x80
#define CASM_PRIORITY_REALTIME      0x100

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
#define CASM_ERR_UNKNOWN          -99

}

#endif
