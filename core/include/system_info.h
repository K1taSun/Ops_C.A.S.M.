#ifndef CASM_SYSTEM_INFO_H
#define CASM_SYSTEM_INFO_H

#include "types.h"
#include <vector>
#include <memory>
#include <mutex>
#include <chrono>

namespace casm {

struct DiskInfo {
    std::wstring driveLetter;
    std::wstring volumeName;
    std::wstring fileSystem;
    uint64_t totalBytes;
    uint64_t freeBytes;
    uint64_t usedBytes;
    double usagePercent;
    
    DiskInfo() : totalBytes(0), freeBytes(0), usedBytes(0), usagePercent(0.0) {}
};

struct NetworkInfo {
    std::wstring name;
    std::wstring description;
    std::string ipAddress;
    std::string macAddress;
    uint64_t bytesReceived;
    uint64_t bytesSent;
    bool isConnected;
    
    NetworkInfo() : bytesReceived(0), bytesSent(0), isConnected(false) {}
};

class CASM_API SystemInfo {
public:
    SystemInfo();
    ~SystemInfo();
    
    SystemInfo(const SystemInfo&) = delete;
    SystemInfo& operator=(const SystemInfo&) = delete;
    
    // OS
    OSInfo getOSInfo();
    std::wstring getOSFullName();
    std::wstring getComputerName();
    std::wstring getUserName();
    uint64_t getSystemUptime();
    std::string getUptimeString();
    
    // CPU
    CPUInfo getCPUInfo();
    double getCpuUsage();
    std::vector<double> getCpuUsagePerCore();
    uint32_t getLogicalProcessorCount();
    uint32_t getPhysicalCoreCount();
    
    // Memory
    MemoryInfo getMemoryInfo();
    uint32_t getMemoryUsagePercent();
    uint64_t getAvailableMemory();
    uint64_t getTotalMemory();
    
    // Disk
    std::vector<DiskInfo> getDiskInfo();
    DiskInfo getDiskInfo(const std::wstring& driveLetter);
    uint64_t getTotalDiskSpace();
    uint64_t getFreeDiskSpace();
    
    // Network
    std::vector<NetworkInfo> getNetworkInfo();
    bool isInternetConnected();
    
    // Process resources
    ProcessResourceUsage getProcessResources(DWORD pid);
    uint32_t getProcessCount();
    uint32_t getTotalThreadCount();
    uint32_t getTotalHandleCount();
    
    // monitoring
    void startPerformanceMonitoring(uint32_t intervalMs = 1000);
    void stopPerformanceMonitoring();
    bool isMonitoringActive() const;
    std::vector<double> getCpuHistory(size_t samples = 60);
    std::vector<double> getMemoryHistory(size_t samples = 60);
    
    // formatowanie
    static std::string formatBytes(uint64_t bytes);
    static std::string formatDuration(uint64_t seconds);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
    
    mutable std::mutex mtx_;
    
    struct Cache {
        OSInfo osInfo;
        CPUInfo cpuInfo;
        bool osInfoValid = false;
        bool cpuInfoValid = false;
        std::chrono::steady_clock::time_point lastUpdate;
    };
    mutable Cache cache_;
    
    std::vector<double> cpuHistory_;
    std::vector<double> memHistory_;
    bool monitoringActive_;
    
    void updateCache();
};

CASM_API SystemInfo& getGlobalSystemInfo();

} // namespace casm

#endif
