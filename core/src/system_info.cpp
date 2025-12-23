#include "../include/system_info.h"

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#include <pdh.h>
#include <intrin.h>
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "psapi.lib")
#endif

#include <sstream>
#include <iomanip>
#include <thread>
#include <atomic>

namespace casm {

class SystemInfo::Impl {
public:
    Impl() : monThread(nullptr), stopFlag(false) {}
    ~Impl() { stopMonitor(); }
    
#ifdef _WIN32
    PDH_HQUERY cpuQuery = nullptr;
    PDH_HCOUNTER cpuCounter = nullptr;
    
    bool initPdh() {
        if (cpuQuery) return true;
        if (PdhOpenQuery(NULL, 0, &cpuQuery) != ERROR_SUCCESS) return false;
        if (PdhAddCounterW(cpuQuery, L"\\Processor(_Total)\\% Processor Time", 
                           0, &cpuCounter) != ERROR_SUCCESS) {
            PdhCloseQuery(cpuQuery);
            cpuQuery = nullptr;
            return false;
        }
        PdhCollectQueryData(cpuQuery);
        return true;
    }
    
    void closePdh() {
        if (cpuQuery) {
            PdhCloseQuery(cpuQuery);
            cpuQuery = nullptr;
            cpuCounter = nullptr;
        }
    }
#endif
    
    std::thread* monThread;
    std::atomic<bool> stopFlag;
    
    void stopMonitor() {
        stopFlag = true;
        if (monThread && monThread->joinable()) {
            monThread->join();
            delete monThread;
            monThread = nullptr;
        }
    }
};

SystemInfo::SystemInfo()
    : pImpl(std::make_unique<Impl>()), monitoringActive_(false) {
#ifdef _WIN32
    pImpl->initPdh();
#endif
}

SystemInfo::~SystemInfo() {
    stopPerformanceMonitoring();
#ifdef _WIN32
    pImpl->closePdh();
#endif
}

OSInfo SystemInfo::getOSInfo() {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (cache_.osInfoValid) return cache_.osInfo;
    
    OSInfo info;
    
#ifdef _WIN32
    typedef NTSTATUS(WINAPI* pRtlGetVersion)(PRTL_OSVERSIONINFOW);
    
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto RtlGetVersion = (pRtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = {0};
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (RtlGetVersion(&osvi) == 0) {
                info.majorVersion = osvi.dwMajorVersion;
                info.minorVersion = osvi.dwMinorVersion;
                info.buildNumber = osvi.dwBuildNumber;
            }
        }
    }
    
    if (info.majorVersion == 10 && info.buildNumber >= 22000) {
        info.name = L"Windows 11";
    } else if (info.majorVersion == 10) {
        info.name = L"Windows 10";
    } else if (info.majorVersion == 6 && info.minorVersion == 3) {
        info.name = L"Windows 8.1";
    } else if (info.majorVersion == 6 && info.minorVersion == 2) {
        info.name = L"Windows 8";
    } else if (info.majorVersion == 6 && info.minorVersion == 1) {
        info.name = L"Windows 7";
    } else {
        info.name = L"Windows";
    }
    
    SYSTEM_INFO sysInfo;
    GetNativeSystemInfo(&sysInfo);
    info.is64Bit = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
#endif
    
    cache_.osInfo = info;
    cache_.osInfoValid = true;
    return info;
}

std::wstring SystemInfo::getOSFullName() {
    auto info = getOSInfo();
    std::wstringstream ss;
    ss << info.name << L" (Build " << info.buildNumber << L")";
    if (info.is64Bit) ss << L" x64";
    return ss.str();
}

std::wstring SystemInfo::getComputerName() {
#ifdef _WIN32
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD sz = sizeof(buf) / sizeof(buf[0]);
    if (GetComputerNameW(buf, &sz)) return buf;
#endif
    return L"Unknown";
}

std::wstring SystemInfo::getUserName() {
#ifdef _WIN32
    wchar_t buf[UNLEN + 1];
    DWORD sz = sizeof(buf) / sizeof(buf[0]);
    if (GetUserNameW(buf, &sz)) return buf;
#endif
    return L"Unknown";
}

uint64_t SystemInfo::getSystemUptime() {
#ifdef _WIN32
    return GetTickCount64() / 1000;
#else
    return 0;
#endif
}

std::string SystemInfo::getUptimeString() {
    return formatDuration(getSystemUptime());
}

CPUInfo SystemInfo::getCPUInfo() {
    std::lock_guard<std::mutex> lock(mtx_);
    
    if (cache_.cpuInfoValid) return cache_.cpuInfo;
    
    CPUInfo info;
    
#ifdef _WIN32
    int cpuInfo[4] = {0};
    
    __cpuid(cpuInfo, 0);
    char vendor[13] = {0};
    memcpy(vendor, &cpuInfo[1], 4);
    memcpy(vendor + 4, &cpuInfo[3], 4);
    memcpy(vendor + 8, &cpuInfo[2], 4);
    info.vendor = vendor;
    
    char brand[49] = {0};
    __cpuid(cpuInfo, 0x80000002);
    memcpy(brand, cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000003);
    memcpy(brand + 16, cpuInfo, 16);
    __cpuid(cpuInfo, 0x80000004);
    memcpy(brand + 32, cpuInfo, 16);
    info.brand = brand;
    
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    info.threadCount = sysInfo.dwNumberOfProcessors;
    
    HKEY hKey;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD mhz;
        DWORD sz = sizeof(mhz);
        if (RegQueryValueExW(hKey, L"~MHz", NULL, NULL, (LPBYTE)&mhz, &sz) == ERROR_SUCCESS) {
            info.currentMHz = mhz;
            info.maxMHz = mhz;
        }
        RegCloseKey(hKey);
    }
    
    info.coreCount = info.threadCount / 2;
    if (info.coreCount == 0) info.coreCount = 1;
#endif
    
    cache_.cpuInfo = info;
    cache_.cpuInfoValid = true;
    return info;
}

double SystemInfo::getCpuUsage() {
#ifdef _WIN32
    if (!pImpl->cpuQuery) {
        if (!pImpl->initPdh()) return 0.0;
    }
    
    PdhCollectQueryData(pImpl->cpuQuery);
    
    PDH_FMT_COUNTERVALUE val;
    if (PdhGetFormattedCounterValue(pImpl->cpuCounter, PDH_FMT_DOUBLE, NULL, &val) == ERROR_SUCCESS) {
        return val.doubleValue;
    }
#endif
    return 0.0;
}

std::vector<double> SystemInfo::getCpuUsagePerCore() {
    std::vector<double> usage;
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    double total = getCpuUsage();
    for (DWORD i = 0; i < sysInfo.dwNumberOfProcessors; i++) {
        usage.push_back(total);  // uproszczone
    }
#endif
    return usage;
}

uint32_t SystemInfo::getLogicalProcessorCount() {
#ifdef _WIN32
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);
    return sysInfo.dwNumberOfProcessors;
#else
    return std::thread::hardware_concurrency();
#endif
}

uint32_t SystemInfo::getPhysicalCoreCount() {
    return getLogicalProcessorCount() / 2;
}

MemoryInfo SystemInfo::getMemoryInfo() {
    MemoryInfo info;
#ifdef _WIN32
    MEMORYSTATUSEX mem;
    mem.dwLength = sizeof(mem);
    if (GlobalMemoryStatusEx(&mem)) {
        info.totalPhysical = mem.ullTotalPhys;
        info.availablePhysical = mem.ullAvailPhys;
        info.totalVirtual = mem.ullTotalVirtual;
        info.availableVirtual = mem.ullAvailVirtual;
        info.memoryLoad = mem.dwMemoryLoad;
    }
#endif
    return info;
}

uint32_t SystemInfo::getMemoryUsagePercent() {
    return getMemoryInfo().memoryLoad;
}

uint64_t SystemInfo::getAvailableMemory() {
    return getMemoryInfo().availablePhysical;
}

uint64_t SystemInfo::getTotalMemory() {
    return getMemoryInfo().totalPhysical;
}

std::vector<DiskInfo> SystemInfo::getDiskInfo() {
    std::vector<DiskInfo> disks;
    
#ifdef _WIN32
    DWORD drives = GetLogicalDrives();
    
    for (char letter = 'A'; letter <= 'Z'; letter++) {
        if (drives & (1 << (letter - 'A'))) {
            wchar_t root[4] = {(wchar_t)letter, L':', L'\\', 0};
            
            UINT type = GetDriveTypeW(root);
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                DiskInfo disk;
                disk.driveLetter = std::wstring(1, letter) + L":";
                
                ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
                if (GetDiskFreeSpaceExW(root, &freeBytesAvail, &totalBytes, &totalFreeBytes)) {
                    disk.totalBytes = totalBytes.QuadPart;
                    disk.freeBytes = totalFreeBytes.QuadPart;
                    disk.usedBytes = disk.totalBytes - disk.freeBytes;
                    disk.usagePercent = (double)disk.usedBytes / disk.totalBytes * 100.0;
                }
                
                wchar_t volName[MAX_PATH + 1] = {0};
                wchar_t fsName[MAX_PATH + 1] = {0};
                if (GetVolumeInformationW(root, volName, MAX_PATH, NULL, NULL, NULL, fsName, MAX_PATH)) {
                    disk.volumeName = volName;
                    disk.fileSystem = fsName;
                }
                
                disks.push_back(disk);
            }
        }
    }
#endif
    
    return disks;
}

DiskInfo SystemInfo::getDiskInfo(const std::wstring& driveLetter) {
    for (const auto& d : getDiskInfo()) {
        if (d.driveLetter == driveLetter) return d;
    }
    return DiskInfo();
}

uint64_t SystemInfo::getTotalDiskSpace() {
    uint64_t total = 0;
    for (const auto& d : getDiskInfo()) total += d.totalBytes;
    return total;
}

uint64_t SystemInfo::getFreeDiskSpace() {
    uint64_t free = 0;
    for (const auto& d : getDiskInfo()) free += d.freeBytes;
    return free;
}

std::vector<NetworkInfo> SystemInfo::getNetworkInfo() {
    // TODO: GetAdaptersAddresses
    return {};
}

bool SystemInfo::isInternetConnected() {
#ifdef _WIN32
    DWORD flags;
    return InternetGetConnectedState(&flags, 0) != FALSE;
#else
    return false;
#endif
}

ProcessResourceUsage SystemInfo::getProcessResources(DWORD pid) {
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

uint32_t SystemInfo::getProcessCount() {
#ifdef _WIN32
    DWORD procs[1024], needed;
    if (EnumProcesses(procs, sizeof(procs), &needed)) {
        return needed / sizeof(DWORD);
    }
#endif
    return 0;
}

uint32_t SystemInfo::getTotalThreadCount() {
    // TODO
    return 0;
}

uint32_t SystemInfo::getTotalHandleCount() {
    // TODO: NtQuerySystemInformation
    return 0;
}

void SystemInfo::startPerformanceMonitoring(uint32_t intervalMs) {
    if (monitoringActive_) return;
    
    monitoringActive_ = true;
    pImpl->stopFlag = false;
    
    pImpl->monThread = new std::thread([this, intervalMs]() {
        while (!pImpl->stopFlag) {
            double cpu = getCpuUsage();
            double mem = (double)getMemoryUsagePercent();
            
            {
                std::lock_guard<std::mutex> lock(mtx_);
                cpuHistory_.push_back(cpu);
                memHistory_.push_back(mem);
                
                // limit histori
                if (cpuHistory_.size() > 3600) cpuHistory_.erase(cpuHistory_.begin());
                if (memHistory_.size() > 3600) memHistory_.erase(memHistory_.begin());
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(intervalMs));
        }
    });
}

void SystemInfo::stopPerformanceMonitoring() {
    monitoringActive_ = false;
    pImpl->stopMonitor();
}

bool SystemInfo::isMonitoringActive() const {
    return monitoringActive_;
}

std::vector<double> SystemInfo::getCpuHistory(size_t samples) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (cpuHistory_.size() <= samples) return cpuHistory_;
    return std::vector<double>(cpuHistory_.end() - samples, cpuHistory_.end());
}

std::vector<double> SystemInfo::getMemoryHistory(size_t samples) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (memHistory_.size() <= samples) return memHistory_;
    return std::vector<double>(memHistory_.end() - samples, memHistory_.end());
}

std::string SystemInfo::formatBytes(uint64_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int u = 0;
    double sz = static_cast<double>(bytes);
    
    while (sz >= 1024 && u < 4) {
        sz /= 1024;
        u++;
    }
    
    std::stringstream ss;
    ss << std::fixed << std::setprecision(1) << sz << " " << units[u];
    return ss.str();
}

std::string SystemInfo::formatDuration(uint64_t seconds) {
    uint64_t d = seconds / 86400;
    uint64_t h = (seconds % 86400) / 3600;
    uint64_t m = (seconds % 3600) / 60;
    
    std::stringstream ss;
    if (d > 0) ss << d << "d ";
    if (h > 0 || d > 0) ss << h << "h ";
    ss << m << "m";
    return ss.str();
}

SystemInfo& getGlobalSystemInfo() {
    static SystemInfo instance;
    return instance;
}

} // namespace casm
