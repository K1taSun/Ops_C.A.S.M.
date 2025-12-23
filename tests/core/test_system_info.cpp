#include <gtest/gtest.h>
#include "system_info.h"

#ifdef _WIN32

using namespace casm;

class SysInfoTest : public ::testing::Test {
protected:
    void SetUp() override {
        info = std::make_unique<SystemInfo>();
    }
    std::unique_ptr<SystemInfo> info;
};

TEST_F(SysInfoTest, OSInfoValid) {
    auto os = info->getOSInfo();
    EXPECT_GE(os.majorVersion, 6);
    EXPECT_FALSE(os.name.empty());
}

TEST_F(SysInfoTest, OSFullName) {
    auto name = info->getOSFullName();
    EXPECT_FALSE(name.empty());
    EXPECT_NE(name.find(L"Windows"), std::wstring::npos);
}

TEST_F(SysInfoTest, ComputerName) {
    auto name = info->getComputerName();
    EXPECT_FALSE(name.empty());
}

TEST_F(SysInfoTest, UserName) {
    auto name = info->getUserName();
    EXPECT_FALSE(name.empty());
}

TEST_F(SysInfoTest, Uptime) {
    EXPECT_GT(info->getSystemUptime(), 0);
}

TEST_F(SysInfoTest, CPUInfo) {
    auto cpu = info->getCPUInfo();
    EXPECT_FALSE(cpu.vendor.empty());
    EXPECT_GT(cpu.threadCount, 0);
}

TEST_F(SysInfoTest, CPUUsageRange) {
    Sleep(1100);
    double u = info->getCpuUsage();
    EXPECT_GE(u, 0.0);
    EXPECT_LE(u, 100.0);
}

TEST_F(SysInfoTest, LogicalCores) {
    EXPECT_GT(info->getLogicalProcessorCount(), 0);
}

TEST_F(SysInfoTest, MemInfo) {
    auto m = info->getMemoryInfo();
    EXPECT_GT(m.totalPhysical, 0);
    EXPECT_LE(m.availablePhysical, m.totalPhysical);
    EXPECT_LE(m.memoryLoad, 100);
}

TEST_F(SysInfoTest, MemPercent) {
    auto p = info->getMemoryUsagePercent();
    EXPECT_LE(p, 100);
}

TEST_F(SysInfoTest, TotalMemAtLeast1GB) {
    uint64_t gb = 1024ULL * 1024 * 1024;
    EXPECT_GE(info->getTotalMemory(), gb);
}

TEST_F(SysInfoTest, DiskNotEmpty) {
    auto disks = info->getDiskInfo();
    EXPECT_FALSE(disks.empty());
}

TEST_F(SysInfoTest, HasCDrive) {
    auto disks = info->getDiskInfo();
    bool found = false;
    for (const auto& d : disks) {
        if (d.driveLetter == L"C:") {
            found = true;
            EXPECT_GT(d.totalBytes, 0);
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(SysInfoTest, ProcCount) {
    EXPECT_GT(info->getProcessCount(), 0);
}

TEST_F(SysInfoTest, FormatBytesKB) {
    EXPECT_EQ(SystemInfo::formatBytes(1536), "1.5 KB");
}

TEST_F(SysInfoTest, FormatBytesMB) {
    EXPECT_EQ(SystemInfo::formatBytes(1572864), "1.5 MB");
}

TEST_F(SysInfoTest, FormatDuration) {
    EXPECT_EQ(SystemInfo::formatDuration(3660), "1h 1m");
}

TEST_F(SysInfoTest, Singleton) {
    auto& a = getGlobalSystemInfo();
    auto& b = getGlobalSystemInfo();
    EXPECT_EQ(&a, &b);
}

TEST_F(SysInfoTest, Monitoring) {
    EXPECT_FALSE(info->isMonitoringActive());
    info->startPerformanceMonitoring(100);
    EXPECT_TRUE(info->isMonitoringActive());
    info->stopPerformanceMonitoring();
    EXPECT_FALSE(info->isMonitoringActive());
}

#endif
