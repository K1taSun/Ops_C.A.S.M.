#include <gtest/gtest.h>
#include "process_manager.h"

#ifdef _WIN32

using namespace casm;

class ProcMgrTest : public ::testing::Test {
protected:
    void SetUp() override {
        mgr = std::make_unique<ProcessManager>();
    }
    std::unique_ptr<ProcessManager> mgr;
};

TEST_F(ProcMgrTest, EnumerateNotEmpty) {
    auto procs = mgr->enumerateProcesses();
    EXPECT_FALSE(procs.empty());
    EXPECT_GT(procs.size(), 5);
}

TEST_F(ProcMgrTest, HasSystemProc) {
    auto procs = mgr->enumerateProcesses();
    bool found = false;
    for (const auto& p : procs) {
        if (p.pid == 4) {
            found = true;
            EXPECT_EQ(p.name, L"System");
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(ProcMgrTest, GetByIdExists) {
    auto p = mgr->getProcessById(4);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->pid, 4);
}

TEST_F(ProcMgrTest, GetByIdNotExists) {
    auto p = mgr->getProcessById(99999999);
    EXPECT_FALSE(p.has_value());
}

TEST_F(ProcMgrTest, FindByName) {
    auto procs = mgr->findProcessesByName(L"System");
    EXPECT_FALSE(procs.empty());
}

TEST_F(ProcMgrTest, FindCaseInsensitive) {
    auto a = mgr->findProcessesByName(L"system", false);
    auto b = mgr->findProcessesByName(L"SYSTEM", false);
    EXPECT_EQ(a.size(), b.size());
}

TEST_F(ProcMgrTest, CountPositive) {
    EXPECT_GT(mgr->getProcessCount(), 0);
}

TEST_F(ProcMgrTest, TreeNotEmpty) {
    auto tree = mgr->getProcessTree();
    EXPECT_FALSE(tree.empty());
}

TEST_F(ProcMgrTest, CantKillSystem) {
    bool ok = mgr->terminateProcess(4, 0, true);
    EXPECT_FALSE(ok);
    EXPECT_EQ(mgr->getLastError(), ErrorCode::AccessDenied);
}

TEST_F(ProcMgrTest, SetPrioInvalidProc) {
    bool ok = mgr->setPriority(99999999, ProcessPriority::Normal);
    EXPECT_FALSE(ok);
}

TEST_F(ProcMgrTest, IsAdmin) {
    // just check it doesn't crash
    ProcessManager::isRunningAsAdmin();
    SUCCEED();
}

TEST_F(ProcMgrTest, EnableDebugPriv) {
    // may or may not work depending on rights
    ProcessManager::enableDebugPrivilege();
    SUCCEED();
}

TEST_F(ProcMgrTest, CurrentProcResources) {
    DWORD pid = GetCurrentProcessId();
    auto r = mgr->getProcessResources(pid);
    EXPECT_GT(r.workingSetSize, 0);
}

TEST_F(ProcMgrTest, CurrentProcRunning) {
    DWORD pid = GetCurrentProcessId();
    EXPECT_TRUE(mgr->isProcessRunning(pid));
}

TEST_F(ProcMgrTest, FakeProcNotRunning) {
    EXPECT_FALSE(mgr->isProcessRunning(99999999));
}

#endif

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
