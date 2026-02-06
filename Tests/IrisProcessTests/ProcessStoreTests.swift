import Testing
@testable import Iris

@Suite("ProcessStore Tests")
struct ProcessStoreTests {

    @Test("Initial state is empty")
    @MainActor
    func testInitialState() async {
        let mockDataSource = MockProcessDataSource()
        let store = ProcessStore(dataSource: mockDataSource)

        #expect(store.processes.isEmpty)
        #expect(!store.isLoading)
        #expect(store.lastUpdate == nil)
        #expect(store.errorMessage == nil)
    }

    @Test("Refresh loads processes from data source")
    @MainActor
    func testRefreshLoadsProcesses() async {
        let mockDataSource = MockProcessDataSource()

        // Create mock process data
        await mockDataSource.setMockProcesses([
            createMockProcess(name: "Safari", pid: 1234),
            createMockProcess(name: "Finder", pid: 5678)
        ])

        let store = ProcessStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.processes.count == 2)
        #expect(store.lastUpdate != nil)
        #expect(store.errorMessage == nil)
    }

    @Test("Refresh handles data source failure")
    @MainActor
    func testRefreshHandlesFailure() async {
        let mockDataSource = MockProcessDataSource()
        await mockDataSource.setShouldFail(true)

        let store = ProcessStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.processes.isEmpty)
        #expect(store.errorMessage != nil)
    }

    @Test("Filter by search text works")
    @MainActor
    func testFilterBySearchText() async {
        let mockDataSource = MockProcessDataSource()

        await mockDataSource.setMockProcesses([
            createMockProcess(name: "Safari", pid: 1234),
            createMockProcess(name: "Finder", pid: 5678),
            createMockProcess(name: "Terminal", pid: 9012)
        ])

        let store = ProcessStore(dataSource: mockDataSource)
        await store.refresh()

        store.filterText = "Saf"
        let filtered = store.displayedProcesses

        #expect(filtered.count == 1)
        #expect(filtered.first?.name == "Safari")
    }

    @Test("Suspicious count is calculated correctly")
    @MainActor
    func testSuspiciousCount() async {
        let mockDataSource = MockProcessDataSource()

        await mockDataSource.setMockProcesses([
            createMockProcess(name: "Normal", pid: 1, isSuspicious: false),
            createMockProcess(name: "Suspicious1", pid: 2, isSuspicious: true),
            createMockProcess(name: "Suspicious2", pid: 3, isSuspicious: true)
        ])

        let store = ProcessStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.suspiciousCount == 2)
        #expect(store.totalCount == 3)
    }

    @Test("Show only suspicious filter works")
    @MainActor
    func testShowOnlySuspiciousFilter() async {
        let mockDataSource = MockProcessDataSource()

        await mockDataSource.setMockProcesses([
            createMockProcess(name: "Normal", pid: 1, isSuspicious: false),
            createMockProcess(name: "Suspicious", pid: 2, isSuspicious: true)
        ])

        let store = ProcessStore(dataSource: mockDataSource)
        await store.refresh()

        store.showOnlySuspicious = true
        let filtered = store.displayedProcesses

        #expect(filtered.count == 1)
        #expect(filtered.first?.isSuspicious == true)
    }

    // MARK: - Helpers

    func createMockProcess(name: String, pid: Int32, isSuspicious: Bool = false) -> ProcessInfo {
        ProcessInfo(
            pid: pid,
            name: name,
            path: "/usr/bin/\(name.lowercased())",
            userId: 501,
            signingStatus: .validApple,
            isSuspicious: isSuspicious
        )
    }
}
