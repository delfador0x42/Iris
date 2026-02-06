import Testing
@testable import Iris

@Suite("SecurityStore Tests")
struct SecurityStoreTests {

    @Test("Initial state is disconnected with empty data")
    @MainActor
    func testInitialState() async {
        let mockDataSource = MockNetworkDataSource()
        let store = SecurityStore(dataSource: mockDataSource)

        #expect(store.connections.isEmpty)
        #expect(store.rules.isEmpty)
        #expect(!store.isConnected)
        #expect(store.lastUpdate == nil)
    }

    @Test("Refresh loads connections from data source")
    @MainActor
    func testRefreshLoadsConnections() async {
        let mockDataSource = MockNetworkDataSource()

        // Create mock connection data
        await mockDataSource.setMockConnections([
            createMockConnection(processName: "Safari", remoteAddress: "17.253.144.10"),
            createMockConnection(processName: "curl", remoteAddress: "8.8.8.8")
        ])

        let store = SecurityStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.connections.count == 2)
        #expect(store.lastUpdate != nil)
        #expect(store.errorMessage == nil)
    }

    @Test("Refresh handles data source failure")
    @MainActor
    func testRefreshHandlesFailure() async {
        let mockDataSource = MockNetworkDataSource()
        await mockDataSource.setShouldFail(true)

        let store = SecurityStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.connections.isEmpty)
        #expect(store.errorMessage != nil)
    }

    @Test("Connections are grouped by process")
    @MainActor
    func testConnectionsGroupedByProcess() async {
        let mockDataSource = MockNetworkDataSource()

        await mockDataSource.setMockConnections([
            createMockConnection(processName: "Safari", remoteAddress: "17.253.144.10", pid: 1234),
            createMockConnection(processName: "Safari", remoteAddress: "17.253.144.11", pid: 1234),
            createMockConnection(processName: "curl", remoteAddress: "8.8.8.8", pid: 5678)
        ])

        let store = SecurityStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.processes.count == 2)
        #expect(store.connectionsByProcess[1234]?.count == 2)
        #expect(store.connectionsByProcess[5678]?.count == 1)
    }

    @Test("Total bytes are calculated correctly")
    @MainActor
    func testTotalBytesCalculation() async {
        let mockDataSource = MockNetworkDataSource()

        await mockDataSource.setMockConnections([
            createMockConnection(processName: "Safari", remoteAddress: "1.2.3.4", bytesUp: 100, bytesDown: 200),
            createMockConnection(processName: "curl", remoteAddress: "5.6.7.8", bytesUp: 50, bytesDown: 150)
        ])

        let store = SecurityStore(dataSource: mockDataSource)
        await store.refresh()

        #expect(store.totalBytesUp == 150)
        #expect(store.totalBytesDown == 350)
    }

    // MARK: - Helpers

    func createMockConnection(
        processName: String,
        remoteAddress: String,
        pid: Int32 = 1234,
        bytesUp: UInt64 = 0,
        bytesDown: UInt64 = 0
    ) -> NetworkConnection {
        NetworkConnection(
            processId: pid,
            processPath: "/usr/bin/\(processName.lowercased())",
            processName: processName,
            localAddress: "192.168.1.100",
            localPort: 54321,
            remoteAddress: remoteAddress,
            remotePort: 443,
            protocol: .tcp,
            state: .established,
            bytesUp: bytesUp,
            bytesDown: bytesDown
        )
    }
}
