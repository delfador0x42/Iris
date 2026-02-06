import Foundation
@testable import Iris
import IrisShared

/// Mock implementation of ProcessDataSourceProtocol for testing.
actor MockProcessDataSource: ProcessDataSourceProtocol {
    var mockProcessData: [Data] = []
    var shouldFail: Bool = false
    var failureError: Error = IrisError.xpc(.connectionFailed("Mock failure"))
    var fetchCallCount: Int = 0

    func fetchProcesses() async throws -> [Data] {
        fetchCallCount += 1
        if shouldFail {
            throw failureError
        }
        return mockProcessData
    }

    func fetchProcess(pid: Int32) async throws -> Data? {
        if shouldFail {
            throw failureError
        }
        // Find process with matching PID in mock data
        let decoder = JSONDecoder()
        for data in mockProcessData {
            if let process = try? decoder.decode(ProcessInfo.self, from: data),
               process.pid == pid {
                return data
            }
        }
        return nil
    }

    func getStatus() async throws -> [String: Any] {
        return ["connected": !shouldFail, "mockSource": true]
    }

    // MARK: - Test Helpers

    func reset() {
        mockProcessData = []
        shouldFail = false
        fetchCallCount = 0
    }

    func setMockProcesses(_ processes: [ProcessInfo]) {
        let encoder = JSONEncoder()
        mockProcessData = processes.compactMap { try? encoder.encode($0) }
    }

    func setShouldFail(_ fail: Bool) {
        shouldFail = fail
    }
}
