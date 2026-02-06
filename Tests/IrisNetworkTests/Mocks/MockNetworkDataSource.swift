import Foundation
@testable import Iris
import IrisShared

/// Mock implementation of NetworkDataSourceProtocol for testing.
actor MockNetworkDataSource: NetworkDataSourceProtocol {
    var mockConnectionData: [Data] = []
    var mockRuleData: [Data] = []
    var shouldFail: Bool = false
    var failureError: Error = IrisError.xpc(.connectionFailed("Mock failure"))
    var fetchConnectionsCallCount: Int = 0
    var fetchRulesCallCount: Int = 0

    func fetchConnections() async throws -> [Data] {
        fetchConnectionsCallCount += 1
        if shouldFail {
            throw failureError
        }
        return mockConnectionData
    }

    func fetchConnections(forPid pid: Int32) async throws -> [Data] {
        if shouldFail {
            throw failureError
        }
        let decoder = JSONDecoder()
        return mockConnectionData.filter { data in
            if let connection = try? decoder.decode(NetworkConnection.self, from: data) {
                return connection.processId == pid
            }
            return false
        }
    }

    func fetchRules() async throws -> [Data] {
        fetchRulesCallCount += 1
        if shouldFail {
            throw failureError
        }
        return mockRuleData
    }

    func addRule(_ ruleData: Data) async throws -> (success: Bool, error: String?) {
        if shouldFail {
            return (false, "Mock failure")
        }
        mockRuleData.append(ruleData)
        return (true, nil)
    }

    func removeRule(_ ruleId: String) async throws -> Bool {
        if shouldFail {
            return false
        }
        let decoder = JSONDecoder()
        mockRuleData.removeAll { data in
            if let rule = try? decoder.decode(SecurityRule.self, from: data) {
                return rule.id.uuidString == ruleId
            }
            return false
        }
        return true
    }

    func toggleRule(_ ruleId: String) async throws -> Bool {
        if shouldFail {
            return false
        }
        return true
    }

    func getStatus() async throws -> [String: Any] {
        return ["connected": !shouldFail, "mockSource": true]
    }

    // MARK: - Test Helpers

    func reset() {
        mockConnectionData = []
        mockRuleData = []
        shouldFail = false
        fetchConnectionsCallCount = 0
        fetchRulesCallCount = 0
    }

    func setMockConnections(_ connections: [NetworkConnection]) {
        let encoder = JSONEncoder()
        mockConnectionData = connections.compactMap { try? encoder.encode($0) }
    }

    func setMockRules(_ rules: [SecurityRule]) {
        let encoder = JSONEncoder()
        mockRuleData = rules.compactMap { try? encoder.encode($0) }
    }

    func setShouldFail(_ fail: Bool) {
        shouldFail = fail
    }
}
