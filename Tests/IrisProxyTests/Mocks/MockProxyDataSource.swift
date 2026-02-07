//
//  MockProxyDataSource.swift
//  IrisProxyTests
//
//  Mock implementation for testing proxy functionality.
//

import Foundation

/// Mock implementation of proxy data source for testing.
/// Simulates XPC communication with the proxy extension.
actor MockProxyDataSource {

    // MARK: - State

    var mockFlows: [ProxyCapturedFlow] = []
    var isEnabled: Bool = false
    var interceptionEnabled: Bool = false
    var shouldFail: Bool = false
    var failureError: Error = MockProxyError.connectionFailed

    // MARK: - Call Tracking

    var getStatusCallCount: Int = 0
    var getFlowsCallCount: Int = 0
    var clearFlowsCallCount: Int = 0
    var setInterceptionEnabledCallCount: Int = 0

    // MARK: - Mock Methods

    func getStatus() async throws -> ProxyStatus {
        getStatusCallCount += 1

        if shouldFail {
            throw failureError
        }

        return ProxyStatus(
            isActive: isEnabled,
            activeFlows: mockFlows.filter { !$0.isComplete }.count,
            flowCount: mockFlows.count,
            interceptionEnabled: interceptionEnabled,
            version: "1.0.0-test"
        )
    }

    func getFlows() async throws -> [ProxyCapturedFlow] {
        getFlowsCallCount += 1

        if shouldFail {
            throw failureError
        }

        return mockFlows
    }

    func getFlow(id: UUID) async throws -> ProxyCapturedFlow? {
        if shouldFail {
            throw failureError
        }

        return mockFlows.first { $0.id == id }
    }

    func clearFlows() async throws {
        clearFlowsCallCount += 1

        if shouldFail {
            throw failureError
        }

        mockFlows.removeAll()
    }

    func setInterceptionEnabled(_ enabled: Bool) async throws {
        setInterceptionEnabledCallCount += 1

        if shouldFail {
            throw failureError
        }

        interceptionEnabled = enabled
    }

    // MARK: - Test Helpers

    func reset() {
        mockFlows = []
        isEnabled = false
        interceptionEnabled = false
        shouldFail = false
        getStatusCallCount = 0
        getFlowsCallCount = 0
        clearFlowsCallCount = 0
        setInterceptionEnabledCallCount = 0
    }

    func setMockFlows(_ flows: [ProxyCapturedFlow]) {
        mockFlows = flows
    }

    func addMockFlow(_ flow: ProxyCapturedFlow) {
        mockFlows.append(flow)
    }

    func setShouldFail(_ fail: Bool) {
        shouldFail = fail
    }

    func setEnabled(_ enabled: Bool) {
        isEnabled = enabled
    }
}

// MARK: - Mock Types

/// Proxy status for mock.
struct ProxyStatus {
    let isActive: Bool
    let activeFlows: Int
    let flowCount: Int
    let interceptionEnabled: Bool
    let version: String
}

/// Mock errors for testing.
enum MockProxyError: Error, LocalizedError {
    case connectionFailed
    case extensionNotRunning
    case invalidResponse
    case timeout

    var errorDescription: String? {
        switch self {
        case .connectionFailed:
            return "Failed to connect to proxy extension"
        case .extensionNotRunning:
            return "Proxy extension is not running"
        case .invalidResponse:
            return "Received invalid response from proxy extension"
        case .timeout:
            return "Request timed out"
        }
    }
}
