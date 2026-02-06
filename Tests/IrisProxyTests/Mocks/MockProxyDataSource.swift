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

// MARK: - Test Flow Factory

/// Factory for creating test flows.
enum TestFlowFactory {

    /// Creates a simple GET request flow.
    static func createGetFlow(
        url: String = "https://example.com/api/test",
        statusCode: Int = 200,
        processName: String? = "TestApp"
    ) -> ProxyCapturedFlow {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: url,
            headers: [
                ["Host", URL(string: url)?.host ?? "example.com"],
                ["User-Agent", "TestClient/1.0"],
                ["Accept", "application/json"]
            ],
            bodySize: 0
        )

        let response = ProxyCapturedResponse(
            statusCode: statusCode,
            reason: reasonPhrase(for: statusCode),
            headers: [
                ["Content-Type", "application/json"],
                ["Content-Length", "50"]
            ],
            bodySize: 50,
            bodyPreview: "{\"success\": true}",
            duration: Double.random(in: 0.05...0.5)
        )

        return ProxyCapturedFlow(
            request: request,
            response: response,
            processName: processName,
            processId: processName != nil ? Int.random(in: 1000...99999) : nil
        )
    }

    /// Creates a POST request flow.
    static func createPostFlow(
        url: String = "https://api.example.com/users",
        statusCode: Int = 201,
        requestBody: String = "{\"name\": \"test\"}",
        responseBody: String = "{\"id\": 123}"
    ) -> ProxyCapturedFlow {
        let request = ProxyCapturedRequest(
            method: "POST",
            url: url,
            headers: [
                ["Host", URL(string: url)?.host ?? "api.example.com"],
                ["Content-Type", "application/json"],
                ["Content-Length", "\(requestBody.count)"]
            ],
            bodySize: requestBody.count,
            bodyPreview: requestBody
        )

        let response = ProxyCapturedResponse(
            statusCode: statusCode,
            reason: reasonPhrase(for: statusCode),
            headers: [
                ["Content-Type", "application/json"],
                ["Content-Length", "\(responseBody.count)"]
            ],
            bodySize: responseBody.count,
            bodyPreview: responseBody,
            duration: Double.random(in: 0.1...0.8)
        )

        return ProxyCapturedFlow(
            request: request,
            response: response,
            processName: "TestApp",
            processId: 12345
        )
    }

    /// Creates a pending flow (no response yet).
    static func createPendingFlow(
        method: String = "GET",
        url: String = "https://slow.example.com/api"
    ) -> ProxyCapturedFlow {
        let request = ProxyCapturedRequest(
            method: method,
            url: url,
            headers: [["Host", URL(string: url)?.host ?? "slow.example.com"]],
            bodySize: 0
        )

        return ProxyCapturedFlow(
            request: request,
            processName: "TestApp",
            processId: 12345
        )
    }

    /// Creates a failed flow.
    static func createErrorFlow(
        url: String = "https://fail.example.com/",
        errorMessage: String = "Connection refused"
    ) -> ProxyCapturedFlow {
        let request = ProxyCapturedRequest(
            method: "GET",
            url: url,
            headers: [["Host", URL(string: url)?.host ?? "fail.example.com"]],
            bodySize: 0
        )

        return ProxyCapturedFlow(
            request: request,
            error: errorMessage,
            processName: "TestApp",
            processId: 12345
        )
    }

    /// Creates a batch of test flows.
    static func createBatch(count: Int) -> [ProxyCapturedFlow] {
        var flows: [ProxyCapturedFlow] = []

        for i in 0..<count {
            let flow: ProxyCapturedFlow
            switch i % 5 {
            case 0:
                flow = createGetFlow(url: "https://example.com/api/\(i)")
            case 1:
                flow = createPostFlow(url: "https://api.example.com/users/\(i)")
            case 2:
                flow = createGetFlow(url: "https://cdn.example.com/asset\(i).js", statusCode: 304)
            case 3:
                flow = createGetFlow(url: "https://api.example.com/notfound/\(i)", statusCode: 404)
            default:
                flow = createPendingFlow(url: "https://slow.example.com/\(i)")
            }
            flows.append(flow)
        }

        return flows
    }

    private static func reasonPhrase(for statusCode: Int) -> String {
        switch statusCode {
        case 200: return "OK"
        case 201: return "Created"
        case 204: return "No Content"
        case 301: return "Moved Permanently"
        case 302: return "Found"
        case 304: return "Not Modified"
        case 400: return "Bad Request"
        case 401: return "Unauthorized"
        case 403: return "Forbidden"
        case 404: return "Not Found"
        case 500: return "Internal Server Error"
        case 502: return "Bad Gateway"
        case 503: return "Service Unavailable"
        default: return "Unknown"
        }
    }
}
