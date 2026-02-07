import Testing
import Foundation
@testable import IrisNetwork

@Suite("SecurityRule Matching Tests")
struct SecurityRuleMatchingTests {

    // MARK: - Rule Matching

    @Test("Process rule matches connection with same path")
    func testProcessRuleMatches() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        let connection = createTestConnection(path: "/usr/bin/curl")
        #expect(rule.matches(connection: connection))
    }

    @Test("Process rule does not match different path")
    func testProcessRuleNoMatchDifferentPath() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        let connection = createTestConnection(path: "/usr/bin/wget")
        #expect(!rule.matches(connection: connection))
    }

    @Test("Disabled rule does not match")
    func testDisabledRuleNoMatch() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            isEnabled: false
        )

        let connection = createTestConnection(path: "/usr/bin/curl")
        #expect(!rule.matches(connection: connection))
    }

    @Test("Endpoint rule matches specific address")
    func testEndpointRuleMatchesAddress() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            remoteAddress: "93.184.216.34",
            action: .allow,
            scope: .endpoint
        )

        let connection = createTestConnection(path: "/usr/bin/curl")
        #expect(rule.matches(connection: connection))
    }

    @Test("Endpoint rule with wildcard address matches any")
    func testEndpointRuleWildcardAddress() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            remoteAddress: "*",
            action: .allow,
            scope: .endpoint
        )

        let connection = createTestConnection(path: "/usr/bin/curl")
        #expect(rule.matches(connection: connection))
    }

    // MARK: - Creation Helpers

    @Test("Allow process helper creates correct rule")
    func testAllowProcessHelper() {
        let rule = SecurityRule.allowProcess(path: "/usr/bin/curl")

        #expect(rule.processPath == "/usr/bin/curl")
        #expect(rule.action == .allow)
        #expect(rule.scope == .process)
    }

    @Test("Block process helper creates correct rule")
    func testBlockProcessHelper() {
        let rule = SecurityRule.blockProcess(path: "/usr/bin/curl")

        #expect(rule.processPath == "/usr/bin/curl")
        #expect(rule.action == .block)
        #expect(rule.scope == .process)
    }

    @Test("For endpoint helper creates correct rule")
    func testForEndpointHelper() {
        let rule = SecurityRule.forEndpoint(
            processPath: "/usr/bin/curl",
            remoteAddress: "example.com",
            remotePort: "443",
            action: .allow
        )

        #expect(rule.processPath == "/usr/bin/curl")
        #expect(rule.remoteAddress == "example.com")
        #expect(rule.remotePort == "443")
        #expect(rule.action == .allow)
        #expect(rule.scope == .endpoint)
    }

    @Test("Temporary helper creates rule with expiration")
    func testTemporaryHelper() {
        let rule = SecurityRule.temporary(
            processPath: "/usr/bin/curl",
            action: .allow,
            duration: 3600
        )

        #expect(rule.processPath == "/usr/bin/curl")
        #expect(rule.expiresAt != nil)
        #expect(!rule.isExpired)
    }

    // MARK: - Codable

    @Test("Rule encodes and decodes correctly")
    func testCodable() throws {
        let original = SecurityRule(
            processPath: "/usr/bin/curl",
            signingId: "com.apple.curl",
            remoteAddress: "example.com",
            action: .allow,
            scope: .endpoint
        )

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(original)
        let decoded = try decoder.decode(SecurityRule.self, from: data)

        #expect(decoded.id == original.id)
        #expect(decoded.processPath == original.processPath)
        #expect(decoded.signingId == original.signingId)
        #expect(decoded.action == original.action)
    }

    // MARK: - Helpers

    func createTestConnection(path: String) -> NetworkConnection {
        NetworkConnection(
            processId: 1234,
            processPath: path,
            processName: URL(fileURLWithPath: path).lastPathComponent,
            localAddress: "192.168.1.100",
            localPort: 54321,
            remoteAddress: "93.184.216.34",
            remotePort: 443,
            protocol: .tcp,
            state: .established
        )
    }
}
