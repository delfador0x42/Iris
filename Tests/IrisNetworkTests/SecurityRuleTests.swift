import Testing
import Foundation
@testable import IrisNetwork

@Suite("SecurityRule Core Tests")
struct SecurityRuleCoreTests {

    // MARK: - Rule Creation

    @Test("Rule initializes with default values")
    func testDefaultInitialization() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        #expect(rule.processPath == "/usr/bin/curl")
        #expect(rule.action == .allow)
        #expect(rule.scope == .process)
        #expect(rule.isEnabled == true)
        #expect(rule.expiresAt == nil)
    }

    // MARK: - Rule Key

    @Test("Rule key uses signing ID when available")
    func testRuleKeyWithSigningId() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            signingId: "com.apple.curl",
            action: .allow,
            scope: .process
        )

        #expect(rule.key == "com.apple.curl")
    }

    @Test("Rule key falls back to path when no signing ID")
    func testRuleKeyWithoutSigningId() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        #expect(rule.key == "/usr/bin/curl")
    }

    @Test("Rule key returns unknown when nothing available")
    func testRuleKeyUnknown() {
        let rule = SecurityRule(
            action: .allow,
            scope: .process
        )

        #expect(rule.key == "unknown")
    }

    // MARK: - Expiration

    @Test("Rule without expiration is not expired")
    func testNonExpiringRuleNotExpired() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        #expect(!rule.isExpired)
    }

    @Test("Rule with future expiration is not expired")
    func testFutureExpirationNotExpired() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            expiresAt: Date().addingTimeInterval(3600)
        )

        #expect(!rule.isExpired)
    }

    @Test("Rule with past expiration is expired")
    func testPastExpirationIsExpired() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            expiresAt: Date().addingTimeInterval(-3600)
        )

        #expect(rule.isExpired)
    }

    // MARK: - Active State

    @Test("Enabled non-expired rule is active")
    func testEnabledNonExpiredIsActive() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            isEnabled: true
        )

        #expect(rule.isActive)
    }

    @Test("Disabled rule is not active")
    func testDisabledNotActive() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            isEnabled: false
        )

        #expect(!rule.isActive)
    }

    @Test("Expired rule is not active")
    func testExpiredNotActive() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process,
            isEnabled: true,
            expiresAt: Date().addingTimeInterval(-3600)
        )

        #expect(!rule.isActive)
    }

    // MARK: - Rule Description

    @Test("Allow process rule description")
    func testAllowProcessDescription() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .allow,
            scope: .process
        )

        #expect(rule.ruleDescription == "Allow from curl")
    }

    @Test("Block process rule description")
    func testBlockProcessDescription() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            action: .block,
            scope: .process
        )

        #expect(rule.ruleDescription == "Block from curl")
    }

    @Test("Endpoint rule description includes address and port")
    func testEndpointDescription() {
        let rule = SecurityRule(
            processPath: "/usr/bin/curl",
            remoteAddress: "example.com",
            remotePort: "443",
            action: .allow,
            scope: .endpoint
        )

        #expect(rule.ruleDescription == "Allow from curl to example.com:443")
    }

    // MARK: - Action Display Names

    @Test("Allow action display name")
    func testAllowDisplayName() {
        #expect(SecurityRule.RuleAction.allow.displayName == "Allow")
    }

    @Test("Block action display name")
    func testBlockDisplayName() {
        #expect(SecurityRule.RuleAction.block.displayName == "Block")
    }

    // MARK: - Scope Display Names

    @Test("Process scope display name")
    func testProcessScopeDisplayName() {
        #expect(SecurityRule.RuleScope.process.displayName == "All Connections")
    }

    @Test("Endpoint scope display name")
    func testEndpointScopeDisplayName() {
        #expect(SecurityRule.RuleScope.endpoint.displayName == "Specific Endpoint")
    }
}
