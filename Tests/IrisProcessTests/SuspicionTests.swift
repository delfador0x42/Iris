import Testing
@testable import IrisProcess

@Suite("Suspicion Reason Severity Tests")
struct SuspicionReasonSeverityTests {

    // MARK: - Suspicion Reason Severity

    @Test("Unsigned has high severity")
    func testUnsignedSeverity() {
        #expect(SuspicionReason.unsigned.severity == .high)
    }

    @Test("Suspicious location has high severity")
    func testSuspiciousLocationSeverity() {
        #expect(SuspicionReason.suspiciousLocation.severity == .high)
    }

    @Test("Ad-hoc signed has medium severity")
    func testAdHocSeverity() {
        #expect(SuspicionReason.adHocSigned.severity == .medium)
    }

    @Test("Hidden process has medium severity")
    func testHiddenProcessSeverity() {
        #expect(SuspicionReason.hiddenProcess.severity == .medium)
    }

    @Test("Not Apple signed has low severity")
    func testNotAppleSignedSeverity() {
        #expect(SuspicionReason.notAppleSigned.severity == .low)
    }

    @Test("No man page has low severity")
    func testNoManPageSeverity() {
        #expect(SuspicionReason.noManPage.severity == .low)
    }

    // MARK: - Severity Comparison

    @Test("Severity levels compare correctly")
    func testSeverityComparison() {
        #expect(SuspicionSeverity.low < SuspicionSeverity.medium)
        #expect(SuspicionSeverity.medium < SuspicionSeverity.high)
        #expect(SuspicionSeverity.low < SuspicionSeverity.high)
    }

    @Test("Severity labels are correct")
    func testSeverityLabels() {
        #expect(SuspicionSeverity.low.label == "Low")
        #expect(SuspicionSeverity.medium.label == "Medium")
        #expect(SuspicionSeverity.high.label == "High")
    }
}

@Suite("Suspicion Signing Detection Tests")
struct SuspicionSigningDetectionTests {

    // MARK: - Process Suspicion Detection - Unsigned

    @Test("Process without code signing info is suspicious")
    func testNoCodeSigningIsSuspicious() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/local/bin/custom",
            name: "custom",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.isSuspicious)
        #expect(process.suspicionReasons.contains(.unsigned))
    }

    @Test("Unsigned binary is flagged")
    func testUnsignedBinaryFlagged() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: nil,
            flags: 0,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/local/bin/custom",
            name: "custom",
            userId: 501,
            groupId: 20,
            codeSigningInfo: csInfo
        )

        #expect(process.suspicionReasons.contains(.unsigned))
    }

    // MARK: - Process Suspicion Detection - Ad-hoc Signed

    @Test("Ad-hoc signed binary is flagged")
    func testAdHocSignedFlagged() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "adhoc-app",
            flags: 0,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/local/bin/custom",
            name: "custom",
            userId: 501,
            groupId: 20,
            codeSigningInfo: csInfo
        )

        #expect(process.suspicionReasons.contains(.adHocSigned))
    }

    // MARK: - Process Suspicion Detection - Apple Signed

    @Test("Apple signed binary is not flagged for signing issues")
    func testAppleSignedNotFlagged() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "com.apple.curl",
            flags: 1,
            isAppleSigned: true,
            isPlatformBinary: true
        )

        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/curl",
            name: "curl",
            userId: 501,
            groupId: 20,
            codeSigningInfo: csInfo
        )

        #expect(!process.suspicionReasons.contains(.unsigned))
        #expect(!process.suspicionReasons.contains(.adHocSigned))
        #expect(!process.suspicionReasons.contains(.notAppleSigned))
    }

    @Test("Developer ID signed binary flagged as not Apple signed")
    func testDevIDFlaggedAsNotAppleSigned() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: "ABC123",
            signingId: "com.example.app",
            flags: 1,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/Applications/Example.app/Contents/MacOS/Example",
            name: "Example",
            userId: 501,
            groupId: 20,
            codeSigningInfo: csInfo
        )

        #expect(process.suspicionReasons.contains(.notAppleSigned))
    }
}
