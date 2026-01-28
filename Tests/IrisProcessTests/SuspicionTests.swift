import Testing
@testable import IrisProcess

@Suite("Suspicion Detection Tests")
struct SuspicionTests {

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

    // MARK: - Process Suspicion Detection - Suspicious Location

    @Test("Process in /tmp is suspicious")
    func testTmpLocationSuspicious() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/tmp/malware",
            name: "malware",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.suspicionReasons.contains(.suspiciousLocation))
    }

    @Test("Process in /var/tmp is suspicious")
    func testVarTmpLocationSuspicious() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/var/tmp/script",
            name: "script",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.suspicionReasons.contains(.suspiciousLocation))
    }

    @Test("Process in /Users/Shared is suspicious")
    func testUsersSharedSuspicious() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/Users/Shared/dropper",
            name: "dropper",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.suspicionReasons.contains(.suspiciousLocation))
    }

    @Test("Process in /usr/bin is not location-suspicious")
    func testUsrBinNotSuspiciousLocation() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "com.apple.ls",
            flags: 1,
            isAppleSigned: true,
            isPlatformBinary: true
        )

        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/ls",
            name: "ls",
            userId: 501,
            groupId: 20,
            codeSigningInfo: csInfo
        )

        #expect(!process.suspicionReasons.contains(.suspiciousLocation))
    }

    // MARK: - Process Suspicion Detection - Hidden Process

    @Test("Hidden process name is suspicious")
    func testHiddenProcessSuspicious() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/local/bin/.hidden",
            name: ".hidden",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.suspicionReasons.contains(.hiddenProcess))
    }

    @Test("Normal process name is not hidden-suspicious")
    func testNormalProcessNotHidden() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/curl",
            name: "curl",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(!process.suspicionReasons.contains(.hiddenProcess))
    }

    // MARK: - Process Suspicion Detection - Man Page

    @Test("Process without man page is flagged when checked")
    func testNoManPageFlagged() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/local/bin/custom",
            name: "custom",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil,
            hasManPage: false
        )

        #expect(process.suspicionReasons.contains(.noManPage))
    }

    @Test("Process with man page is not flagged")
    func testHasManPageNotFlagged() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/curl",
            name: "curl",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil,
            hasManPage: true
        )

        #expect(!process.suspicionReasons.contains(.noManPage))
    }

    @Test("Process with unchecked man page is not flagged")
    func testUncheckedManPageNotFlagged() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/curl",
            name: "curl",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil,
            hasManPage: nil
        )

        #expect(!process.suspicionReasons.contains(.noManPage))
    }

    // MARK: - Highest Severity

    @Test("Highest severity returns max severity")
    func testHighestSeverity() {
        // Process with both high (unsigned, location) and medium (hidden)
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/tmp/.hidden",
            name: ".hidden",
            userId: 501,
            groupId: 20,
            codeSigningInfo: nil
        )

        #expect(process.highestSeverity == .high)
    }

    @Test("Clean process has no highest severity")
    func testCleanProcessNoSeverity() {
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
            userId: 0,
            groupId: 0,
            codeSigningInfo: csInfo,
            hasManPage: true
        )

        #expect(process.highestSeverity == nil)
        #expect(!process.isSuspicious)
    }

    // MARK: - Code Signing Info Description

    @Test("Apple platform binary signer description")
    func testApplePlatformSignerDescription() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "com.apple.curl",
            flags: 1,
            isAppleSigned: true,
            isPlatformBinary: true
        )

        #expect(csInfo.signerDescription == "Apple (Platform)")
    }

    @Test("Apple non-platform signer description")
    func testAppleNonPlatformSignerDescription() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "com.apple.curl",
            flags: 0,
            isAppleSigned: true,
            isPlatformBinary: false
        )

        #expect(csInfo.signerDescription == "Apple")
    }

    @Test("Developer ID signer description includes team ID")
    func testDevIDSignerDescription() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: "ABC123",
            signingId: "com.example.app",
            flags: 1,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        #expect(csInfo.signerDescription == "Developer ID (ABC123)")
    }

    @Test("Ad-hoc signed signer description")
    func testAdHocSignerDescription() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: "adhoc-app",
            flags: 0,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        #expect(csInfo.signerDescription == "Ad-hoc signed")
    }

    @Test("Unsigned signer description")
    func testUnsignedSignerDescription() {
        let csInfo = IrisProcess.ProcessInfo.CodeSigningInfo(
            teamId: nil,
            signingId: nil,
            flags: 0,
            isAppleSigned: false,
            isPlatformBinary: false
        )

        #expect(csInfo.signerDescription == "Unsigned")
    }
}
