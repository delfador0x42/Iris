import Testing
@testable import IrisProcess

@Suite("Suspicion Highest Severity Tests")
struct SuspicionHighestSeverityTests {

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
}

@Suite("Code Signing Info Description Tests")
struct CodeSigningInfoDescriptionTests {

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
