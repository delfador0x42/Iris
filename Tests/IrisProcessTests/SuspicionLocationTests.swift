import Testing
@testable import IrisProcess

@Suite("Suspicion Location and Process Detection Tests")
struct SuspicionLocationTests {

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
}
