import Testing
import Foundation
@testable import IrisProcess

@Suite("ProcessInfo Tests")
struct ProcessInfoTests {

    // MARK: - Model Creation

    @Test("Process initializes with all properties")
    func testProcessInitialization() {
        let process = createTestProcess()

        #expect(process.pid == 1234)
        #expect(process.ppid == 1)
        #expect(process.path == "/usr/bin/curl")
        #expect(process.name == "curl")
        #expect(process.userId == 501)
        #expect(process.groupId == 20)
    }

    // MARK: - Bundle Name Extraction

    @Test("Bundle name extracts from app path")
    func testBundleNameFromAppPath() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/Applications/Safari.app/Contents/MacOS/Safari",
            name: "Safari",
            userId: 501,
            groupId: 20
        )

        #expect(process.bundleName == "Safari.app")
    }

    @Test("Bundle name is nil for non-app path")
    func testBundleNameForNonApp() {
        let process = createTestProcess()
        #expect(process.bundleName == nil)
    }

    // MARK: - Display Name

    @Test("Display name uses bundle name when available")
    func testDisplayNameWithBundle() {
        let process = IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/Applications/Safari.app/Contents/MacOS/Safari",
            name: "Safari",
            userId: 501,
            groupId: 20
        )

        #expect(process.displayName == "Safari.app")
    }

    @Test("Display name falls back to process name")
    func testDisplayNameFallback() {
        let process = createTestProcess()
        #expect(process.displayName == "curl")
    }

    // MARK: - Codable

    @Test("Process encodes and decodes correctly")
    func testCodable() throws {
        let original = createTestProcess()
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let data = try encoder.encode(original)
        let decoded = try decoder.decode(IrisProcess.ProcessInfo.self, from: data)

        #expect(decoded.id == original.id)
        #expect(decoded.pid == original.pid)
        #expect(decoded.path == original.path)
        #expect(decoded.name == original.name)
    }

    // MARK: - Helpers

    func createTestProcess() -> IrisProcess.ProcessInfo {
        IrisProcess.ProcessInfo(
            pid: 1234,
            ppid: 1,
            path: "/usr/bin/curl",
            name: "curl",
            userId: 501,
            groupId: 20
        )
    }
}
