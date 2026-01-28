import Testing
@testable import IrisShared

@Suite("ExtensionType Tests")
struct ExtensionTypeTests {

    @Test("Network extension has correct bundle identifier")
    func testNetworkBundleIdentifier() {
        let type = ExtensionType.network
        #expect(type.bundleIdentifier == "com.wudan.iris.NetworkExtension")
    }

    @Test("Endpoint extension has correct bundle identifier")
    func testEndpointBundleIdentifier() {
        let type = ExtensionType.endpoint
        #expect(type.bundleIdentifier == "com.wudan.iris.EndpointExtension")
    }

    @Test("Network extension has correct display name")
    func testNetworkDisplayName() {
        let type = ExtensionType.network
        #expect(type.displayName == "Network Filter")
    }

    @Test("Endpoint extension has correct display name")
    func testEndpointDisplayName() {
        let type = ExtensionType.endpoint
        #expect(type.displayName == "Process Monitor")
    }

    @Test("All cases are iterable")
    func testCaseIterable() {
        let allCases = ExtensionType.allCases
        #expect(allCases.count == 2)
        #expect(allCases.contains(.network))
        #expect(allCases.contains(.endpoint))
    }
}
