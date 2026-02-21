import Testing
@testable import IrisShared

@Suite("XPC Service Name Tests")
struct XPCServiceNameTests {

    // MARK: - Endpoint XPC Service

    @Test("Endpoint XPC service name has correct format")
    func testEndpointServiceName() {
        let serviceName = EndpointXPCService.extensionServiceName
        #expect(serviceName == "99HGW2AR62.com.wudan.iris.endpoint.xpc")
    }

    @Test("Endpoint XPC service name starts with team ID")
    func testEndpointServiceNameTeamIdPrefix() {
        let serviceName = EndpointXPCService.extensionServiceName
        #expect(serviceName.hasPrefix("99HGW2AR62."))
    }

    @Test("Endpoint app group identifier has correct format")
    func testEndpointAppGroupIdentifier() {
        let appGroup = EndpointXPCService.appGroupIdentifier
        #expect(appGroup == "group.com.wudan.iris")
        #expect(appGroup.hasPrefix("group."))
    }
}
