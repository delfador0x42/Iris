import Testing
@testable import IrisShared

@Suite("XPC Service Name Tests")
struct XPCServiceNameTests {

    // MARK: - Network XPC Service

    @Test("Network XPC service name has correct format")
    func testNetworkServiceName() {
        let serviceName = NetworkXPCService.extensionServiceName
        #expect(serviceName == "99HGW2AR62.com.wudan.iris.network.xpc")
    }

    @Test("Network XPC service name starts with team ID")
    func testNetworkServiceNameTeamIdPrefix() {
        let serviceName = NetworkXPCService.extensionServiceName
        #expect(serviceName.hasPrefix("99HGW2AR62."))
    }

    @Test("Network app group identifier has correct format")
    func testNetworkAppGroupIdentifier() {
        let appGroup = NetworkXPCService.appGroupIdentifier
        #expect(appGroup == "group.com.wudan.iris")
        #expect(appGroup.hasPrefix("group."))
    }

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

    // MARK: - Service Names are Distinct

    @Test("Network and endpoint service names are different")
    func testServiceNamesAreDistinct() {
        let networkService = NetworkXPCService.extensionServiceName
        let endpointService = EndpointXPCService.extensionServiceName
        #expect(networkService != endpointService)
    }

    @Test("Both services share the same app group")
    func testSharedAppGroup() {
        let networkAppGroup = NetworkXPCService.appGroupIdentifier
        let endpointAppGroup = EndpointXPCService.appGroupIdentifier
        #expect(networkAppGroup == endpointAppGroup)
    }
}
