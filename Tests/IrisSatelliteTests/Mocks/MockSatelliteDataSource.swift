import Foundation
@testable import IrisSatellite
import IrisShared

/// Mock implementation of SatelliteDataSourceProtocol for testing.
actor MockSatelliteDataSource: SatelliteDataSourceProtocol {
    var mockSatellites: [SatelliteData] = []
    var shouldFail: Bool = false
    var failureError: Error = IrisError.network(.noConnection)
    var fetchCallCount: Int = 0
    var lastRequestedGroup: SatelliteGroup?
    var lastForceRefresh: Bool?

    func fetchSatellites(group: SatelliteGroup, forceRefresh: Bool) async throws -> [SatelliteData] {
        fetchCallCount += 1
        lastRequestedGroup = group
        lastForceRefresh = forceRefresh

        if shouldFail {
            throw failureError
        }
        return mockSatellites
    }

    func clearCache() async {
        // No-op for mock
    }

    // MARK: - Test Helpers

    func reset() {
        mockSatellites = []
        shouldFail = false
        fetchCallCount = 0
        lastRequestedGroup = nil
        lastForceRefresh = nil
    }

    func setMockSatellites(_ satellites: [SatelliteData]) {
        mockSatellites = satellites
    }

    func setShouldFail(_ fail: Bool) {
        shouldFail = fail
    }
}
