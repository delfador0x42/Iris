import Testing
@testable import IrisSatellite

@Suite("SatelliteGroup Tests")
struct SatelliteGroupTests {

    @Test("All groups have display names")
    func testDisplayNames() {
        for group in SatelliteGroup.allCases {
            #expect(!group.displayName.isEmpty)
        }
    }

    @Test("All groups have raw values")
    func testRawValues() {
        for group in SatelliteGroup.allCases {
            #expect(!group.rawValue.isEmpty)
        }
    }

    @Test("Expected number of groups")
    func testGroupCount() {
        #expect(SatelliteGroup.allCases.count == 9)
    }

    @Test("Active group is available")
    func testActiveGroup() {
        let active = SatelliteGroup.active
        #expect(active.rawValue == "active")
        #expect(active.displayName == "Active Satellites")
    }
}
