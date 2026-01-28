import Testing
@testable import IrisSatellite

@Suite("SatelliteStore Tests")
struct SatelliteStoreTests {

    @Test("Initial state is idle")
    @MainActor
    func testInitialState() async {
        let mockDataSource = MockSatelliteDataSource()
        let store = SatelliteStore(dataSource: mockDataSource)

        #expect(store.satellites.isEmpty)
        #expect(store.loadingState == .idle)
        #expect(!store.isPaused)
    }

    @Test("Loading satellites updates state")
    @MainActor
    func testLoadSatellites() async {
        let mockDataSource = MockSatelliteDataSource()

        // Create mock satellite data
        await mockDataSource.setMockSatellites([
            createMockSatellite(name: "TEST-1", inclination: 45.0),
            createMockSatellite(name: "TEST-2", inclination: 90.0)
        ])

        let store = SatelliteStore(dataSource: mockDataSource)
        await store.loadSatellites()

        #expect(store.satellites.count == 2)
        if case .loaded(let count) = store.loadingState {
            #expect(count == 2)
        } else {
            Issue.record("Expected loaded state")
        }
        #expect(store.statistics.totalCount == 2)
    }

    @Test("Load failure sets error state")
    @MainActor
    func testLoadFailure() async {
        let mockDataSource = MockSatelliteDataSource()
        await mockDataSource.setShouldFail(true)

        let store = SatelliteStore(dataSource: mockDataSource)
        await store.loadSatellites()

        #expect(store.loadingState.errorMessage != nil)
    }

    @Test("Toggle pause works correctly")
    @MainActor
    func testTogglePause() async {
        let mockDataSource = MockSatelliteDataSource()
        let store = SatelliteStore(dataSource: mockDataSource)

        #expect(!store.isPaused)
        store.togglePause()
        #expect(store.isPaused)
        store.togglePause()
        #expect(!store.isPaused)
    }

    @Test("Set time scale works correctly")
    @MainActor
    func testSetTimeScale() async {
        let mockDataSource = MockSatelliteDataSource()
        let store = SatelliteStore(dataSource: mockDataSource)

        store.setTimeScale(10.0)
        #expect(store.timeScale == 10.0)

        store.setTimeScale(60.0)
        #expect(store.timeScale == 60.0)
    }

    @Test("Reset time sets to current date")
    @MainActor
    func testResetTime() async {
        let mockDataSource = MockSatelliteDataSource()
        let store = SatelliteStore(dataSource: mockDataSource)

        // Modify time
        store.stepTime(by: 3600) // +1 hour

        let beforeReset = store.simulationTime
        store.resetTime()
        let afterReset = store.simulationTime

        // After reset should be closer to now
        #expect(afterReset.timeIntervalSinceNow < beforeReset.timeIntervalSinceNow)
    }

    // MARK: - Helpers

    func createMockSatellite(name: String, inclination: Double) -> SatelliteData {
        SatelliteData(
            objectName: name,
            objectId: "00001",
            noradCatId: 1,
            epoch: "2024-01-01T00:00:00.000000",
            meanMotion: 15.0,
            eccentricity: 0.001,
            inclination: inclination,
            raOfAscNode: 0.0,
            argOfPericenter: 0.0,
            meanAnomaly: 0.0,
            bstar: 0.0,
            meanMotionDot: 0.0,
            meanMotionDdot: 0.0
        )
    }
}
