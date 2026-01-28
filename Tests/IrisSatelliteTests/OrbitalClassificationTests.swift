import Testing
@testable import IrisSatellite

@Suite("OrbitalClassification Tests")
struct OrbitalClassificationTests {

    @Test("Equatorial classification for low inclination")
    func testEquatorialClassification() {
        #expect(OrbitalClassification(inclination: 0) == .equatorial)
        #expect(OrbitalClassification(inclination: 5) == .equatorial)
        #expect(OrbitalClassification(inclination: 9.9) == .equatorial)
    }

    @Test("Low inclination classification")
    func testLowClassification() {
        #expect(OrbitalClassification(inclination: 10) == .low)
        #expect(OrbitalClassification(inclination: 25) == .low)
        #expect(OrbitalClassification(inclination: 44.9) == .low)
    }

    @Test("Medium inclination classification")
    func testMediumClassification() {
        #expect(OrbitalClassification(inclination: 45) == .medium)
        #expect(OrbitalClassification(inclination: 55) == .medium)
        #expect(OrbitalClassification(inclination: 69.9) == .medium)
    }

    @Test("High inclination classification")
    func testHighClassification() {
        #expect(OrbitalClassification(inclination: 70) == .high)
        #expect(OrbitalClassification(inclination: 80) == .high)
        #expect(OrbitalClassification(inclination: 89.9) == .high)
    }

    @Test("Retrograde classification for inclination >= 90")
    func testRetrogradeClassification() {
        #expect(OrbitalClassification(inclination: 90) == .retrograde)
        #expect(OrbitalClassification(inclination: 100) == .retrograde)
        #expect(OrbitalClassification(inclination: 180) == .retrograde)
    }

    @Test("All cases are iterable")
    func testAllCases() {
        #expect(OrbitalClassification.allCases.count == 5)
    }

    @Test("Each classification has a unique color")
    func testUniqueColors() {
        let colors = OrbitalClassification.allCases.map { $0.color }
        let uniqueColors = Set(colors.map { "\($0.x),\($0.y),\($0.z)" })
        #expect(uniqueColors.count == OrbitalClassification.allCases.count)
    }
}
