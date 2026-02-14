import Foundation

/// Satellite data from CelesTrak JSON format
public struct SatelliteData: Codable, Identifiable, Sendable, Equatable {
  public let objectName: String
  public let objectId: String
  public let noradCatId: Int
  public let epoch: String
  public let meanMotion: Double
  public let eccentricity: Double
  public let inclination: Double
  public let raOfAscNode: Double
  public let argOfPericenter: Double
  public let meanAnomaly: Double
  public let bstar: Double
  public let meanMotionDot: Double
  public let meanMotionDdot: Double

  public var id: Int { noradCatId }

  public init(
    objectName: String,
    objectId: String,
    noradCatId: Int,
    epoch: String,
    meanMotion: Double,
    eccentricity: Double,
    inclination: Double,
    raOfAscNode: Double,
    argOfPericenter: Double,
    meanAnomaly: Double,
    bstar: Double,
    meanMotionDot: Double,
    meanMotionDdot: Double
  ) {
    self.objectName = objectName
    self.objectId = objectId
    self.noradCatId = noradCatId
    self.epoch = epoch
    self.meanMotion = meanMotion
    self.eccentricity = eccentricity
    self.inclination = inclination
    self.raOfAscNode = raOfAscNode
    self.argOfPericenter = argOfPericenter
    self.meanAnomaly = meanAnomaly
    self.bstar = bstar
    self.meanMotionDot = meanMotionDot
    self.meanMotionDdot = meanMotionDdot
  }

  enum CodingKeys: String, CodingKey {
    case objectName = "OBJECT_NAME"
    case objectId = "OBJECT_ID"
    case noradCatId = "NORAD_CAT_ID"
    case epoch = "EPOCH"
    case meanMotion = "MEAN_MOTION"
    case eccentricity = "ECCENTRICITY"
    case inclination = "INCLINATION"
    case raOfAscNode = "RA_OF_ASC_NODE"
    case argOfPericenter = "ARG_OF_PERICENTER"
    case meanAnomaly = "MEAN_ANOMALY"
    case bstar = "BSTAR"
    case meanMotionDot = "MEAN_MOTION_DOT"
    case meanMotionDdot = "MEAN_MOTION_DDOT"
  }
}

/// Computed position in ECI coordinates (km)
public struct SatellitePosition: Sendable {
  public let satellite: SatelliteData
  public let position: SIMD3<Double>
  public let velocity: SIMD3<Double>
  public let classification: OrbitalClassification

  public init(
    satellite: SatelliteData,
    position: SIMD3<Double>,
    velocity: SIMD3<Double>,
    classification: OrbitalClassification
  ) {
    self.satellite = satellite
    self.position = position
    self.velocity = velocity
    self.classification = classification
  }
}

// MARK: - GPU Conversion

extension SatelliteData {
  // Swift 6: nonisolated(unsafe) for static formatter accessed from multiple contexts
  private nonisolated(unsafe) static let epochFormatter: ISO8601DateFormatter = {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return f
  }()

  /// Convert satellite data to GPU-compatible orbital elements
  public func toOrbitalElements(referenceEpoch: Date) -> OrbitalElements {
    let epochDate = Self.epochFormatter.date(from: epoch) ?? referenceEpoch
    let epochOffsetSeconds = Float(epochDate.timeIntervalSince(referenceEpoch))
    let classification = OrbitalClassification(inclination: inclination)

    // Compute semi-major axis from mean motion
    let mu: Double = 398600.4418  // Earth gravitational parameter km^3/s^2
    let n = meanMotion * 2.0 * .pi / 86400.0  // rad/s
    let a = pow(mu / (n * n), 1.0 / 3.0)

    return OrbitalElements(
      meanMotion: Float(meanMotion * 2.0 * .pi / 1440.0),  // rad/min
      eccentricity: Float(eccentricity),
      inclination: Float(inclination * .pi / 180.0),
      raOfAscNode: Float(raOfAscNode * .pi / 180.0),
      argOfPericenter: Float(argOfPericenter * .pi / 180.0),
      meanAnomaly: Float(meanAnomaly * .pi / 180.0),
      semiMajorAxis: Float(a),
      epochOffset: epochOffsetSeconds,
      classificationIndex: classification.gpuIndex
    )
  }
}
