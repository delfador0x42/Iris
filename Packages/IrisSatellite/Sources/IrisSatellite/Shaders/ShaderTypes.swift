import simd

/// Uniforms passed to vertex shaders
public struct Uniforms: Sendable {
    public var modelMatrix: matrix_float4x4
    public var viewMatrix: matrix_float4x4
    public var projectionMatrix: matrix_float4x4
    public var normalMatrix: matrix_float3x3
    public var lightDirection: SIMD3<Float>
    public var cameraPosition: SIMD3<Float>
    public var time: Float
    public var padding: Float

    public init(
        modelMatrix: matrix_float4x4,
        viewMatrix: matrix_float4x4,
        projectionMatrix: matrix_float4x4,
        normalMatrix: matrix_float3x3,
        lightDirection: SIMD3<Float>,
        cameraPosition: SIMD3<Float>,
        time: Float,
        padding: Float = 0
    ) {
        self.modelMatrix = modelMatrix
        self.viewMatrix = viewMatrix
        self.projectionMatrix = projectionMatrix
        self.normalMatrix = normalMatrix
        self.lightDirection = lightDirection
        self.cameraPosition = cameraPosition
        self.time = time
        self.padding = padding
    }
}

/// Vertex data for Earth mesh
public struct EarthVertex: Sendable {
    public var position: SIMD3<Float>
    public var normal: SIMD3<Float>
    public var uv: SIMD2<Float>

    public init(position: SIMD3<Float>, normal: SIMD3<Float>, uv: SIMD2<Float>) {
        self.position = position
        self.normal = normal
        self.uv = uv
    }
}

/// Instance data for each satellite (optimized layout: 32 bytes instead of 48)
public struct SatelliteInstance: Sendable {
    public var position: SIMD3<Float>  // 12 bytes
    public var size: Float             // 4 bytes (fills to 16-byte alignment)
    public var color: SIMD4<Float>     // 16 bytes
    // Total: 32 bytes, no padding needed

    public init(position: SIMD3<Float>, size: Float, color: SIMD4<Float>) {
        self.position = position
        self.size = size
        self.color = color
    }
}

/// Orbital elements for GPU propagation (packed for Metal alignment)
public struct OrbitalElements: Sendable {
    public var meanMotion: Float      // rad/min
    public var eccentricity: Float
    public var inclination: Float     // radians
    public var raOfAscNode: Float     // radians (RAAN)
    public var argOfPericenter: Float // radians
    public var meanAnomaly: Float     // radians at epoch
    public var semiMajorAxis: Float   // km
    public var epochOffset: Float     // seconds from reference time
    public var classificationIndex: UInt32 // 0-4 for color lookup
    public var padding: SIMD3<Float>

    public init(
        meanMotion: Float,
        eccentricity: Float,
        inclination: Float,
        raOfAscNode: Float,
        argOfPericenter: Float,
        meanAnomaly: Float,
        semiMajorAxis: Float,
        epochOffset: Float,
        classificationIndex: UInt32,
        padding: SIMD3<Float> = .zero
    ) {
        self.meanMotion = meanMotion
        self.eccentricity = eccentricity
        self.inclination = inclination
        self.raOfAscNode = raOfAscNode
        self.argOfPericenter = argOfPericenter
        self.meanAnomaly = meanAnomaly
        self.semiMajorAxis = semiMajorAxis
        self.epochOffset = epochOffset
        self.classificationIndex = classificationIndex
        self.padding = padding
    }
}

/// Propagation uniforms (updated each frame)
public struct PropagationUniforms: Sendable {
    public var currentTime: Float     // seconds since reference epoch
    public var earthRadius: Float     // 6371.0 km
    public var padding: SIMD2<Float>

    public init(currentTime: Float, earthRadius: Float, padding: SIMD2<Float> = .zero) {
        self.currentTime = currentTime
        self.earthRadius = earthRadius
        self.padding = padding
    }
}

/// Buffer indices for shader bindings
public enum BufferIndex: Int, Sendable {
    case vertices = 0
    case uniforms = 1
    case instances = 2
    case orbitalElements = 3
    case propagationUniforms = 4
}

/// Texture indices for shader bindings
public enum TextureIndex: Int, Sendable {
    case earthDay = 0
    case earthNight = 1
    case earthSpecular = 2
}
