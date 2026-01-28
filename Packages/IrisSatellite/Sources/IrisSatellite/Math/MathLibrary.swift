import simd

// MARK: - Matrix Creation

extension matrix_float4x4 {
    /// Identity matrix
    public static var identity: matrix_float4x4 {
        matrix_float4x4(
            SIMD4<Float>(1, 0, 0, 0),
            SIMD4<Float>(0, 1, 0, 0),
            SIMD4<Float>(0, 0, 1, 0),
            SIMD4<Float>(0, 0, 0, 1)
        )
    }

    /// Translation matrix
    public init(translation: SIMD3<Float>) {
        self = matrix_float4x4(
            SIMD4<Float>(1, 0, 0, 0),
            SIMD4<Float>(0, 1, 0, 0),
            SIMD4<Float>(0, 0, 1, 0),
            SIMD4<Float>(translation.x, translation.y, translation.z, 1)
        )
    }

    /// Scale matrix
    public init(scale: SIMD3<Float>) {
        self = matrix_float4x4(
            SIMD4<Float>(scale.x, 0, 0, 0),
            SIMD4<Float>(0, scale.y, 0, 0),
            SIMD4<Float>(0, 0, scale.z, 0),
            SIMD4<Float>(0, 0, 0, 1)
        )
    }

    /// Rotation around X axis
    public init(rotationX angle: Float) {
        let c = cos(angle)
        let s = sin(angle)
        self = matrix_float4x4(
            SIMD4<Float>(1, 0, 0, 0),
            SIMD4<Float>(0, c, s, 0),
            SIMD4<Float>(0, -s, c, 0),
            SIMD4<Float>(0, 0, 0, 1)
        )
    }

    /// Rotation around Y axis
    public init(rotationY angle: Float) {
        let c = cos(angle)
        let s = sin(angle)
        self = matrix_float4x4(
            SIMD4<Float>(c, 0, -s, 0),
            SIMD4<Float>(0, 1, 0, 0),
            SIMD4<Float>(s, 0, c, 0),
            SIMD4<Float>(0, 0, 0, 1)
        )
    }

    /// Rotation around Z axis
    public init(rotationZ angle: Float) {
        let c = cos(angle)
        let s = sin(angle)
        self = matrix_float4x4(
            SIMD4<Float>(c, s, 0, 0),
            SIMD4<Float>(-s, c, 0, 0),
            SIMD4<Float>(0, 0, 1, 0),
            SIMD4<Float>(0, 0, 0, 1)
        )
    }

    /// Look-at matrix
    public init(eye: SIMD3<Float>, center: SIMD3<Float>, up: SIMD3<Float>) {
        let z = normalize(eye - center)
        let x = normalize(cross(up, z))
        let y = cross(z, x)

        self = matrix_float4x4(
            SIMD4<Float>(x.x, y.x, z.x, 0),
            SIMD4<Float>(x.y, y.y, z.y, 0),
            SIMD4<Float>(x.z, y.z, z.z, 0),
            SIMD4<Float>(-dot(x, eye), -dot(y, eye), -dot(z, eye), 1)
        )
    }

    /// Perspective projection matrix
    public init(fovRadians fov: Float, aspectRatio: Float, nearZ: Float, farZ: Float) {
        let y = 1 / tan(fov * 0.5)
        let x = y / aspectRatio
        let z = farZ / (nearZ - farZ)

        self = matrix_float4x4(
            SIMD4<Float>(x, 0, 0, 0),
            SIMD4<Float>(0, y, 0, 0),
            SIMD4<Float>(0, 0, z, -1),
            SIMD4<Float>(0, 0, z * nearZ, 0)
        )
    }

    /// Extract upper-left 3x3 matrix (for normals)
    public var upperLeft3x3: matrix_float3x3 {
        matrix_float3x3(
            SIMD3<Float>(columns.0.x, columns.0.y, columns.0.z),
            SIMD3<Float>(columns.1.x, columns.1.y, columns.1.z),
            SIMD3<Float>(columns.2.x, columns.2.y, columns.2.z)
        )
    }
}

// MARK: - Float Extensions

extension Float {
    /// Convert degrees to radians
    public var radians: Float {
        self * .pi / 180.0
    }

    /// Convert radians to degrees
    public var degrees: Float {
        self * 180.0 / .pi
    }

    /// Clamp value to range
    public func clamped(to range: ClosedRange<Float>) -> Float {
        min(max(self, range.lowerBound), range.upperBound)
    }
}

// MARK: - SIMD Extensions

extension SIMD3 where Scalar == Float {
    /// Spherical to Cartesian conversion
    /// - Parameters:
    ///   - r: radius
    ///   - theta: polar angle (from Y axis)
    ///   - phi: azimuthal angle (from Z axis in XZ plane)
    public static func spherical(r: Float, theta: Float, phi: Float) -> SIMD3<Float> {
        SIMD3<Float>(
            r * sin(theta) * sin(phi),
            r * cos(theta),
            r * sin(theta) * cos(phi)
        )
    }
}
