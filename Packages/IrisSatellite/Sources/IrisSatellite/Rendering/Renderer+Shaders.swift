import Metal

// MARK: - Embedded Shader Source

@MainActor
extension Renderer {

    static let metalShaderSource = """
    #include <metal_stdlib>
    using namespace metal;

    struct Uniforms {
        float4x4 modelMatrix;
        float4x4 viewMatrix;
        float4x4 projectionMatrix;
        float3x3 normalMatrix;
        float3 lightDirection;
        float3 cameraPosition;
        float time;
        float padding;
    };

    struct EarthVertex {
        float3 position;
        float3 normal;
        float2 uv;
    };

    struct SatelliteInstance {
        float3 position;  // 12 bytes
        float size;       // 4 bytes (fills to 16)
        float4 color;     // 16 bytes
        // Total: 32 bytes (optimized from 48)
    };

    struct EarthVertexOut {
        float4 position [[position]];
        float3 worldPosition;
        float3 worldNormal;
        float2 uv;
    };

    vertex EarthVertexOut earth_vertex(
        uint vertexID [[vertex_id]],
        constant EarthVertex* vertices [[buffer(0)]],
        constant Uniforms& uniforms [[buffer(1)]]
    ) {
        EarthVertex v = vertices[vertexID];
        float4 worldPos = uniforms.modelMatrix * float4(v.position, 1.0);

        EarthVertexOut out;
        out.position = uniforms.projectionMatrix * uniforms.viewMatrix * worldPos;
        out.worldPosition = worldPos.xyz;
        out.worldNormal = uniforms.normalMatrix * v.normal;
        out.uv = v.uv;
        return out;
    }

    fragment float4 earth_fragment(
        EarthVertexOut in [[stage_in]],
        constant Uniforms& uniforms [[buffer(1)]]
    ) {
        float3 normal = normalize(in.worldNormal);
        float3 viewDir = normalize(uniforms.cameraPosition - in.worldPosition);

        // Dark base color
        float3 baseColor = float3(0.01, 0.01, 0.02);

        // Fresnel effect - bright edges, dark center
        float fresnel = 1.0 - max(dot(viewDir, normal), 0.0);

        // Optimized fresnel layers using integer powers (faster than pow())
        float fresnel2 = fresnel * fresnel;           // fresnel^2
        float fresnel3 = fresnel2 * fresnel;          // fresnel^3
        float fresnel5 = fresnel3 * fresnel2;         // fresnel^5
        float innerGlow = fresnel * sqrt(fresnel) * 0.15;  // ~fresnel^1.5
        float midGlow = fresnel3 * 0.4;               // fresnel^3
        float outerGlow = fresnel5 * 0.8;             // fresnel^5

        // Glow color (cyan/blue gradient)
        float3 glowColor = mix(
            float3(0.1, 0.3, 0.6),   // Inner: deeper blue
            float3(0.3, 0.7, 1.0),   // Outer: bright cyan
            fresnel
        );

        // Subtle light-side shading
        float3 lightDir = normalize(uniforms.lightDirection);
        float diffuse = max(dot(normal, lightDir), 0.0) * 0.08;

        // Combine layers
        float3 finalColor = baseColor + baseColor * diffuse;
        finalColor += glowColor * (innerGlow + midGlow + outerGlow);

        return float4(finalColor, 1.0);
    }

    struct SatelliteVertexOut {
        float4 position [[position]];
        float4 color;
        float pointSize [[point_size]];
    };

    vertex SatelliteVertexOut satellite_vertex(
        uint instanceID [[instance_id]],
        constant SatelliteInstance* instances [[buffer(2)]],
        constant Uniforms& uniforms [[buffer(1)]]
    ) {
        SatelliteInstance sat = instances[instanceID];
        float3 scaledPos = sat.position / 6371.0;

        float4 worldPos = float4(scaledPos, 1.0);
        float4 viewPos = uniforms.viewMatrix * worldPos;

        SatelliteVertexOut out;
        out.position = uniforms.projectionMatrix * viewPos;
        out.color = sat.color;

        float dist = length(viewPos.xyz);
        out.pointSize = sat.size * (10.0 / max(dist, 1.0));
        out.pointSize = clamp(out.pointSize, 1.0, 20.0);

        return out;
    }

    fragment float4 satellite_fragment(
        SatelliteVertexOut in [[stage_in]],
        float2 pointCoord [[point_coord]]
    ) {
        float dist = length(pointCoord - 0.5) * 2.0;
        if (dist > 1.0) { discard_fragment(); }
        float alpha = 1.0 - smoothstep(0.6, 1.0, dist);
        return float4(in.color.rgb, in.color.a * alpha);
    }

    // MARK: - Compute Shaders

    // Classification colors (must match OrbitalClassification.gpuIndex order)
    constant float4 classificationColors[5] = {
        float4(1.0, 0.2, 0.2, 1.0),   // equatorial - Red
        float4(1.0, 0.6, 0.2, 1.0),   // low - Orange
        float4(1.0, 1.0, 0.2, 1.0),   // medium - Yellow
        float4(0.2, 1.0, 0.5, 1.0),   // high - Green
        float4(0.4, 0.6, 1.0, 1.0)    // retrograde - Blue
    };

    struct OrbitalElements {
        float meanMotion;       // rad/min
        float eccentricity;
        float inclination;      // radians
        float raOfAscNode;      // radians
        float argOfPericenter;  // radians
        float meanAnomaly;      // radians at epoch
        float semiMajorAxis;    // km
        float epochOffset;      // seconds from reference
        uint classificationIndex;
        float3 padding;
    };

    struct PropagationUniforms {
        float currentTime;      // seconds since reference epoch
        float earthRadius;
        float2 padding;
    };

    // Metal 4: Optimized Kepler equation solver using fast math
    float solveKepler(float M, float e, int iterations) {
        float E = M;
        for (int i = 0; i < iterations; i++) {
            // Use fast math approximations for visualization (acceptable precision)
            float sinE = metal::fast::sin(E);
            float cosE = metal::fast::cos(E);
            // Fused multiply-add for efficiency
            float denominator = fma(-e, cosE, 1.0f);  // 1.0 - e * cosE
            float numerator = fma(-e, sinE, E) - M;    // E - e * sinE - M
            E -= numerator / denominator;
        }
        return E;
    }

    kernel void propagate_satellites(
        constant OrbitalElements* elements [[buffer(0)]],
        device SatelliteInstance* instances [[buffer(1)]],
        constant PropagationUniforms& uniforms [[buffer(2)]],
        uint id [[thread_position_in_grid]]
    ) {
        OrbitalElements elem = elements[id];

        // Time since this satellite's epoch (minutes)
        float timeSinceEpoch = (uniforms.currentTime - elem.epochOffset) / 60.0;

        // Current mean anomaly
        float M = elem.meanAnomaly + elem.meanMotion * timeSinceEpoch;

        // Metal 4: Adaptive iteration count based on eccentricity
        // Low eccentricity orbits converge faster
        int iterations = (elem.eccentricity < 0.1f) ? 5 :
                         (elem.eccentricity < 0.5f) ? 8 : 10;

        // Solve Kepler's equation
        float E = solveKepler(M, elem.eccentricity, iterations);

        // True anomaly using half-angle formula
        float sinHalfE = sin(E * 0.5);
        float cosHalfE = cos(E * 0.5);
        float sqrtPlusE = sqrt(1.0 + elem.eccentricity);
        float sqrtMinusE = sqrt(1.0 - elem.eccentricity);
        float nu = 2.0 * atan2(sqrtPlusE * sinHalfE, sqrtMinusE * cosHalfE);

        // Distance from Earth center
        float r = elem.semiMajorAxis * (1.0 - elem.eccentricity * cos(E));

        // Position in orbital plane
        float cosNu = cos(nu);
        float sinNu = sin(nu);
        float xOrbit = r * cosNu;
        float yOrbit = r * sinNu;

        // Precompute rotation sines/cosines
        float cosRAAN = cos(elem.raOfAscNode);
        float sinRAAN = sin(elem.raOfAscNode);
        float cosI = cos(elem.inclination);
        float sinI = sin(elem.inclination);
        float cosOmega = cos(elem.argOfPericenter);
        float sinOmega = sin(elem.argOfPericenter);

        // Transform to ECI coordinates
        float3 position;
        position.x = xOrbit * (cosRAAN * cosOmega - sinRAAN * sinOmega * cosI) -
                     yOrbit * (cosRAAN * sinOmega + sinRAAN * cosOmega * cosI);
        position.y = xOrbit * (sinRAAN * cosOmega + cosRAAN * sinOmega * cosI) -
                     yOrbit * (sinRAAN * sinOmega - cosRAAN * cosOmega * cosI);
        position.z = xOrbit * (sinOmega * sinI) + yOrbit * (cosOmega * sinI);

        // Write instance data (optimized struct layout)
        instances[id].position = position;
        instances[id].size = 4.0;
        instances[id].color = classificationColors[elem.classificationIndex];
    }
    """
}
