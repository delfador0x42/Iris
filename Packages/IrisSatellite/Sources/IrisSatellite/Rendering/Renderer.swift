import MetalKit
import simd
import Combine
import os.log

/// Main Metal renderer for satellite visualization.
/// Conforms to SatelliteRendererProtocol for dependency injection.
@MainActor
public class Renderer: NSObject, ObservableObject, MTKViewDelegate, SatelliteRendererProtocol {
    // Configuration
    private let configuration: RenderingConfiguration
    private let logger = Logger(subsystem: "com.wudan.iris", category: "Renderer")

    // Metal objects
    private var device: MTLDevice!
    private var commandQueue: MTLCommandQueue!
    private var earthPipelineState: MTLRenderPipelineState!
    private var satellitePipelineState: MTLRenderPipelineState!
    private var depthStencilState: MTLDepthStencilState!

    // Buffers
    private var earthVertexBuffer: MTLBuffer!
    private var earthIndexBuffer: MTLBuffer!
    private var uniformBuffer: MTLBuffer!

    // Textures (Earth uses wireframe grid shader, no texture needed)

    // Geometry
    private var earthIndexCount: Int = 0
    private var satelliteCount: Int = 0

    // Compute pipeline for GPU propagation
    private var propagationPipelineState: MTLComputePipelineState!
    private var orbitalElementsBuffer: MTLBuffer?
    private var propagationUniformsBuffer: MTLBuffer!

    // Metal 4: Separate compute queue for async work
    private var computeQueue: MTLCommandQueue!

    // Metal 4: GPU timeline for compute/render synchronization
    private var computeTimeline: MTLSharedEvent!
    private var timelineValue: UInt64 = 0

    // Metal 4: Residency set for explicit GPU memory management
    private var residencySet: MTLResidencySet?

    // Metal 4: Triple-buffered satellite output for async compute
    private var satelliteBuffers: [MTLBuffer] = []
    private var currentBufferIndex = 0
    private var frameSemaphore: DispatchSemaphore!

    // GPU propagation state
    private var referenceEpoch: Date = Date()
    public var currentSimulationTime: Date = Date()

    // Camera
    public var camera: Camera = Camera()

    // Time
    private var startTime: Date = Date()

    // Light direction (sun position)
    private var lightDirection: SIMD3<Float> = normalize(SIMD3<Float>(1, 0.5, 1))

    // Cached aspect ratio (updated on resize, avoids division every frame)
    private var cachedAspectRatio: Float = 1.0

    public init(configuration: RenderingConfiguration = .default) {
        self.configuration = configuration
        super.init()
    }

    public func setup(device: MTLDevice, view: MTKView) throws {
        self.device = device

        // Metal 4: Enable concurrent shader compilation for faster startup
        device.shouldMaximizeConcurrentCompilation = true

        guard let commandQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.commandQueue = commandQueue

        // Metal 4: Create separate compute queue for async work
        guard let computeQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.computeQueue = computeQueue

        // Metal 4: Create GPU timeline for synchronization
        guard let computeTimeline = device.makeSharedEvent() else {
            throw IrisError.rendering(.bufferCreationFailed("shared event"))
        }
        self.computeTimeline = computeTimeline

        // Metal 4: Create frame semaphore for triple buffering
        self.frameSemaphore = DispatchSemaphore(value: configuration.maxFramesInFlight)

        try createPipelineStates(view: view)
        try createComputePipelineStates()
        createDepthStencilState()
        createEarthGeometry()
        createUniformBuffer()
        createPropagationUniformsBuffer()

        // Metal 4: Create residency set for static buffers
        createResidencySet()
    }

    private func createPipelineStates(view: MTKView) throws {
        // Try to load default library first (works in Xcode), fall back to source compilation for SPM
        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            // For SPM: compile shaders from source at runtime
            let shaderSource = Self.metalShaderSource
            do {
                library = try device.makeLibrary(source: shaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed(error.localizedDescription))
            }
        }

        // Earth pipeline
        let earthDescriptor = MTLRenderPipelineDescriptor()
        earthDescriptor.vertexFunction = library.makeFunction(name: "earth_vertex")
        earthDescriptor.fragmentFunction = library.makeFunction(name: "earth_fragment")
        earthDescriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        earthDescriptor.depthAttachmentPixelFormat = view.depthStencilPixelFormat

        do {
            earthPipelineState = try device.makeRenderPipelineState(descriptor: earthDescriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Earth: \(error.localizedDescription)"))
        }

        // Satellite pipeline
        let satelliteDescriptor = MTLRenderPipelineDescriptor()
        satelliteDescriptor.vertexFunction = library.makeFunction(name: "satellite_vertex")
        satelliteDescriptor.fragmentFunction = library.makeFunction(name: "satellite_fragment")
        satelliteDescriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat
        satelliteDescriptor.colorAttachments[0].isBlendingEnabled = true
        satelliteDescriptor.colorAttachments[0].rgbBlendOperation = .add
        satelliteDescriptor.colorAttachments[0].alphaBlendOperation = .add
        satelliteDescriptor.colorAttachments[0].sourceRGBBlendFactor = .sourceAlpha
        satelliteDescriptor.colorAttachments[0].destinationRGBBlendFactor = .oneMinusSourceAlpha
        satelliteDescriptor.colorAttachments[0].sourceAlphaBlendFactor = .one
        satelliteDescriptor.colorAttachments[0].destinationAlphaBlendFactor = .oneMinusSourceAlpha
        satelliteDescriptor.depthAttachmentPixelFormat = view.depthStencilPixelFormat

        do {
            satellitePipelineState = try device.makeRenderPipelineState(descriptor: satelliteDescriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Satellite: \(error.localizedDescription)"))
        }
    }

    private func createDepthStencilState() {
        let descriptor = MTLDepthStencilDescriptor()
        descriptor.depthCompareFunction = .less
        descriptor.isDepthWriteEnabled = true
        depthStencilState = device.makeDepthStencilState(descriptor: descriptor)
    }

    private func createEarthGeometry() {
        let (vertices, indices) = generateUVSphere(
            radius: 1.0,
            latSegments: configuration.earthLatSegments,
            lonSegments: configuration.earthLonSegments
        )

        let vertexSize = vertices.count * MemoryLayout<EarthVertex>.stride
        let indexSize = indices.count * MemoryLayout<UInt32>.stride

        // Use private storage for static earth geometry (GPU-only, better cache efficiency)
        let vertexStaging = device.makeBuffer(bytes: vertices, length: vertexSize, options: .storageModeShared)!
        let indexStaging = device.makeBuffer(bytes: indices, length: indexSize, options: .storageModeShared)!

        earthVertexBuffer = device.makeBuffer(length: vertexSize, options: .storageModePrivate)
        earthIndexBuffer = device.makeBuffer(length: indexSize, options: .storageModePrivate)

        // Blit copy from staging to private buffers
        if let blitBuffer = commandQueue.makeCommandBuffer(),
           let blitEncoder = blitBuffer.makeBlitCommandEncoder() {
            blitEncoder.copy(from: vertexStaging, sourceOffset: 0, to: earthVertexBuffer, destinationOffset: 0, size: vertexSize)
            blitEncoder.copy(from: indexStaging, sourceOffset: 0, to: earthIndexBuffer, destinationOffset: 0, size: indexSize)
            blitEncoder.endEncoding()
            blitBuffer.commit()
            blitBuffer.waitUntilCompleted()  // OK to block during setup
        }

        earthIndexCount = indices.count
    }

    private func generateUVSphere(radius: Float, latSegments: Int, lonSegments: Int) -> ([EarthVertex], [UInt32]) {
        var vertices: [EarthVertex] = []
        var indices: [UInt32] = []

        for lat in 0...latSegments {
            let theta = Float(lat) * .pi / Float(latSegments)
            let sinTheta = sin(theta)
            let cosTheta = cos(theta)

            for lon in 0...lonSegments {
                let phi = Float(lon) * 2.0 * .pi / Float(lonSegments)
                let sinPhi = sin(phi)
                let cosPhi = cos(phi)

                let x = sinTheta * sinPhi
                let y = cosTheta
                let z = sinTheta * cosPhi

                let position = SIMD3<Float>(x, y, z) * radius
                let normal = SIMD3<Float>(x, y, z)
                let u = Float(lon) / Float(lonSegments)
                let v = Float(lat) / Float(latSegments)

                vertices.append(EarthVertex(position: position, normal: normal, uv: SIMD2<Float>(u, v)))
            }
        }

        for lat in 0..<latSegments {
            for lon in 0..<lonSegments {
                let first = UInt32(lat * (lonSegments + 1) + lon)
                let second = first + UInt32(lonSegments + 1)

                indices.append(first)
                indices.append(second)
                indices.append(first + 1)

                indices.append(second)
                indices.append(second + 1)
                indices.append(first + 1)
            }
        }

        return (vertices, indices)
    }

    private func createUniformBuffer() {
        uniformBuffer = device.makeBuffer(
            length: MemoryLayout<Uniforms>.stride,
            options: .storageModeShared
        )
    }

    private func createComputePipelineStates() throws {
        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            do {
                library = try device.makeLibrary(source: Self.metalShaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed("Compute: \(error.localizedDescription)"))
            }
        }

        // Propagation compute pipeline
        guard let propagationFunction = library.makeFunction(name: "propagate_satellites") else {
            throw IrisError.rendering(.shaderCompilationFailed("propagate_satellites function not found"))
        }

        do {
            propagationPipelineState = try device.makeComputePipelineState(function: propagationFunction)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Propagation: \(error.localizedDescription)"))
        }
    }

    private func createPropagationUniformsBuffer() {
        propagationUniformsBuffer = device.makeBuffer(
            length: MemoryLayout<PropagationUniforms>.stride,
            options: .storageModeShared
        )
    }

    // Metal 4: Create residency set for explicit GPU memory management
    private func createResidencySet() {
        let descriptor = MTLResidencySetDescriptor()
        descriptor.label = "Iris Buffers"

        do {
            residencySet = try device.makeResidencySet(descriptor: descriptor)

            // Add static buffers to residency set
            residencySet?.addAllocation(earthVertexBuffer)
            residencySet?.addAllocation(earthIndexBuffer)
            residencySet?.addAllocation(uniformBuffer)
            residencySet?.addAllocation(propagationUniformsBuffer)

            // Commit to make buffers resident on GPU
            residencySet?.commit()
        } catch {
            logger.warning("Could not create residency set: \(error.localizedDescription)")
        }
    }

    /// Upload orbital elements to GPU (call once when satellites load)
    public func uploadOrbitalElements(_ satellites: [SatelliteData]) {
        guard !satellites.isEmpty else {
            satelliteCount = 0
            orbitalElementsBuffer = nil
            satelliteBuffers = []
            return
        }

        referenceEpoch = Date()
        satelliteCount = satellites.count

        let elements = satellites.map { $0.toOrbitalElements(referenceEpoch: referenceEpoch) }
        let bufferSize = elements.count * MemoryLayout<OrbitalElements>.stride

        // Metal 4: Use private storage with blit upload for orbital elements
        let stagingBuffer = device.makeBuffer(
            bytes: elements,
            length: bufferSize,
            options: .storageModeShared
        )!

        orbitalElementsBuffer = device.makeBuffer(
            length: bufferSize,
            options: .storageModePrivate
        )

        // Blit copy from staging to private buffer
        if let blitBuffer = commandQueue.makeCommandBuffer(),
           let blitEncoder = blitBuffer.makeBlitCommandEncoder() {
            blitEncoder.copy(
                from: stagingBuffer,
                sourceOffset: 0,
                to: orbitalElementsBuffer!,
                destinationOffset: 0,
                size: bufferSize
            )
            blitEncoder.endEncoding()
            blitBuffer.commit()
            blitBuffer.waitUntilCompleted()
        }

        // Metal 4: Allocate triple-buffered satellite instance buffers with private storage
        let instanceSize = satellites.count * MemoryLayout<SatelliteInstance>.stride
        satelliteBuffers = (0..<configuration.maxFramesInFlight).map { _ in
            device.makeBuffer(length: instanceSize, options: .storageModePrivate)!
        }

        // Reset buffer index
        currentBufferIndex = 0

        // Add new buffers to residency set
        if let residencySet = residencySet {
            residencySet.addAllocation(orbitalElementsBuffer!)
            for buffer in satelliteBuffers {
                residencySet.addAllocation(buffer)
            }
            residencySet.commit()
        }
    }

    // MARK: - MTKViewDelegate

    public func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        // Cache aspect ratio on resize (avoids division every frame)
        if size.height > 0 {
            cachedAspectRatio = Float(size.width / size.height)
        }
    }

    public func draw(in view: MTKView) {
        // Metal 4: Wait for a buffer slot (triple buffering)
        frameSemaphore.wait()

        guard let drawable = view.currentDrawable,
              let renderPassDescriptor = view.currentRenderPassDescriptor else {
            frameSemaphore.signal()
            return
        }

        // Get current buffer index for this frame
        let bufferIndex = currentBufferIndex
        currentBufferIndex = (currentBufferIndex + 1) % configuration.maxFramesInFlight

        // === COMPUTE PASS: Propagate satellites on GPU (async on compute queue) ===
        if satelliteCount > 0,
           let orbitalBuffer = orbitalElementsBuffer,
           !satelliteBuffers.isEmpty,
           let computeCommandBuffer = computeQueue.makeCommandBuffer(),
           let computeEncoder = computeCommandBuffer.makeComputeCommandEncoder() {

            // Update propagation uniforms with current simulation time
            var propUniforms = PropagationUniforms(
                currentTime: Float(currentSimulationTime.timeIntervalSince(referenceEpoch)),
                earthRadius: configuration.earthRadius
            )
            memcpy(propagationUniformsBuffer.contents(), &propUniforms, MemoryLayout<PropagationUniforms>.stride)

            computeEncoder.setComputePipelineState(propagationPipelineState)
            computeEncoder.setBuffer(orbitalBuffer, offset: 0, index: 0)
            computeEncoder.setBuffer(satelliteBuffers[bufferIndex], offset: 0, index: 1)
            computeEncoder.setBuffer(propagationUniformsBuffer, offset: 0, index: 2)

            let threadGroupSize = min(propagationPipelineState.maxTotalThreadsPerThreadgroup, 256)
            let threadGroups = (satelliteCount + threadGroupSize - 1) / threadGroupSize

            computeEncoder.dispatchThreadgroups(
                MTLSize(width: threadGroups, height: 1, depth: 1),
                threadsPerThreadgroup: MTLSize(width: threadGroupSize, height: 1, depth: 1)
            )
            computeEncoder.endEncoding()

            // Metal 4: Signal timeline when compute completes
            timelineValue += 1
            computeCommandBuffer.encodeSignalEvent(computeTimeline, value: timelineValue)
            computeCommandBuffer.commit()
        }

        // === RENDER PASS: Draw Earth and satellites ===
        guard let renderCommandBuffer = commandQueue.makeCommandBuffer() else {
            frameSemaphore.signal()
            return
        }

        // Metal 4: Wait for compute to complete before rendering
        if satelliteCount > 0 && !satelliteBuffers.isEmpty {
            renderCommandBuffer.encodeWaitForEvent(computeTimeline, value: timelineValue)
        }

        guard let renderEncoder = renderCommandBuffer.makeRenderCommandEncoder(descriptor: renderPassDescriptor) else {
            frameSemaphore.signal()
            return
        }

        // Update render uniforms (use cached aspectRatio)
        let time = Float(Date().timeIntervalSince(startTime))

        var uniforms = Uniforms(
            modelMatrix: matrix_float4x4.identity,
            viewMatrix: camera.viewMatrix,
            projectionMatrix: camera.projectionMatrix(aspectRatio: cachedAspectRatio),
            normalMatrix: matrix_float4x4.identity.upperLeft3x3,
            lightDirection: lightDirection,
            cameraPosition: camera.position,
            time: time
        )

        memcpy(uniformBuffer.contents(), &uniforms, MemoryLayout<Uniforms>.stride)

        renderEncoder.setDepthStencilState(depthStencilState)

        // Draw Earth (wireframe grid - no texture needed)
        renderEncoder.setRenderPipelineState(earthPipelineState)
        renderEncoder.setVertexBuffer(earthVertexBuffer, offset: 0, index: 0)
        renderEncoder.setVertexBuffer(uniformBuffer, offset: 0, index: 1)
        renderEncoder.setFragmentBuffer(uniformBuffer, offset: 0, index: 1)
        renderEncoder.drawIndexedPrimitives(
            type: .triangle,
            indexCount: earthIndexCount,
            indexType: .uint32,
            indexBuffer: earthIndexBuffer,
            indexBufferOffset: 0
        )

        // Draw Satellites (using GPU-computed positions from current buffer)
        if satelliteCount > 0 && !satelliteBuffers.isEmpty {
            renderEncoder.setRenderPipelineState(satellitePipelineState)
            renderEncoder.setVertexBuffer(uniformBuffer, offset: 0, index: 1)
            renderEncoder.setVertexBuffer(satelliteBuffers[bufferIndex], offset: 0, index: 2)
            renderEncoder.drawPrimitives(
                type: .point,
                vertexStart: 0,
                vertexCount: 1,
                instanceCount: satelliteCount
            )
        }

        renderEncoder.endEncoding()

        // Metal 4: Signal semaphore when frame completes
        // Capture semaphore locally to avoid main actor isolation in completion handler
        let semaphore = frameSemaphore!
        renderCommandBuffer.addCompletedHandler { _ in
            semaphore.signal()
        }

        renderCommandBuffer.present(drawable)
        renderCommandBuffer.commit()
    }

    // MARK: - Embedded Shader Source

    private static let metalShaderSource = """
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
