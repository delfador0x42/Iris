import MetalKit
import os.log

// MARK: - Satellite Data Upload & Residency

@MainActor
extension Renderer {

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

    // Metal 4: Create residency set for explicit GPU memory management
    func createResidencySet() {
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
}
