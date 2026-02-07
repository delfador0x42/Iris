import MetalKit
import simd

// MARK: - MTKViewDelegate & Drawing

@MainActor
extension Renderer {

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
        dispatchComputePass(bufferIndex: bufferIndex)

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

        drawEarth(encoder: renderEncoder)
        drawSatellites(encoder: renderEncoder, bufferIndex: bufferIndex)

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

    // MARK: - Compute Pass

    func dispatchComputePass(bufferIndex: Int) {
        guard satelliteCount > 0,
              let orbitalBuffer = orbitalElementsBuffer,
              !satelliteBuffers.isEmpty,
              let computeCommandBuffer = computeQueue.makeCommandBuffer(),
              let computeEncoder = computeCommandBuffer.makeComputeCommandEncoder() else {
            return
        }

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

    // MARK: - Draw Calls

    func drawEarth(encoder: MTLRenderCommandEncoder) {
        encoder.setRenderPipelineState(earthPipelineState)
        encoder.setVertexBuffer(earthVertexBuffer, offset: 0, index: 0)
        encoder.setVertexBuffer(uniformBuffer, offset: 0, index: 1)
        encoder.setFragmentBuffer(uniformBuffer, offset: 0, index: 1)
        encoder.drawIndexedPrimitives(
            type: .triangle,
            indexCount: earthIndexCount,
            indexType: .uint32,
            indexBuffer: earthIndexBuffer,
            indexBufferOffset: 0
        )
    }

    func drawSatellites(encoder: MTLRenderCommandEncoder, bufferIndex: Int) {
        guard satelliteCount > 0 && !satelliteBuffers.isEmpty else { return }

        encoder.setRenderPipelineState(satellitePipelineState)
        encoder.setVertexBuffer(uniformBuffer, offset: 0, index: 1)
        encoder.setVertexBuffer(satelliteBuffers[bufferIndex], offset: 0, index: 2)
        encoder.drawPrimitives(
            type: .point,
            vertexStart: 0,
            vertexCount: 1,
            instanceCount: satelliteCount
        )
    }
}
