import MetalKit
import simd

// MARK: - Drawing & Interaction

extension HomeRenderer {

    public func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        viewSize = size
    }

    public func draw(in view: MTKView) {
        guard let drawable = view.currentDrawable,
              let descriptor = view.currentRenderPassDescriptor,
              let commandBuffer = commandQueue.makeCommandBuffer(),
              let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: descriptor) else { return }

        let time = Float(Date().timeIntervalSince(startTime))
        let sceneTime = Float(Date().timeIntervalSince(sceneStartTime))
        let hoverTime = Float(Date().timeIntervalSince(hoverStartTime))
        let aspect = viewSize.width > 0 ? Float(viewSize.width / viewSize.height) : 1.0

        // Normalized mouse position (-1 to 1)
        let mouseX = viewSize.width > 0 ? Float(mousePosition.x / viewSize.width) * 2.0 - 1.0 : 0.0
        let mouseY = viewSize.height > 0 ? Float(1.0 - mousePosition.y / viewSize.height) * 2.0 - 1.0 : 0.0

        var uniforms = HomeUniforms(
            time: time,
            aspectRatio: aspect,
            hoveredButton: Int32(hoveredButton ?? -1),
            previousHoveredButton: Int32(previousHoveredButton ?? -1),
            hoverStartTime: hoverTime,
            sceneStartTime: sceneTime,
            mouseX: mouseX,
            mouseY: mouseY
        )
        memcpy(uniformBuffer.contents(), &uniforms, MemoryLayout<HomeUniforms>.stride)

        encoder.setRenderPipelineState(pipelineState)
        encoder.setVertexBuffer(vertexBuffer, offset: 0, index: 0)
        encoder.setFragmentBuffer(uniformBuffer, offset: 0, index: 0)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 6)
        encoder.endEncoding()

        commandBuffer.present(drawable)
        commandBuffer.commit()
    }

    /// Update hover state with transition tracking
    public func setHoveredButton(_ button: Int?) {
        if button != hoveredButton {
            previousHoveredButton = hoveredButton
            hoveredButton = button
            hoverStartTime = Date()
        }
    }

    public func buttonAt(point: CGPoint, in size: CGSize) -> Int? {
        guard size.width > 0 && size.height > 0 else { return nil }

        let nx = Float(point.x / size.width) * 2.0 - 1.0
        // Note: In SwiftUI context, the view is already flipped (origin at top-left)
        // so we don't need to flip Y here
        let ny = Float(point.y / size.height) * 2.0 - 1.0
        let aspect = Float(size.width / size.height)
        let ax = nx * aspect
        let ay = ny

        let radius: Float = 0.5
        let hitSize: Float = 0.12  // Slightly larger hit area for better UX

        for i in 0..<buttonCount {
            let angle = -Float.pi / 2.0 + Float(i) * (2.0 * Float.pi / Float(buttonCount))
            let bx = cos(angle) * radius
            let by = sin(angle) * radius
            if sqrt((ax - bx) * (ax - bx) + (ay - by) * (ay - by)) < hitSize {
                return i
            }
        }
        return nil
    }
}
