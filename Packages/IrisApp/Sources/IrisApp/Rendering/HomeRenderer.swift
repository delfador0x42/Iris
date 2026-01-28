import MetalKit
import simd
import IrisShared

/// Extended uniforms for AAA home renderer
struct HomeUniforms {
    var time: Float
    var aspectRatio: Float
    var hoveredButton: Int32
    var previousHoveredButton: Int32
    var hoverStartTime: Float
    var sceneStartTime: Float
    var mouseX: Float
    var mouseY: Float
}

/// AAA-quality Metal renderer for the home screen
@MainActor
public class HomeRenderer: NSObject, ObservableObject, MTKViewDelegate {
    private var device: MTLDevice!
    private var commandQueue: MTLCommandQueue!
    private var pipelineState: MTLRenderPipelineState!
    private var vertexBuffer: MTLBuffer!
    private var uniformBuffer: MTLBuffer!

    private var startTime: Date = Date()
    private var sceneStartTime: Date = Date()
    private var viewSize: CGSize = .zero

    @Published public var hoveredButton: Int? = nil
    public var previousHoveredButton: Int? = nil
    private var hoverStartTime: Date = Date()
    public var mousePosition: CGPoint = .zero

    private let buttonCount = 8

    public override init() {
        super.init()
    }

    public func setup(device: MTLDevice, view: MTKView) throws {
        self.device = device

        guard let commandQueue = device.makeCommandQueue() else {
            throw IrisError.rendering(.commandQueueCreationFailed)
        }
        self.commandQueue = commandQueue
        self.sceneStartTime = Date()

        let library: MTLLibrary
        if let defaultLibrary = device.makeDefaultLibrary() {
            library = defaultLibrary
        } else {
            do {
                library = try device.makeLibrary(source: Self.shaderSource, options: nil)
            } catch {
                throw IrisError.rendering(.shaderCompilationFailed("Home: \(error.localizedDescription)"))
            }
        }

        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = library.makeFunction(name: "home_vertex")
        descriptor.fragmentFunction = library.makeFunction(name: "home_fragment")
        descriptor.colorAttachments[0].pixelFormat = view.colorPixelFormat

        do {
            pipelineState = try device.makeRenderPipelineState(descriptor: descriptor)
        } catch {
            throw IrisError.rendering(.pipelineCreationFailed("Home: \(error.localizedDescription)"))
        }

        let vertices: [SIMD2<Float>] = [
            SIMD2(-1, -1), SIMD2(1, -1), SIMD2(-1, 1),
            SIMD2(1, -1), SIMD2(1, 1), SIMD2(-1, 1)
        ]
        vertexBuffer = device.makeBuffer(bytes: vertices, length: vertices.count * MemoryLayout<SIMD2<Float>>.stride, options: .storageModeShared)
        uniformBuffer = device.makeBuffer(length: MemoryLayout<HomeUniforms>.stride, options: .storageModeShared)
    }

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

    // MARK: - Modern Minimalist Shader Source

    private static let shaderSource = """
    #include <metal_stdlib>
    using namespace metal;

    // =====================================================
    // UNIFORMS
    // =====================================================
    struct HomeUniforms {
        float time;
        float aspectRatio;
        int hoveredButton;
        int previousHoveredButton;
        float hoverStartTime;
        float sceneStartTime;
        float mouseX;
        float mouseY;
    };

    struct VertexOut {
        float4 position [[position]];
        float2 uv;
    };

    // =====================================================
    // CONSTANTS - Cyberpunk Color Palette
    // =====================================================
    constant float3 CYAN = float3(0.0, 0.85, 0.85);
    constant float3 CYAN_DIM = float3(0.0, 0.4, 0.45);
    constant float3 CYAN_GLOW = float3(0.0, 0.6, 0.65);
    constant float3 BG_DARK = float3(0.012, 0.015, 0.022);
    constant float3 BG_GRID = float3(0.025, 0.03, 0.045);

    // =====================================================
    // UTILITY FUNCTIONS
    // =====================================================

    float hash21(float2 p) {
        p = fract(p * float2(234.34, 435.345));
        p += dot(p, p + 34.23);
        return fract(p.x * p.y);
    }

    float easeOutCubic(float t) {
        t = t - 1.0;
        return t * t * t + 1.0;
    }

    float easeOutQuad(float t) {
        return t * (2.0 - t);
    }

    // =====================================================
    // BACKGROUND - Clean Grid
    // =====================================================

    float3 renderGrid(float2 uv, float time, float entrance) {
        float3 color = float3(0.0);

        float gridEntrance = saturate(entrance * 2.0);

        // Major grid lines
        float2 gridUV = uv * 12.0;
        float2 gridLine = abs(fract(gridUV) - 0.5);
        float majorGrid = 1.0 - smoothstep(0.0, 0.04, min(gridLine.x, gridLine.y));

        // Minor grid lines (subdivisions)
        float2 minorGridUV = uv * 48.0;
        float2 minorGridLine = abs(fract(minorGridUV) - 0.5);
        float minorGrid = 1.0 - smoothstep(0.0, 0.08, min(minorGridLine.x, minorGridLine.y));

        // Distance fade
        float dist = length(uv);
        float fade = smoothstep(1.2, 0.2, dist);

        // Combine grids
        color += CYAN_DIM * majorGrid * 0.15 * fade * gridEntrance;
        color += CYAN_DIM * minorGrid * 0.04 * fade * gridEntrance;

        return color;
    }

    // =====================================================
    // SCANLINE EFFECT
    // =====================================================

    float3 renderScanlines(float2 uv, float time, float entrance) {
        float3 color = float3(0.0);

        // Subtle CRT-style horizontal lines only
        float crtLines = sin(uv.y * 400.0) * 0.5 + 0.5;
        crtLines = smoothstep(0.3, 0.7, crtLines);
        color *= 0.97 + crtLines * 0.03;

        return color;
    }

    // =====================================================
    // CENTRAL HEX/CIRCLE
    // =====================================================

    float3 renderCenterElement(float2 uv, float time, float entrance) {
        float3 color = float3(0.0);
        float dist = length(uv);

        float centerEntrance = saturate((entrance - 0.2) * 3.0);
        float scale = easeOutCubic(centerEntrance);

        // Outer ring
        float outerRadius = 0.16 * scale;
        float outerRing = smoothstep(0.003, 0.0, abs(dist - outerRadius));
        color += CYAN * outerRing * 0.8;

        // Inner ring
        float innerRadius = 0.12 * scale;
        float innerRing = smoothstep(0.002, 0.0, abs(dist - innerRadius));
        color += CYAN_DIM * innerRing * 0.5;

        // Center fill with subtle gradient
        float innerFill = smoothstep(innerRadius, innerRadius - 0.03, dist);
        float3 fillColor = mix(BG_DARK, BG_GRID, 0.5);
        color = mix(color, fillColor, innerFill * 0.8);

        // Pulsing glow
        float pulse = 0.5 + 0.5 * sin(time * 1.2);
        float glow = smoothstep(0.25, 0.0, dist) * pulse * 0.08;
        color += CYAN_GLOW * glow * centerEntrance;

        return color;
    }

    // =====================================================
    // ORBITAL RING
    // =====================================================

    float3 renderOrbitalRing(float2 uv, float time, float entrance) {
        float3 color = float3(0.0);
        float dist = length(uv);
        float angle = atan2(uv.y, uv.x);

        float ringEntrance = saturate((entrance - 0.4) * 2.5);
        float buttonRadius = 0.5;

        // Main orbital ring
        float ring = smoothstep(0.004, 0.0, abs(dist - buttonRadius));

        // Animated dashes
        float dashPattern = sin(angle * 32.0 - time * 1.5);
        dashPattern = smoothstep(0.3, 0.7, dashPattern);
        ring *= dashPattern;

        color += CYAN_DIM * ring * 0.4 * ringEntrance;

        // Inner subtle ring
        float innerRingRadius = 0.35;
        float innerRing = smoothstep(0.002, 0.0, abs(dist - innerRingRadius));
        float innerDash = sin(angle * 48.0 + time * 0.8);
        innerDash = smoothstep(0.4, 0.6, innerDash);
        innerRing *= innerDash;
        color += CYAN_DIM * innerRing * 0.15 * ringEntrance;

        // Outer subtle ring
        float outerRingRadius = 0.65;
        float outerRing = smoothstep(0.002, 0.0, abs(dist - outerRingRadius));
        float outerDash = sin(angle * 24.0 - time * 0.5);
        outerDash = smoothstep(0.4, 0.6, outerDash);
        outerRing *= outerDash;
        color += CYAN_DIM * outerRing * 0.12 * ringEntrance;

        return color;
    }

    // =====================================================
    // MINIMALIST BUTTON
    // =====================================================

    float3 renderButton(float2 uv, float2 btnPos, int index, int hovered, int prevHovered,
                        float time, float hoverTime, float entrance) {
        float2 localUV = uv - btnPos;
        float dist = length(localUV);
        bool isHovered = (hovered == index);
        bool wasHovered = (prevHovered == index);

        // Staggered entrance - ensure all buttons reach full size by entrance = 1.0
        float btnEntranceDelay = 0.2 + float(index) * 0.05;
        float btnEntrance = saturate((entrance - btnEntranceDelay) * 5.0);
        btnEntrance = easeOutQuad(btnEntrance);

        if (btnEntrance <= 0.0) return float3(0.0);

        // Hover transition
        float hoverTransition = saturate(hoverTime * 6.0);
        if (!isHovered) hoverTransition = 1.0 - hoverTransition;
        if (!isHovered && !wasHovered) hoverTransition = 0.0;
        if (isHovered && wasHovered) hoverTransition = 1.0;

        float3 buttonColor = float3(0.0);

        // Button size
        float baseSize = 0.055;
        float hoverSize = 0.065;
        float size = mix(baseSize, hoverSize, hoverTransition) * btnEntrance;

        // Outer glow (hover only)
        float glowSize = size * 2.5;
        float glow = smoothstep(glowSize, size, dist);
        glow *= hoverTransition;
        buttonColor += CYAN_GLOW * glow * 0.25;

        // Button border (clean circle)
        float borderWidth = mix(0.003, 0.004, hoverTransition);
        float border = smoothstep(borderWidth, 0.0, abs(dist - size));
        float3 borderColor = mix(CYAN_DIM, CYAN, hoverTransition);
        buttonColor += borderColor * border * (0.6 + 0.4 * hoverTransition);

        // Inner fill (subtle)
        float fill = smoothstep(size - 0.002, size - 0.015, dist);
        float3 fillColor = mix(BG_DARK * 1.5, BG_GRID * 1.5, hoverTransition);
        buttonColor = mix(buttonColor, fillColor, fill * 0.7);

        // Center dot
        float dotSize = 0.008 * (1.0 + hoverTransition * 0.3);
        float dot = smoothstep(dotSize, dotSize * 0.3, dist);
        buttonColor += CYAN * dot * (0.4 + 0.6 * hoverTransition);

        // Hover ring animation
        if (hoverTransition > 0.01) {
            float ringTime = fract(time * 0.8);
            float ringRadius = size * (0.3 + ringTime * 1.5);
            float ring = smoothstep(0.006, 0.0, abs(dist - ringRadius));
            ring *= (1.0 - ringTime) * hoverTransition;
            buttonColor += CYAN * ring * 0.3;
        }

        return buttonColor * btnEntrance;
    }

    // =====================================================
    // CORNER DECORATIONS
    // =====================================================

    float3 renderCornerElements(float2 uv, float time, float entrance) {
        float3 color = float3(0.0);

        float cornerEntrance = saturate((entrance - 0.6) * 2.0);

        // Corner brackets
        float margin = 0.85;
        float bracketLen = 0.12;
        float bracketWidth = 0.003;

        // Process each corner
        for (int i = 0; i < 4; i++) {
            float sx = (i % 2 == 0) ? -1.0 : 1.0;
            float sy = (i < 2) ? -1.0 : 1.0;

            float2 corner = float2(sx * margin, sy * margin);

            // Horizontal part
            float hDist = abs(uv.y - corner.y);
            float hLine = smoothstep(bracketWidth, 0.0, hDist);
            hLine *= step(min(corner.x, corner.x + sx * bracketLen), uv.x * sx) *
                     step(uv.x * sx, max(corner.x, corner.x + sx * bracketLen) * sx);

            // Vertical part
            float vDist = abs(uv.x - corner.x);
            float vLine = smoothstep(bracketWidth, 0.0, vDist);
            vLine *= step(min(corner.y, corner.y + sy * bracketLen), uv.y * sy) *
                     step(uv.y * sy, max(corner.y, corner.y + sy * bracketLen) * sy);

            color += CYAN_DIM * (hLine + vLine) * 0.5 * cornerEntrance;
        }

        return color;
    }

    // =====================================================
    // POST PROCESSING
    // =====================================================

    float3 applyPostProcess(float3 color, float2 uv, float time) {
        // Subtle vignette
        float vignette = 1.0 - smoothstep(0.5, 1.4, length(uv));
        color *= 0.7 + 0.3 * vignette;

        // Very subtle film grain
        float grain = (hash21(uv * 800.0 + time * 50.0) - 0.5) * 0.015;
        color += grain;

        // Slight contrast boost
        color = pow(color, float3(0.95));

        return saturate(color);
    }

    // =====================================================
    // MAIN SHADERS
    // =====================================================

    vertex VertexOut home_vertex(uint vid [[vertex_id]], constant float2* verts [[buffer(0)]]) {
        VertexOut out;
        out.position = float4(verts[vid], 0.0, 1.0);
        out.uv = verts[vid];
        return out;
    }

    fragment float4 home_fragment(VertexOut in [[stage_in]], constant HomeUniforms& u [[buffer(0)]]) {
        float2 uv = in.uv;
        uv.x *= u.aspectRatio;

        float sceneTime = u.sceneStartTime;

        // Entrance animation (0-1 over ~1.5 seconds)
        float entranceProgress = saturate(sceneTime / 1.5);

        // Mouse parallax (very subtle)
        float2 parallaxOffset = float2(u.mouseX, u.mouseY) * 0.008;
        float2 bgUV = uv + parallaxOffset;

        // === BASE BACKGROUND ===
        float3 color = BG_DARK;

        // === GRID ===
        color += renderGrid(bgUV, u.time, entranceProgress);

        // === SCANLINES ===
        color += renderScanlines(uv, u.time, entranceProgress);

        // === ORBITAL RINGS ===
        color += renderOrbitalRing(uv, u.time, entranceProgress);

        // === CENTER ELEMENT ===
        color += renderCenterElement(uv, u.time, entranceProgress);

        // === CORNER DECORATIONS ===
        color += renderCornerElements(uv, u.time, entranceProgress);

        // === BUTTONS ===
        int buttonCount = 8;
        float buttonRadius = 0.5;

        for (int i = 0; i < buttonCount; i++) {
            float angle = -3.14159 / 2.0 + float(i) * 2.0 * 3.14159 / float(buttonCount);
            float2 btnPos = float2(cos(angle), sin(angle)) * buttonRadius;

            color += renderButton(uv, btnPos, i,
                                  u.hoveredButton, u.previousHoveredButton,
                                  u.time, u.hoverStartTime, entranceProgress);
        }

        // === POST PROCESSING ===
        color = applyPostProcess(color, uv, u.time);

        return float4(color, 1.0);
    }
    """
}
