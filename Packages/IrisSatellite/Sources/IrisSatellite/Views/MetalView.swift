import SwiftUI
import MetalKit
import IrisShared

/// SwiftUI wrapper for MTKView
struct MetalView: NSViewRepresentable {
    // Don't use @ObservedObject - Metal handles rendering via delegate, not SwiftUI
    var renderer: Renderer
    var camera: Camera
    var onSetupError: ((IrisError) -> Void)?

    func makeNSView(context: Context) -> MTKView {
        let view = MTKView()

        guard let device = MTLCreateSystemDefaultDevice() else {
            let error = IrisError.rendering(.metalNotSupported)
            onSetupError?(error)
            print("MetalView setup error: \(error.localizedDescription)")
            return view
        }

        view.device = device
        view.delegate = renderer
        view.colorPixelFormat = .bgra8Unorm
        view.depthStencilPixelFormat = .depth32Float
        view.clearColor = MTLClearColor(red: 0.0, green: 0.0, blue: 0.02, alpha: 1.0)
        view.preferredFramesPerSecond = 60
        view.enableSetNeedsDisplay = false
        view.isPaused = false

        // Enable layer-backed for proper compositing
        view.layer?.isOpaque = true

        // Setup renderer with device
        do {
            try renderer.setup(device: device, view: view)
        } catch let error as IrisError {
            onSetupError?(error)
            print("MetalView setup error: \(error.localizedDescription)")
        } catch {
            let wrappedError = IrisError.rendering(.deviceCreationFailed)
            onSetupError?(wrappedError)
            print("MetalView setup error: \(error.localizedDescription)")
        }

        // Setup input handling
        context.coordinator.setupGestures(view: view)

        return view
    }

    func updateNSView(_ nsView: MTKView, context: Context) {
        // Update renderer with current camera
        renderer.camera = camera
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(camera: camera)
    }

    @MainActor
    class Coordinator: NSObject {
        let camera: Camera
        private var lastPanLocation: NSPoint = .zero
        private var isPanning: Bool = false
        // Store scroll monitor to prevent memory leak (nonisolated for deinit access)
        nonisolated(unsafe) private var scrollMonitor: Any?

        init(camera: Camera) {
            self.camera = camera
            super.init()
        }

        deinit {
            // Remove scroll monitor to prevent memory leak
            if let monitor = scrollMonitor {
                NSEvent.removeMonitor(monitor)
            }
        }

        func setupGestures(view: MTKView) {
            // Enable touch events
            view.allowedTouchTypes = [.indirect]

            // Pan gesture for rotation
            let panGesture = NSPanGestureRecognizer(target: self, action: #selector(handlePan(_:)))
            view.addGestureRecognizer(panGesture)

            // Magnify gesture for zoom
            let magnifyGesture = NSMagnificationGestureRecognizer(target: self, action: #selector(handleMagnify(_:)))
            view.addGestureRecognizer(magnifyGesture)

            // Scroll wheel for zoom - store monitor for cleanup in deinit
            scrollMonitor = NSEvent.addLocalMonitorForEvents(matching: .scrollWheel) { [weak self] event in
                guard let self = self else { return event }
                if let view = event.window?.contentView?.hitTest(event.locationInWindow),
                   view is MTKView {
                    self.handleScroll(event)
                }
                return event
            }
        }

        @objc func handlePan(_ gesture: NSPanGestureRecognizer) {
            let translation = gesture.translation(in: gesture.view)

            // Check for modifier keys
            if NSEvent.modifierFlags.contains(.shift) {
                // Pan mode
                camera.pan(deltaX: Float(-translation.x), deltaY: Float(translation.y))
            } else {
                // Rotation mode
                camera.rotate(
                    deltaAzimuth: Float(translation.x) * 0.005,
                    deltaElevation: Float(translation.y) * 0.005
                )
            }

            gesture.setTranslation(.zero, in: gesture.view)
        }

        @objc func handleMagnify(_ gesture: NSMagnificationGestureRecognizer) {
            camera.zoom(delta: Float(gesture.magnification))
            gesture.magnification = 0
        }

        func handleScroll(_ event: NSEvent) {
            // Use scroll delta for zoom
            let delta = Float(event.scrollingDeltaY) * 0.01
            camera.zoom(delta: delta)
        }
    }
}
