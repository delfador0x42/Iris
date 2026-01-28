import SwiftUI
import MetalKit

/// SwiftUI wrapper for the Metal-based home screen
struct HomeMetalView: NSViewRepresentable {
    var renderer: HomeRenderer
    var onButtonClick: (Int) -> Void
    var onSetupError: ((IrisError) -> Void)?

    func makeNSView(context: Context) -> MTKView {
        let view = MTKView()

        guard let device = MTLCreateSystemDefaultDevice() else {
            let error = IrisError.rendering(.metalNotSupported)
            onSetupError?(error)
            print("HomeMetalView setup error: \(error.localizedDescription)")
            return view
        }

        view.device = device
        view.delegate = renderer
        view.colorPixelFormat = .bgra8Unorm
        view.clearColor = MTLClearColor(red: 0.02, green: 0.03, blue: 0.04, alpha: 1.0)
        view.preferredFramesPerSecond = 60
        view.enableSetNeedsDisplay = false
        view.isPaused = false

        // Enable layer-backed for proper compositing
        view.layer?.isOpaque = true

        // Setup renderer
        do {
            try renderer.setup(device: device, view: view)
        } catch let error as IrisError {
            onSetupError?(error)
            print("HomeMetalView setup error: \(error.localizedDescription)")
        } catch {
            let wrappedError = IrisError.rendering(.deviceCreationFailed)
            onSetupError?(wrappedError)
            print("HomeMetalView setup error: \(error.localizedDescription)")
        }

        // Setup mouse tracking
        context.coordinator.setupTracking(view: view)

        return view
    }

    func updateNSView(_ nsView: MTKView, context: Context) {
        // Update coordinator with current callback
        context.coordinator.onButtonClick = onButtonClick
    }

    func makeCoordinator() -> Coordinator {
        Coordinator(renderer: renderer, onButtonClick: onButtonClick)
    }

    @MainActor
    class Coordinator: NSObject {
        let renderer: HomeRenderer
        var onButtonClick: (Int) -> Void
        private weak var trackedView: MTKView?

        // Store event monitors to prevent memory leak (nonisolated for deinit access)
        nonisolated(unsafe) private var mouseMoveMonitor: Any?
        nonisolated(unsafe) private var mouseExitMonitor: Any?

        init(renderer: HomeRenderer, onButtonClick: @escaping (Int) -> Void) {
            self.renderer = renderer
            self.onButtonClick = onButtonClick
            super.init()
        }

        deinit {
            if let monitor = mouseMoveMonitor {
                NSEvent.removeMonitor(monitor)
            }
            if let monitor = mouseExitMonitor {
                NSEvent.removeMonitor(monitor)
            }
        }

        func setupTracking(view: MTKView) {
            self.trackedView = view

            // Add tracking area for mouse events
            let trackingArea = NSTrackingArea(
                rect: view.bounds,
                options: [.activeInKeyWindow, .mouseMoved, .mouseEnteredAndExited, .inVisibleRect],
                owner: view,
                userInfo: nil
            )
            view.addTrackingArea(trackingArea)

            // Add click gesture recognizer
            let clickGesture = NSClickGestureRecognizer(target: self, action: #selector(handleClick(_:)))
            view.addGestureRecognizer(clickGesture)

            // Monitor mouse move events
            mouseMoveMonitor = NSEvent.addLocalMonitorForEvents(matching: .mouseMoved) { [weak self] event in
                self?.handleMouseMoved(event)
                return event
            }

            // Monitor mouse exited events
            mouseExitMonitor = NSEvent.addLocalMonitorForEvents(matching: .mouseExited) { [weak self] event in
                self?.handleMouseExited(event)
                return event
            }
        }

        private func handleMouseMoved(_ event: NSEvent) {
            guard let view = trackedView,
                  let hitView = event.window?.contentView?.hitTest(event.locationInWindow),
                  hitView === view else {
                return
            }

            let locationInView = view.convert(event.locationInWindow, from: nil)

            // Update mouse position for parallax effects
            renderer.mousePosition = locationInView

            // Update hovered button with transition tracking
            let button = renderer.buttonAt(point: locationInView, in: view.bounds.size)
            renderer.setHoveredButton(button)

            // Update cursor
            if button != nil {
                NSCursor.pointingHand.set()
            } else {
                NSCursor.arrow.set()
            }
        }

        private func handleMouseExited(_ event: NSEvent) {
            renderer.setHoveredButton(nil)
            NSCursor.arrow.set()
        }

        @objc func handleClick(_ gesture: NSClickGestureRecognizer) {
            guard let view = gesture.view as? MTKView else { return }

            let location = gesture.location(in: view)
            if let button = renderer.buttonAt(point: location, in: view.bounds.size) {
                onButtonClick(button)
            }
        }
    }
}
