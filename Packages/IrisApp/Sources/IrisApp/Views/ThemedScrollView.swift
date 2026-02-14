import SwiftUI
import AppKit

/// Themed scroll view with interactive cyan-tinted scrollbar.
/// VSCode-style: hidden by default, appears on hover or scroll, fades out after inactivity.
struct ThemedScrollView<Content: View>: View {
    let axes: Axis.Set
    @ViewBuilder let content: () -> Content

    @State private var contentLength: CGFloat = 0
    @State private var viewportLength: CGFloat = 0
    @State private var scrollOffset: CGFloat = 0
    @State private var isDragging = false
    @State private var isContainerHovered = false
    @State private var scrollbarVisible = false
    @State private var hideTask: Task<Void, Never>?
    @State private var scrollBridge: ScrollBridge?

    private var isVertical: Bool { axes != .horizontal }

    init(_ axes: Axis.Set = .vertical, @ViewBuilder content: @escaping () -> Content) {
        self.axes = axes
        self.content = content
    }

    var body: some View {
        ScrollView(axes) {
            content()
                .background(ScrollBridgeFinder(bridge: $scrollBridge))
        }
        .scrollIndicators(.hidden)
        .onScrollGeometryChange(for: ScrollMetrics.self) { geo in
            ScrollMetrics(
                content: isVertical ? geo.contentSize.height : geo.contentSize.width,
                viewport: isVertical ? geo.containerSize.height : geo.containerSize.width,
                offset: isVertical ? geo.contentOffset.y : geo.contentOffset.x
            )
        } action: { old, new in
            contentLength = new.content
            viewportLength = new.viewport
            scrollOffset = new.offset
            if old.offset != new.offset { revealScrollbar() }
        }
        .onHover { hovering in
            isContainerHovered = hovering
            if hovering {
                revealScrollbar()
            } else if !isDragging {
                scheduleHide()
            }
        }
        .overlay(alignment: isVertical ? .trailing : .bottom) {
            scrollIndicator
        }
    }

    // MARK: - Visibility (VSCode timings: 100ms in, 500ms delay, 800ms out)

    private func revealScrollbar() {
        hideTask?.cancel()
        withAnimation(.linear(duration: 0.1)) {
            scrollbarVisible = true
        }
        if !isContainerHovered && !isDragging {
            scheduleHide()
        }
    }

    private func scheduleHide() {
        hideTask?.cancel()
        hideTask = Task { @MainActor in
            try? await Task.sleep(for: .milliseconds(500))
            guard !Task.isCancelled else { return }
            withAnimation(.linear(duration: 0.8)) {
                scrollbarVisible = false
            }
        }
    }

    // MARK: - Interactive Indicator

    @ViewBuilder
    private var scrollIndicator: some View {
        if contentLength > viewportLength, viewportLength > 0 {
            let ratio = viewportLength / contentLength
            let thumbLength = max(ratio * viewportLength, 30)
            let maxOffset = contentLength - viewportLength
            let progress = maxOffset > 0 ? min(max(scrollOffset / maxOffset, 0), 1) : 0
            let thumbOffset = progress * (viewportLength - thumbLength)

            GeometryReader { geo in
                ZStack(alignment: isVertical ? .top : .leading) {
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color.white.opacity(0.04))

                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color.cyan.opacity(isDragging ? 0.5 : 0.25))
                        .frame(
                            width: isVertical ? nil : thumbLength,
                            height: isVertical ? thumbLength : nil
                        )
                        .offset(
                            x: isVertical ? 0 : thumbOffset,
                            y: isVertical ? thumbOffset : 0
                        )
                }
                .contentShape(Rectangle())
                .gesture(
                    DragGesture(minimumDistance: 0)
                        .onChanged { value in
                            isDragging = true
                            hideTask?.cancel()
                            let trackLength = isVertical ? geo.size.height : geo.size.width
                            let pos = isVertical ? value.location.y : value.location.x
                            let fraction = min(max(pos / trackLength, 0), 1)
                            scrollBridge?.scroll(to: fraction, vertical: isVertical)
                        }
                        .onEnded { _ in
                            isDragging = false
                            scheduleHide()
                        }
                )
            }
            .frame(width: isVertical ? 8 : nil, height: isVertical ? nil : 8)
            .padding(2)
            .opacity(scrollbarVisible ? 1 : 0)
            .allowsHitTesting(scrollbarVisible)
        }
    }

    private struct ScrollMetrics: Equatable {
        let content: CGFloat
        let viewport: CGFloat
        let offset: CGFloat
    }
}

// MARK: - NSScrollView Bridge

/// Bridges SwiftUI scroll gestures to the underlying NSScrollView.
final class ScrollBridge {
    weak var scrollView: NSScrollView?

    func scroll(to fraction: CGFloat, vertical: Bool) {
        guard let sv = scrollView, let doc = sv.documentView else { return }
        if vertical {
            let maxY = doc.frame.height - sv.contentSize.height
            sv.contentView.setBoundsOrigin(
                NSPoint(x: sv.contentView.bounds.origin.x, y: fraction * maxY)
            )
        } else {
            let maxX = doc.frame.width - sv.contentSize.width
            sv.contentView.setBoundsOrigin(
                NSPoint(x: fraction * maxX, y: sv.contentView.bounds.origin.y)
            )
        }
        sv.reflectScrolledClipView(sv.contentView)
    }
}



/// Invisible NSView placed inside the ScrollView content to find the backing NSScrollView.
struct ScrollBridgeFinder: NSViewRepresentable {
    @Binding var bridge: ScrollBridge?

    func makeNSView(context: Context) -> NSView {
        let view = NSView()
        view.frame = .zero
        DispatchQueue.main.async { [weak view] in
            guard let view, let sv = view.enclosingScrollView else { return }
            let b = ScrollBridge()
            b.scrollView = sv
            bridge = b
        }
        return view
    }

    func updateNSView(_ nsView: NSView, context: Context) {
        if bridge?.scrollView == nil, let sv = nsView.enclosingScrollView {
            DispatchQueue.main.async {
                let b = ScrollBridge()
                b.scrollView = sv
                bridge = b
            }
        }
    }
}











