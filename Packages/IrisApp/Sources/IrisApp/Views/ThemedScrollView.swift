import SwiftUI

/// Themed scroll view with a styled indicator matching the app's dark aesthetic.
/// Drop-in replacement for ScrollView — uses onScrollGeometryChange for accurate tracking
/// including LazyVStack content.
struct ThemedScrollView<Content: View>: View {
    let axes: Axis.Set
    @ViewBuilder let content: () -> Content

    @State private var contentLength: CGFloat = 0
    @State private var viewportLength: CGFloat = 0
    @State private var scrollOffset: CGFloat = 0

    private var isVertical: Bool { axes != .horizontal }

    init(_ axes: Axis.Set = .vertical, @ViewBuilder content: @escaping () -> Content) {
        self.axes = axes
        self.content = content
    }

    var body: some View {
        ScrollView(axes) {
            content()
        }
        .scrollIndicators(.hidden)
        .onScrollGeometryChange(for: ScrollMetrics.self) { geo in
            ScrollMetrics(
                content: isVertical ? geo.contentSize.height : geo.contentSize.width,
                viewport: isVertical ? geo.containerSize.height : geo.containerSize.width,
                offset: isVertical ? geo.contentOffset.y : geo.contentOffset.x
            )
        } action: { _, new in
            contentLength = new.content
            viewportLength = new.viewport
            scrollOffset = new.offset
        }
        .overlay(alignment: isVertical ? .trailing : .bottom) {
            scrollIndicator
                .allowsHitTesting(false)
        }
    }

    // MARK: - Indicator

    @ViewBuilder
    private var scrollIndicator: some View {
        if contentLength > viewportLength, viewportLength > 0 {
            let ratio = viewportLength / contentLength
            let thumbLength = max(ratio * viewportLength, 30)
            let maxOffset = contentLength - viewportLength
            let progress = maxOffset > 0 ? min(max(scrollOffset / maxOffset, 0), 1) : 0
            let thumbOffset = progress * (viewportLength - thumbLength)

            ZStack(alignment: isVertical ? .top : .leading) {
                RoundedRectangle(cornerRadius: 3)
                    .fill(Color.white.opacity(0.04))

                RoundedRectangle(cornerRadius: 3)
                    .fill(Color.cyan.opacity(0.25))
                    .frame(
                        width: isVertical ? nil : thumbLength,
                        height: isVertical ? thumbLength : nil
                    )
                    .offset(
                        x: isVertical ? 0 : thumbOffset,
                        y: isVertical ? thumbOffset : 0
                    )
            }
            .frame(width: isVertical ? 6 : nil, height: isVertical ? nil : 6)
            .padding(2)
        }
    }

    private struct ScrollMetrics: Equatable {
        let content: CGFloat
        let viewport: CGFloat
        let offset: CGFloat
    }
}
