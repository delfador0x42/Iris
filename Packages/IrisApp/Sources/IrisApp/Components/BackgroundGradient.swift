import SwiftUI

/// Standard app background gradient
/// Used as the base background across all main views
public struct BackgroundGradient: View {
    public init() {}

    public var body: some View {
        LinearGradient(
            colors: [
                Color(red: 0.02, green: 0.03, blue: 0.05),
                Color(red: 0.05, green: 0.07, blue: 0.1)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
        .ignoresSafeArea()
    }
}

/// View modifier to apply the standard background gradient
public struct BackgroundGradientModifier: ViewModifier {
    public func body(content: Content) -> some View {
        ZStack {
            BackgroundGradient()
            content
        }
    }
}

public extension View {
    /// Applies the standard app background gradient behind the content
    func withBackgroundGradient() -> some View {
        modifier(BackgroundGradientModifier())
    }
}
