import SwiftUI

/// Reusable detail section with title and content
/// Used in detail sheets and popovers across the app
public struct DetailSection<Content: View>: View {
    let title: String
    @ViewBuilder let content: () -> Content

    public init(title: String, @ViewBuilder content: @escaping () -> Content) {
        self.title = title
        self.content = content
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))

            VStack(alignment: .leading, spacing: 8) {
                content()
            }
            .padding(12)
            .background(Color.white.opacity(0.05))
            .cornerRadius(8)
        }
    }
}
