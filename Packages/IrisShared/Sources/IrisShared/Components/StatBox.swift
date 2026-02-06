import SwiftUI

/// Reusable stat display box showing a label and value
/// Used in headers across ProcessListView, NetworkMonitorView, and DiskUsageView
public struct StatBox: View {
    let label: String
    let value: String
    let color: Color
    var fontSize: CGFloat = 14
    var fontWeight: Font.Weight = .medium

    public init(
        label: String,
        value: String,
        color: Color,
        fontSize: CGFloat = 14,
        fontWeight: Font.Weight = .medium
    ) {
        self.label = label
        self.value = value
        self.color = color
        self.fontSize = fontSize
        self.fontWeight = fontWeight
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 10))
                .foregroundColor(.gray.opacity(0.7))
            Text(value)
                .font(.system(size: fontSize, weight: fontWeight, design: .monospaced))
                .foregroundColor(color)
        }
    }
}
