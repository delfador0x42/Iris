import SwiftUI

/// Compact stat box — outline style, NieR aesthetic.
public struct StatBox: View {
    let label: String
    let value: String
    let color: Color
    var fontSize: CGFloat = 13
    var fontWeight: Font.Weight = .bold

    public init(
        label: String,
        value: String,
        color: Color,
        fontSize: CGFloat = 13,
        fontWeight: Font.Weight = .bold
    ) {
        self.label = label
        self.value = value
        self.color = color
        self.fontSize = fontSize
        self.fontWeight = fontWeight
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 1) {
            Text(label.uppercased())
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(.white.opacity(0.25))
            Text(value)
                .font(.system(size: fontSize, weight: fontWeight, design: .monospaced))
                .foregroundColor(color)
        }
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(color.opacity(0.04))
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(color.opacity(0.12), lineWidth: 0.5)
        )
        .cornerRadius(3)
    }
}
