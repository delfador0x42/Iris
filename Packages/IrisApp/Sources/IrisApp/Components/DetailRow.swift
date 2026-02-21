import SwiftUI

/// Compact detail row — monospaced, NieR aesthetic.
public struct DetailRow: View {
    let label: String
    let value: String
    var labelWidth: CGFloat = 80

    public init(label: String, value: String, labelWidth: CGFloat = 80) {
        self.label = label
        self.value = value
        self.labelWidth = labelWidth
    }

    public var body: some View {
        HStack(alignment: .top, spacing: 6) {
            Text(label)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.3))
                .frame(width: labelWidth, alignment: .leading)
            Text(value)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
                .textSelection(.enabled)
            Spacer()
        }
    }
}
