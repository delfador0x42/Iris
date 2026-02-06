import SwiftUI

/// Reusable detail row showing a label and value
/// Used in detail sheets and popovers across the app
public struct DetailRow: View {
    let label: String
    let value: String
    var labelWidth: CGFloat = 120

    public init(label: String, value: String, labelWidth: CGFloat = 120) {
        self.label = label
        self.value = value
        self.labelWidth = labelWidth
    }

    public var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .foregroundColor(.gray)
                .frame(width: labelWidth, alignment: .leading)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white)
                .textSelection(.enabled)
            Spacer()
        }
    }
}
