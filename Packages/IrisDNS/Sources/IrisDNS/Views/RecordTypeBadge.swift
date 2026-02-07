import SwiftUI

// MARK: - Record Type Badge

struct RecordTypeBadge: View {
    let type: String

    var body: some View {
        Text(type)
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(colorForType)
            .cornerRadius(4)
    }

    private var colorForType: Color {
        switch type {
        case "A": return .blue
        case "AAAA": return .indigo
        case "CNAME": return .purple
        case "MX": return .orange
        case "TXT": return .teal
        case "NS": return .green
        case "SOA": return .brown
        case "SRV": return .pink
        case "HTTPS", "SVCB": return .cyan
        case "PTR": return .mint
        default: return .gray
        }
    }
}
