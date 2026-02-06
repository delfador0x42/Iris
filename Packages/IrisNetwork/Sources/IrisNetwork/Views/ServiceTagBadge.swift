import SwiftUI

/// Badge displaying a service tag with color-coding based on tag type
struct ServiceTagBadge: View {
    let tag: String

    var body: some View {
        Text(tag)
            .font(.system(size: 10, weight: .medium))
            .padding(.horizontal, 6)
            .padding(.vertical, 3)
            .background(tagColor.opacity(0.2))
            .foregroundColor(tagColor)
            .cornerRadius(4)
    }

    private var tagColor: Color {
        switch tag.lowercased() {
        case "vpn": return .purple
        case "proxy": return .orange
        case "botnet", "malware", "compromised": return .red
        case "tor": return .indigo
        case "honeypot": return .yellow
        case "self-signed": return .orange
        case "cloud": return .cyan
        case "iot": return .teal
        case "database": return .blue
        case "starttls": return .green
        default: return .gray
        }
    }
}
