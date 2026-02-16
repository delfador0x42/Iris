import SwiftUI

struct SeverityBadge: View {
    let severity: AnomalySeverity

    var body: some View {
        Text(severity.label)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(color)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .background(color.opacity(0.15))
            .cornerRadius(4)
            .frame(width: 60)
    }

    private var color: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .gray
        }
    }
}

struct MITREBadge: View {
    let id: String
    var body: some View {
        Text(id)
            .font(.system(size: 8, design: .monospaced))
            .foregroundColor(.cyan.opacity(0.8))
            .padding(.horizontal, 4).padding(.vertical, 2)
            .background(Color.cyan.opacity(0.08))
            .cornerRadius(3)
    }
}

struct ExpandChevron: View {
    let isExpanded: Bool
    var body: some View {
        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
            .foregroundColor(.gray).font(.system(size: 10))
    }
}

func backgroundFor(_ severity: AnomalySeverity) -> Color {
    switch severity {
    case .critical: return Color.red.opacity(0.05)
    case .high: return Color.orange.opacity(0.03)
    default: return Color.white.opacity(0.02)
    }
}
