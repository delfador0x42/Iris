import SwiftUI

/// Row displaying a single security check result with status and remediation
struct SecurityCheckRow: View {
    let check: SecurityCheck
    @State private var showRemediation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 10) {
                statusIcon
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(check.name)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(.white)

                    Text(check.description)
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }

                Spacer()

                severityBadge
            }

            if showRemediation, let remediation = check.remediation {
                HStack(spacing: 8) {
                    Image(systemName: "lightbulb.fill")
                        .foregroundColor(.yellow)
                        .font(.system(size: 11))

                    Text(remediation)
                        .font(.system(size: 11))
                        .foregroundColor(.white.opacity(0.8))
                }
                .padding(.leading, 30)
                .padding(.top, 2)
            }
        }
        .padding(10)
        .background(statusBackground)
        .cornerRadius(8)
        .onTapGesture {
            if check.remediation != nil {
                withAnimation(.easeInOut(duration: 0.2)) {
                    showRemediation.toggle()
                }
            }
        }
    }

    private var statusIcon: some View {
        Group {
            switch check.status {
            case .pass:
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.green)
            case .fail:
                Image(systemName: "xmark.circle.fill")
                    .foregroundColor(.red)
            case .warning:
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange)
            case .unknown:
                Image(systemName: "questionmark.circle.fill")
                    .foregroundColor(.gray)
            }
        }
    }

    private var severityBadge: some View {
        Text(check.severity.label)
            .font(.system(size: 10, weight: .medium))
            .foregroundColor(severityColor)
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(severityColor.opacity(0.15))
            .cornerRadius(4)
    }

    private var statusBackground: Color {
        switch check.status {
        case .pass: return .green.opacity(0.05)
        case .fail: return .red.opacity(0.08)
        case .warning: return .orange.opacity(0.06)
        case .unknown: return .gray.opacity(0.05)
        }
    }

    private var severityColor: Color {
        switch check.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return Color(red: 0.4, green: 0.7, blue: 1.0)
        case .info: return .gray
        }
    }
}
