import SwiftUI

/// Process monitor header — NieR aesthetic.
struct ProcessListHeaderView: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            // Title row
            HStack {
                Text("PROCESS MONITOR")
                    .font(.system(size: 12, weight: .bold, design: .monospaced))
                    .foregroundColor(.cyan.opacity(0.7))

                Spacer()

                Button(action: {
                    Task { await store.refreshProcesses() }
                }) {
                    Image(systemName: "arrow.clockwise")
                        .font(.system(size: 11))
                        .foregroundColor(.cyan.opacity(store.isLoading ? 0.2 : 0.5))
                }
                .buttonStyle(.plain)
                .disabled(store.isLoading)
            }

            // Stats row
            HStack(spacing: 12) {
                StatBox(label: "Total", value: "\(store.totalCount)", color: .cyan)
                StatBox(
                    label: "Suspicious", value: "\(store.suspiciousCount)",
                    color: store.suspiciousCount > 0
                        ? Color(red: 1.0, green: 0.35, blue: 0.35)
                        : Color(red: 0.3, green: 0.9, blue: 0.5)
                )

                if store.viewMode == .history {
                    StatBox(label: "History", value: "\(store.processHistory.count)", color: .cyan)
                }

                esStatusBadge

                Spacer()

                if let lastUpdate = store.lastUpdate {
                    Text(lastUpdate, style: .time)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.2))
                }
            }
        }
        .padding(.vertical, 12)
        .padding(.horizontal, 16)
        .background(Color(red: 0.02, green: 0.03, blue: 0.06))
    }

    private var esStatusBadge: some View {
        let (color, icon, label): (Color, String, String) = {
            switch store.esExtensionStatus {
            case .running:
                return (Color(red: 0.3, green: 0.9, blue: 0.5), "shield.checkered", "ES")
            case .esDisabled:
                return (Color(red: 1.0, green: 0.6, blue: 0.2), "shield.slash", "ES OFF")
            case .notInstalled:
                return (Color(red: 1.0, green: 0.35, blue: 0.35), "shield.slash", "NO ES")
            case .error:
                return (Color(red: 1.0, green: 0.35, blue: 0.35), "exclamationmark.shield", "ES ERR")
            case .unknown:
                return (Color.white.opacity(0.3), "shield", "...")
            }
        }()

        return HStack(spacing: 4) {
            Image(systemName: icon)
                .font(.system(size: 10))
            Text(label)
                .font(.system(size: 9, weight: .bold, design: .monospaced))
        }
        .foregroundColor(color)
        .padding(.horizontal, 6)
        .padding(.vertical, 3)
        .background(color.opacity(0.06))
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(color.opacity(0.2), lineWidth: 0.5)
        )
        .cornerRadius(3)
    }
}
