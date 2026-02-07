import SwiftUI
import AppKit

// MARK: - Threat Intelligence Section & Shodan Link

extension IPDetailPopover {

    var threatIntelligenceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label("Threat Intelligence", systemImage: "shield.checkerboard")
                .font(.headline)
                .foregroundColor(.primary)

            VStack(alignment: .leading, spacing: 8) {
                // Abuse score with color indicator and progress bar
                if let score = connection.abuseScore {
                    InfoRow(label: "Abuse Score") {
                        HStack(spacing: 6) {
                            Text("\(score)%")
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(abuseScoreColor(score))
                            ProgressView(value: Double(score), total: 100)
                                .progressViewStyle(.linear)
                                .frame(width: 60)
                                .tint(abuseScoreColor(score))
                        }
                    }
                }

                // Scanner status
                if let isScanner = connection.isKnownScanner {
                    SimpleInfoRow(
                        label: "Scanner",
                        value: isScanner ? "Yes (known scanner)" : "No"
                    )
                }

                // Benign service status
                if let isBenign = connection.isBenignService {
                    SimpleInfoRow(
                        label: "Benign Service",
                        value: isBenign ? "Yes (CDN/Cloud)" : "No"
                    )
                }

                // Tor exit node
                if let isTor = connection.isTor, isTor {
                    InfoRow(label: "Tor Exit") {
                        HStack(spacing: 4) {
                            Image(systemName: "eye.slash.fill")
                                .foregroundColor(.purple)
                            Text("Yes")
                                .font(.system(size: 12))
                        }
                    }
                }

                // Classification badge
                if let classification = connection.threatClassification {
                    InfoRow(label: "Classification") {
                        ThreatBadge(classification: classification)
                    }
                }

                // Data sources
                if let sources = connection.enrichmentSources, !sources.isEmpty {
                    InfoRow(label: "Sources") {
                        Text(sources.joined(separator: ", "))
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
    }

    /// Color for abuse score based on severity
    func abuseScoreColor(_ score: Int) -> Color {
        switch score {
        case 0..<25: return .green
        case 25..<50: return .yellow
        case 50..<75: return .orange
        default: return .red
        }
    }

    // MARK: - Shodan Link

    var shodanLink: some View {
        Button {
            let urlString = "https://www.shodan.io/host/\(connection.remoteAddress)"
            if let url = URL(string: urlString) {
                NSWorkspace.shared.open(url)
            }
        } label: {
            HStack {
                Label("View Full Details on Shodan", systemImage: "arrow.up.right.square")
                Spacer()
            }
        }
        .buttonStyle(.link)
        .pointerCursor()
    }
}
