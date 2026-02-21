import SwiftUI

// MARK: - Network Capture Settings

extension SettingsView {

    var networkCaptureSection: some View {
        VStack(alignment: .leading, spacing: 16) {
            sectionHeader(title: "Network Capture", icon: "waveform")

            CaptureSettingsContent()
        }
        .padding(20)
        .background(Color.white.opacity(0.04))
        .cornerRadius(12)
    }
}

/// Standalone view for capture stats — uses shared SecurityStore
private struct CaptureSettingsContent: View {
    @StateObject private var store = SecurityStore.shared
    @State private var budgetGB: Double = 30
    @State private var totalCaptureBytes: Int = 0
    @State private var connectionsWithData: Int = 0
    @State private var totalConnections: Int = 0
    @State private var isLoading = true

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            if isLoading {
                HStack {
                    ProgressView().controlSize(.small)
                    Text("Loading capture stats...")
                        .font(.system(size: 12))
                        .foregroundColor(.gray)
                }
            } else {
                usageDisplay
            }

            // Budget slider
            VStack(alignment: .leading, spacing: 8) {
                Text("Memory Budget")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundColor(.white)

                HStack(spacing: 12) {
                    Slider(value: $budgetGB, in: 1...100, step: 1)
                        .frame(maxWidth: 300)

                    Text("\(Int(budgetGB)) GB")
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.white)
                        .frame(width: 60, alignment: .trailing)
                }

                Text("Maximum memory for buffering raw network data. Oldest connections evicted when exceeded.")
                    .font(.system(size: 11))
                    .foregroundColor(.gray)
            }

            HStack(spacing: 12) {
                Button("Apply Budget") {
                    Task { await applyBudget() }
                }
                .buttonStyle(.bordered)
                .tint(.blue)

                Button("Refresh Stats") {
                    Task { await refreshStats() }
                }
                .buttonStyle(.bordered)
                .tint(.gray)
            }
        }
        .onAppear {
            Task { await refreshStats() }
        }
    }

    private var usageDisplay: some View {
        VStack(alignment: .leading, spacing: 6) {
            let usedStr = ByteFormatter.format(UInt64(totalCaptureBytes))
            let budgetStr = ByteFormatter.format(UInt64(budgetGB * 1024 * 1024 * 1024))
            let pct = budgetGB > 0 ? Double(totalCaptureBytes) / (budgetGB * 1024 * 1024 * 1024) : 0

            HStack(spacing: 8) {
                Text("\(usedStr) / \(budgetStr)")
                    .font(.system(size: 14, weight: .medium, design: .monospaced))
                    .foregroundColor(.white)

                Text("(\(connectionsWithData) of \(totalConnections) connections)")
                    .font(.system(size: 12))
                    .foregroundColor(.gray)
            }

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.white.opacity(0.1))
                        .frame(height: 8)

                    RoundedRectangle(cornerRadius: 4)
                        .fill(pct > 0.9 ? Color.red : pct > 0.7 ? Color.orange : Color.green)
                        .frame(width: max(0, geo.size.width * min(pct, 1.0)), height: 8)
                }
            }
            .frame(height: 8)
        }
    }

    private func refreshStats() async {
        let stats = await store.fetchCaptureStats()
        totalCaptureBytes = stats["totalCaptureBytes"] as? Int ?? 0
        connectionsWithData = stats["connectionsWithData"] as? Int ?? 0
        totalConnections = stats["totalConnections"] as? Int ?? 0
        let currentBudget = stats["captureMemoryBudget"] as? Int ?? Int(30 * 1024 * 1024 * 1024)
        budgetGB = Double(currentBudget) / (1024 * 1024 * 1024)
        isLoading = false
    }

    private func applyBudget() async {
        let bytes = Int(budgetGB * 1024 * 1024 * 1024)
        _ = await store.setCaptureMemoryBudget(bytes)
        await refreshStats()
    }
}
