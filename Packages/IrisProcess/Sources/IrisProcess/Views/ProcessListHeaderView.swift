import SwiftUI

/// Header view for the process list showing title and stats
struct ProcessListHeaderView: View {
    @ObservedObject var store: ProcessStore

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Title row
            HStack {
                Text("Process List")
                    .font(.system(size: 24, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                Spacer()

                // Refresh button
                Button(action: {
                    Task {
                        await store.refreshProcesses()
                    }
                }) {
                    Image(systemName: "arrow.clockwise")
                        .foregroundColor(.white)
                        .opacity(store.isLoading ? 0.5 : 1.0)
                }
                .buttonStyle(.plain)
                .disabled(store.isLoading)
            }

            // Stats row
            HStack(spacing: 24) {
                StatBox(
                    label: "Total Processes",
                    value: "\(store.totalCount)",
                    color: .white,
                    fontSize: 18,
                    fontWeight: .bold
                )
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.white.opacity(0.05))
                .cornerRadius(8)

                StatBox(
                    label: "Suspicious",
                    value: "\(store.suspiciousCount)",
                    color: store.suspiciousCount > 0 ? .red : .green,
                    fontSize: 18,
                    fontWeight: .bold
                )
                .padding(.horizontal, 12)
                .padding(.vertical, 8)
                .background(Color.white.opacity(0.05))
                .cornerRadius(8)

                Spacer()

                // Last update
                if let lastUpdate = store.lastUpdate {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Last update")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(lastUpdate, style: .time)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }
            }
        }
        .padding(.vertical, 16)
        .padding(.horizontal, 20)
        .background(Color.black.opacity(0.3))
    }
}
