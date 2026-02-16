import SwiftUI

/// Disk space information from the system
struct DiskSpaceInfo {
    let totalCapacity: UInt64
    let availableSpace: UInt64
    var usedSpace: UInt64 { totalCapacity - availableSpace }

    static func current() -> DiskSpaceInfo? {
        let fileManager = FileManager.default
        guard let attributes = try? fileManager.attributesOfFileSystem(forPath: "/"),
              let totalSize = attributes[.systemSize] as? NSNumber,
              let freeSize = attributes[.systemFreeSize] as? NSNumber else {
            return nil
        }
        return DiskSpaceInfo(
            totalCapacity: totalSize.uint64Value,
            availableSpace: freeSize.uint64Value
        )
    }
}

/// Header view for disk usage screen
struct DiskUsageHeaderView: View {
    @ObservedObject var store: DiskUsageStore
    @State private var diskInfo: DiskSpaceInfo?

    private var isScanning: Bool {
        if case .scanning = store.scanState { return true }
        return false
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Title row with rescan button
            HStack {
                Text("Disk Usage")
                    .font(.system(size: 24, weight: .bold, design: .serif))
                    .foregroundColor(.white)

                Spacer()

                // Rescan button
                if !isScanning {
                    Button(action: { store.startScan() }) {
                        HStack(spacing: 6) {
                            Image(systemName: "arrow.clockwise")
                            Text("Rescan")
                                .font(.system(size: 13))
                        }
                    }
                    .buttonStyle(.bordered)
                }
            }

            // Disk info row
            HStack(spacing: 16) {
                if let info = diskInfo {
                    // Total capacity
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Total")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(ByteFormatter.format(info.totalCapacity, style: .abbreviated))
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.white)
                    }

                    // Used space
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Used")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(ByteFormatter.format(info.usedSpace, style: .abbreviated))
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.orange)
                    }

                    // Available space
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Available")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(ByteFormatter.format(info.availableSpace, style: .abbreviated))
                            .font(.system(size: 14, weight: .medium, design: .monospaced))
                            .foregroundColor(.green)
                    }
                }

                Spacer()

                // Last scan time
                if let date = store.lastScanDate {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Last scan")
                            .font(.system(size: 10))
                            .foregroundColor(.gray.opacity(0.7))
                        Text(formatRelativeDate(date))
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.gray)
                    }
                }
            }
        }
        .padding(.vertical, 16)
        .padding(.horizontal, 20)
        .background(Color.black.opacity(0.3))
        .onAppear {
            diskInfo = DiskSpaceInfo.current()
        }
    }

    private func formatRelativeDate(_ date: Date) -> String {
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .abbreviated
        return formatter.localizedString(for: date, relativeTo: Date())
    }
}
