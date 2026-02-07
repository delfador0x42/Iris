import SwiftUI

/// Single row in the process list showing process info with hover and selection
struct ProcessRow: View {
    let process: ProcessInfo
    let onSelect: () -> Void
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 0) {
            // PID
            Text("\(process.pid)")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(rowColor)
                .frame(width: 70, alignment: .leading)

            // Process name with icon
            HStack(spacing: 8) {
                // Suspicious indicator
                if process.isSuspicious {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundColor(.red)
                        .font(.system(size: 12))
                }

                Text(process.displayName)
                    .font(.system(size: 13, weight: process.isSuspicious ? .semibold : .regular, design: .monospaced))
                    .foregroundColor(rowColor)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            // CPU
            Text(process.resources?.formattedCPU ?? "-")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(cpuColor)
                .frame(width: 70, alignment: .trailing)

            // Memory
            Text(process.resources?.formattedMemory ?? "-")
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.green.opacity(0.8))
                .frame(width: 80, alignment: .trailing)

            // User
            Text(ProcessStore.username(forUID: process.userId))
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(rowColor)
                .frame(width: 100, alignment: .leading)

            // Signing status
            Text(signingStatus)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(signingColor)
                .frame(width: 140, alignment: .leading)
        }
        .padding(.vertical, 6)
        .padding(.horizontal, 4)
        .contentShape(Rectangle())
        .background(backgroundColor)
        .onTapGesture {
            onSelect()
        }
        .onHover { hovering in
            isHovered = hovering
        }
    }

    private var backgroundColor: Color {
        if process.isSuspicious {
            return Color.red.opacity(isHovered ? 0.15 : 0.08)
        } else if isHovered {
            return Color.white.opacity(0.05)
        }
        return Color.clear
    }

    private var rowColor: Color {
        process.isSuspicious ? .red : .white
    }

    private var signingStatus: String {
        process.codeSigningInfo?.signerDescription ?? "Unknown"
    }

    private var cpuColor: Color {
        guard let cpu = process.resources?.cpuUsagePercent else { return .gray }
        if cpu > 80 { return .red }
        if cpu > 40 { return .orange }
        return .cyan
    }

    private var signingColor: Color {
        guard let csInfo = process.codeSigningInfo else {
            return .orange
        }

        if csInfo.isPlatformBinary {
            return .green
        } else if csInfo.isAppleSigned {
            return .green.opacity(0.8)
        } else if csInfo.teamId != nil {
            return .blue
        } else if csInfo.signingId != nil {
            return .orange  // Ad-hoc
        } else {
            return .red  // Unsigned
        }
    }
}
