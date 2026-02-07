//
//  FlowRowView.swift
//  IrisProxy
//
//  Row view for displaying a single HTTP flow in the flow list.
//

import SwiftUI

struct FlowRowView: View {
    let flow: ProxyCapturedFlow

    var body: some View {
        HStack(spacing: 12) {
            // Method badge
            MethodBadge(method: flow.request.method)

            // Status badge or pending/error
            statusView

            // URL and details
            VStack(alignment: .leading, spacing: 2) {
                Text(flow.request.host ?? "unknown")
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)

                Text(flow.request.path)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
                    .lineLimit(1)
            }

            Spacer()

            // Process name
            if let process = flow.processName {
                Text(process)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(4)
            }

            // Duration
            if let duration = flow.duration {
                Text(formatDuration(duration))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            // Size
            let size = flow.request.bodySize + (flow.response?.bodySize ?? 0)
            if size > 0 {
                Text(ByteCountFormatter.string(fromByteCount: Int64(size), countStyle: .file))
                    .font(.system(size: 11))
                    .foregroundColor(.secondary)
            }
        }
        .padding(.vertical, 4)
    }

    @ViewBuilder
    private var statusView: some View {
        if let error = flow.error {
            ErrorBadge(message: error)
        } else if let response = flow.response {
            StatusBadge(statusCode: response.statusCode)
        } else {
            PendingBadge()
        }
    }

    private func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        } else {
            return String(format: "%.2fs", duration)
        }
    }
}
