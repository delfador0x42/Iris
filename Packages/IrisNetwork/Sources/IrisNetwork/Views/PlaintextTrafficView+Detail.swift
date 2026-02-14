//
//  PlaintextTrafficView+Detail.swift
//  IrisNetwork
//
//  Expanded request/response detail and formatting helpers.
//

import SwiftUI

extension PlaintextTrafficView {

    // MARK: - Expanded Detail

    func expandedDetail(_ flow: ProxyCapturedFlow) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            requestDetail(flow)

            if let response = flow.response {
                responseDetail(flow: flow, response: response)
            } else if let error = flow.error {
                errorDetail(error)
            }
        }
        .padding(.horizontal, 24)
        .padding(.bottom, 12)
    }

    private func requestDetail(_ flow: ProxyCapturedFlow) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(flow.request.method) \(flow.request.path) \(flow.request.httpVersion)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.orange)
                    .textSelection(.enabled)

                headerRows(flow.request.headers, color: .blue.opacity(0.8))

                if let body = flow.request.bodyPreview {
                    Divider().background(Color.gray.opacity(0.3))
                    Text(body)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.orange.opacity(0.8))
                        .textSelection(.enabled)
                        .lineLimit(20)
                }
            }
            .padding(4)
        } label: {
            Label("Request", systemImage: "arrow.up")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(.orange)
        }
    }

    private func responseDetail(flow: ProxyCapturedFlow, response: ProxyCapturedResponse) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 6) {
                Text("\(response.httpVersion) \(response.statusCode) \(response.reason)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(.cyan)
                    .textSelection(.enabled)

                headerRows(response.headers, color: .blue.opacity(0.8))

                if let body = response.bodyPreview {
                    Divider().background(Color.gray.opacity(0.3))
                    Text(body)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.cyan.opacity(0.8))
                        .textSelection(.enabled)
                        .lineLimit(30)
                }
            }
            .padding(4)
        } label: {
            Label("Response (\(formatDuration(response.duration)))", systemImage: "arrow.down")
                .font(.system(size: 10, weight: .medium))
                .foregroundColor(.cyan)
        }
    }

    private func errorDetail(_ error: String) -> some View {
        HStack {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.red)
            Text(error)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(.red.opacity(0.8))
        }
    }

    private func headerRows(_ headers: [[String]], color: Color) -> some View {
        ForEach(Array(headers.enumerated()), id: \.offset) { _, header in
            if header.count >= 2 {
                HStack(alignment: .top, spacing: 4) {
                    Text(header[0] + ":")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(color)
                    Text(header[1])
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.white.opacity(0.7))
                        .textSelection(.enabled)
                }
            }
        }
    }

    // MARK: - Formatting

    func formatBytes(_ bytes: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }

    func formatDuration(_ duration: TimeInterval) -> String {
        if duration < 1 {
            return String(format: "%.0fms", duration * 1000)
        }
        return String(format: "%.2fs", duration)
    }

    func formatTime(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "HH:mm:ss"
        return formatter.string(from: date)
    }
}
