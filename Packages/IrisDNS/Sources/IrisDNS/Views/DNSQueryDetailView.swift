//
//  DNSQueryDetailView.swift
//  IrisDNS
//
//  Detail view for a single DNS query showing full resolution details.
//

import SwiftUI

/// Detail view for a DNS query record.
struct DNSQueryDetailView: View {
    let query: DNSQueryRecord

    var body: some View {
        ThemedScrollView {
            VStack(alignment: .leading, spacing: 16) {
                // Header
                queryHeader

                Divider()

                // Query details
                GroupBox("Query") {
                    VStack(alignment: .leading, spacing: 8) {
                        DetailPair(label: "Domain", value: query.domain)
                        DetailPair(label: "Record Type", value: query.recordType)
                        DetailPair(label: "Timestamp", value: formatTimestamp(query.timestamp))
                        if let process = query.processName {
                            DetailPair(label: "Process", value: process)
                        }
                    }
                    .padding(.vertical, 4)
                }

                // Response details
                GroupBox("Response") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let code = query.responseCode {
                            HStack {
                                Text("Response Code")
                                    .foregroundColor(.secondary)
                                    .frame(width: 110, alignment: .leading)
                                responseCodeBadge(code)
                                Text(code)
                                    .font(.system(size: 12, design: .monospaced))
                            }
                        }

                        if !query.answers.isEmpty {
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Answers")
                                    .foregroundColor(.secondary)
                                ForEach(Array(query.answers.enumerated()), id: \.offset) { _, answer in
                                    Text(answer)
                                        .font(.system(size: 12, design: .monospaced))
                                        .textSelection(.enabled)
                                        .padding(.leading, 110)
                                }
                            }
                        } else {
                            DetailPair(label: "Answers", value: "None")
                        }

                        if let ttl = query.ttl {
                            DetailPair(label: "TTL", value: formatTTL(ttl))
                        }

                        if let latency = query.latencyMs {
                            HStack {
                                Text("Latency")
                                    .foregroundColor(.secondary)
                                    .frame(width: 110, alignment: .leading)
                                Text(String(format: "%.1fms", latency))
                                    .font(.system(size: 12, design: .monospaced))
                                    .foregroundColor(latency < 50 ? .green : (latency < 100 ? .orange : .red))
                            }
                        }
                    }
                    .padding(.vertical, 4)
                }

                // Security info
                GroupBox("Security") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Encrypted")
                                .foregroundColor(.secondary)
                                .frame(width: 110, alignment: .leading)
                            Image(systemName: query.isEncrypted ? "lock.fill" : "lock.open.fill")
                                .foregroundColor(query.isEncrypted ? .green : .red)
                            Text(query.isEncrypted ? "Yes (DoH)" : "No (plaintext)")
                                .font(.system(size: 12))
                        }
                        HStack {
                            Text("Blocked")
                                .foregroundColor(.secondary)
                                .frame(width: 110, alignment: .leading)
                            Image(systemName: query.isBlocked ? "xmark.shield.fill" : "checkmark.shield.fill")
                                .foregroundColor(query.isBlocked ? .red : .green)
                            Text(query.isBlocked ? "Yes" : "No")
                                .font(.system(size: 12))
                        }
                    }
                    .padding(.vertical, 4)
                }

                // Actions
                HStack {
                    Button(action: copyDomain) {
                        Label("Copy Domain", systemImage: "doc.on.doc")
                    }

                    if !query.answers.isEmpty {
                        Button(action: copyAnswers) {
                            Label("Copy Answers", systemImage: "doc.on.doc")
                        }
                    }
                }
            }
            .padding()
        }
        .background(Color(NSColor.controlBackgroundColor))
    }

    // MARK: - Header

    private var queryHeader: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                RecordTypeBadge(type: query.recordType)

                if let code = query.responseCode {
                    responseCodeBadge(code)
                }

                Spacer()

                HStack(spacing: 8) {
                    if query.isEncrypted {
                        Image(systemName: "lock.fill")
                            .foregroundColor(.green)
                            .help("Encrypted via DoH")
                    }
                    if query.isBlocked {
                        Image(systemName: "xmark.shield.fill")
                            .foregroundColor(.red)
                            .help("Blocked")
                    }
                }
            }

            Text(query.domain)
                .font(.system(size: 14, weight: .medium, design: .monospaced))
                .textSelection(.enabled)

            if !query.answers.isEmpty {
                Text(query.answers.first ?? "")
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundColor(.secondary)
                    .textSelection(.enabled)
            }
        }
        .padding(.bottom, 4)
    }

    // MARK: - Helpers

    @ViewBuilder
    private func responseCodeBadge(_ code: String) -> some View {
        let color: Color = {
            switch code {
            case "NOERROR": return .green
            case "NXDOMAIN": return .orange
            case "SERVFAIL": return .red
            case "REFUSED": return .red
            default: return .gray
            }
        }()

        Text(code)
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color)
            .cornerRadius(4)
    }

    private func copyDomain() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(query.domain, forType: .string)
    }

    private func copyAnswers() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(query.answers.joined(separator: "\n"), forType: .string)
    }

    private func formatTimestamp(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss.SSS"
        return formatter.string(from: date)
    }

    private func formatTTL(_ ttl: UInt32) -> String {
        if ttl >= 3600 {
            return "\(ttl)s (\(ttl / 3600)h \((ttl % 3600) / 60)m)"
        } else if ttl >= 60 {
            return "\(ttl)s (\(ttl / 60)m \(ttl % 60)s)"
        } else {
            return "\(ttl)s"
        }
    }
}

// MARK: - Detail Pair

struct DetailPair: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top) {
            Text(label)
                .foregroundColor(.secondary)
                .frame(width: 110, alignment: .leading)
            Text(value)
                .font(.system(size: 12, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}

// MARK: - Preview

#Preview {
    DNSQueryDetailView(
        query: DNSQueryRecord(
            domain: "api.apple.com",
            recordType: "A",
            processName: "Safari",
            responseCode: "NOERROR",
            answers: ["17.253.144.10", "17.253.144.11"],
            ttl: 3600,
            latencyMs: 23.5,
            isBlocked: false,
            isEncrypted: true
        )
    )
    .frame(width: 400, height: 600)
}
