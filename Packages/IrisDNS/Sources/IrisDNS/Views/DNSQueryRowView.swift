import SwiftUI

// MARK: - DNS Query Row View

struct DNSQueryRowView: View {
    let query: DNSQueryRecord

    var body: some View {
        HStack(spacing: 10) {
            // Record type badge
            RecordTypeBadge(type: query.recordType)

            // Response status
            responseStatusView

            // Domain and answers
            VStack(alignment: .leading, spacing: 2) {
                Text(query.domain)
                    .font(.system(size: 12, weight: .medium))
                    .lineLimit(1)

                if !query.answers.isEmpty {
                    Text(query.answers.joined(separator: ", "))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.secondary)
                        .lineLimit(1)
                }
            }

            Spacer()

            // Process name
            if let process = query.processName {
                Text(process)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.secondary.opacity(0.1))
                    .cornerRadius(4)
            }

            // Flags
            HStack(spacing: 4) {
                if query.isEncrypted {
                    Image(systemName: "lock.fill")
                        .font(.system(size: 9))
                        .foregroundColor(.green)
                }
                if query.isBlocked {
                    Image(systemName: "xmark.shield.fill")
                        .font(.system(size: 9))
                        .foregroundColor(.red)
                }
            }

            // Latency
            if let latency = query.latencyMs {
                Text(String(format: "%.0fms", latency))
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundColor(latency < 50 ? .green : (latency < 100 ? .orange : .red))
            }
        }
        .padding(.vertical, 3)
    }

    @ViewBuilder
    private var responseStatusView: some View {
        if let code = query.responseCode {
            switch code {
            case "NOERROR":
                Text("OK")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.green)
                    .cornerRadius(4)
            case "NXDOMAIN":
                Text("NX")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.orange)
                    .cornerRadius(4)
            case "SERVFAIL":
                Text("FAIL")
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.red)
                    .cornerRadius(4)
            default:
                Text(code)
                    .font(.system(size: 10, weight: .semibold, design: .monospaced))
                    .foregroundColor(.white)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(Color.gray)
                    .cornerRadius(4)
            }
        } else {
            ProgressView()
                .scaleEffect(0.6)
                .frame(width: 30)
        }
    }
}
