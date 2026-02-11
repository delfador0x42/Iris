import SwiftUI
import AppKit

// MARK: - Hex Dump Logic

extension HTTPRawDetailView {

    static func hexDumpLines(_ data: Data.SubSequence) -> [String] {
        var lines: [String] = []
        let bytesPerLine = 16
        var offset = 0

        while offset < data.count {
            let end = min(offset + bytesPerLine, data.count)
            let chunk = data[data.startIndex + offset ..< data.startIndex + end]

            // Offset column
            var line = String(format: "%08x  ", offset)

            // Hex bytes
            for (i, byte) in chunk.enumerated() {
                line += String(format: "%02x ", byte)
                if i == 7 { line += " " }
            }

            // Pad if short line
            let missing = bytesPerLine - chunk.count
            for i in 0..<missing {
                line += "   "
                if chunk.count + i == 7 { line += " " }
            }

            // ASCII column
            line += " |"
            for byte in chunk {
                line += (byte >= 0x20 && byte < 0x7F) ? String(UnicodeScalar(byte)) : "."
            }
            line += "|"

            lines.append(line)
            offset = end
        }
        return lines
    }

    // MARK: - Text Analysis

    static func isPrintable(_ text: String) -> Bool {
        // Consider it printable if <5% of characters are control chars (excluding newline/tab/CR)
        let controlCount = text.unicodeScalars.filter { scalar in
            scalar.value < 0x20 && scalar.value != 0x0A && scalar.value != 0x0D && scalar.value != 0x09
        }.count
        return controlCount < max(1, text.count / 20)
    }

    // MARK: - Header Redaction

    static let sensitiveHeaders: Set<String> = [
        "authorization", "cookie", "set-cookie", "x-api-key",
        "x-auth-token", "proxy-authorization", "www-authenticate"
    ]

    static func redactSensitiveHeaders(_ text: String) -> String {
        text.components(separatedBy: "\r\n").map { line in
            guard let colonIndex = line.firstIndex(of: ":") else { return line }
            let name = line[..<colonIndex].trimmingCharacters(in: .whitespaces).lowercased()
            if sensitiveHeaders.contains(name) {
                return "\(line[..<colonIndex]): [REDACTED]"
            }
            return line
        }.joined(separator: "\r\n")
    }

    // MARK: - Clipboard

    func copyToClipboard() {
        var content = ""

        if let data = rawOutbound, !data.isEmpty {
            content += "=== REQUEST (\(ByteFormatter.format(UInt64(data.count)))) ===\n\n"
            content += String(data: data, encoding: .utf8) ?? "[binary data]"
            content += "\n\n"
        } else if let rawRequest = connection.httpRawRequest {
            content += "=== REQUEST HEADERS ===\n\n"
            content += Self.redactSensitiveHeaders(rawRequest)
            content += "\n\n"
        }

        if let data = rawInbound, !data.isEmpty {
            content += "=== RESPONSE (\(ByteFormatter.format(UInt64(data.count)))) ===\n\n"
            content += String(data: data, encoding: .utf8) ?? "[binary data]"
        } else if let rawResponse = connection.httpRawResponse {
            content += "=== RESPONSE HEADERS ===\n\n"
            content += Self.redactSensitiveHeaders(rawResponse)
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(content, forType: .string)
    }
}

// MARK: - Supporting Views

struct SectionHeader: View {
    let title: String
    let icon: String

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.system(size: 12))
            Text(title)
                .font(.system(size: 12, weight: .semibold))
        }
        .foregroundColor(.secondary)
    }
}

struct RawTextView: View {
    let text: String

    var body: some View {
        Text(text)
            .font(.system(size: 12, design: .monospaced))
            .textSelection(.enabled)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(12)
            .background(Color(nsColor: .textBackgroundColor).opacity(0.5))
            .cornerRadius(8)
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color.gray.opacity(0.2), lineWidth: 1)
            )
    }
}
