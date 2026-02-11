import SwiftUI
import AppKit

// MARK: - Clipboard & Static Helpers

extension ConnectionConversationView {

    func copyConversationToClipboard() {
        var text = "Connection: \(connection.processName) → \(connection.remoteEndpoint)\n"
        text += "Protocol: \(connection.protocol.rawValue) | State: \(connection.state.rawValue)\n"
        text += String(repeating: "─", count: 72) + "\n\n"

        for segment in segments {
            let time = Self.timeFormatter.string(from: segment.timestamp)
            let dir = segment.direction == .outbound ? ">>>" : "<<<"
            let label = segment.direction == .outbound ? "OUT" : "IN"
            text += "[\(time)] \(dir) \(label) (\(segment.byteCount) bytes)\n"

            if let str = String(data: segment.data, encoding: .utf8),
               Self.isPrintable(str) {
                text += str
            } else {
                text += "[binary data: \(segment.byteCount) bytes]\n"
            }
            if !text.hasSuffix("\n") { text += "\n" }
            text += "\n"
        }

        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    var stateColor: Color {
        switch connection.state {
        case .established: return .green
        case .listen: return .blue
        case .closed: return .gray
        default: return .orange
        }
    }

    // MARK: - Static Helpers

    static func isPrintable(_ text: String) -> Bool {
        let controlCount = text.unicodeScalars.filter {
            $0.value < 32 && $0.value != 10 && $0.value != 13 && $0.value != 9
        }.count
        return controlCount < max(1, text.count / 20)
    }

    static func formatBytes(_ bytes: Int) -> String {
        if bytes < 1024 { return "\(bytes) B" }
        if bytes < 1024 * 1024 { return String(format: "%.1f KB", Double(bytes) / 1024) }
        return String(format: "%.1f MB", Double(bytes) / (1024 * 1024))
    }

    static func buildHexLines(_ data: Data) -> [String] {
        var lines: [String] = []
        let bytes = Array(data)
        var offset = 0
        while offset < bytes.count {
            let chunk = Array(bytes[offset..<min(offset + 16, bytes.count)])
            let hex = chunk.map { String(format: "%02x", $0) }
                .enumerated()
                .map { $0.offset == 8 ? " " + $0.element : $0.element }
                .joined(separator: " ")
            let ascii = chunk.map { (0x20...0x7e).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
            let padded = hex.padding(toLength: 49, withPad: " ", startingAt: 0)
            lines.append(String(format: "%08x  %@  |%@|", offset, padded, ascii))
            offset += 16
        }
        return lines
    }
}
