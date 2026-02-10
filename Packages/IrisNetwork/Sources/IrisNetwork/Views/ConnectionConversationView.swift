import SwiftUI
import AppKit

/// Full conversation view for a network connection.
/// Shows timestamped back-and-forth traffic in chronological order.
struct ConnectionConversationView: View {
    let connection: NetworkConnection
    var onDismiss: () -> Void = {}

    @EnvironmentObject private var store: SecurityStore
    @State private var segments: [CaptureSegment] = []
    @State private var isLoading = true
    @State private var autoScroll = true

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "HH:mm:ss.SSS"
        return f
    }()

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().background(Color.gray.opacity(0.3))
            toolbarRow
            Divider().background(Color.gray.opacity(0.3))
            conversationBody
        }
        .background(Color(red: 0.04, green: 0.05, blue: 0.08))
        .task { await loadConversation() }
    }

    // MARK: - Header

    private var header: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    Text(connection.processName)
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.white)

                    Text("pid \(connection.processId)")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundColor(.gray)
                }

                HStack(spacing: 6) {
                    Text(connection.remoteEndpoint)
                        .font(.system(size: 13, design: .monospaced))
                        .foregroundColor(.cyan)
                        .textSelection(.enabled)

                    Text(connection.protocol.rawValue)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(.gray)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Color.white.opacity(0.1))
                        .cornerRadius(3)

                    Text(connection.state.rawValue)
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(stateColor)
                }

                if let hostname = connection.remoteHostname {
                    Text(hostname)
                        .font(.system(size: 11))
                        .foregroundColor(.gray)
                }
            }

            Spacer()

            Button("Close") { onDismiss() }
                .foregroundColor(.blue)
        }
        .padding(16)
    }

    // MARK: - Toolbar

    private var toolbarRow: some View {
        HStack(spacing: 16) {
            HStack(spacing: 12) {
                Label("\(segments.count) segments", systemImage: "arrow.left.arrow.right")
                Label(formatTotalBytes(.outbound), systemImage: "arrow.up")
                    .foregroundColor(.orange)
                Label(formatTotalBytes(.inbound), systemImage: "arrow.down")
                    .foregroundColor(.cyan)
            }
            .font(.system(size: 11))
            .foregroundColor(.gray)

            Spacer()

            Button {
                Task { await loadConversation() }
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .foregroundColor(.gray)
            .help("Refresh")

            Button {
                copyConversationToClipboard()
            } label: {
                Image(systemName: "doc.on.doc")
                    .font(.system(size: 11))
            }
            .buttonStyle(.plain)
            .foregroundColor(.gray)
            .help("Copy to clipboard")
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.3))
    }

    // MARK: - Conversation Body

    @ViewBuilder
    private var conversationBody: some View {
        if isLoading {
            VStack(spacing: 12) {
                ProgressView().tint(.white)
                Text("Loading conversation...")
                    .font(.system(size: 13))
                    .foregroundColor(.gray)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if segments.isEmpty {
            VStack(spacing: 12) {
                Image(systemName: "waveform.slash")
                    .font(.system(size: 36))
                    .foregroundColor(.gray.opacity(0.5))
                Text("No captured data")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundColor(.gray)
                Text("Traffic may be encrypted or data was evicted")
                    .font(.system(size: 12))
                    .foregroundColor(.gray.opacity(0.7))
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(segments.enumerated()), id: \.offset) { index, segment in
                            segmentRow(segment: segment)
                                .id(index)
                        }
                    }
                    .padding(.vertical, 8)
                }
                .onChange(of: segments.count) { _, newCount in
                    if autoScroll, newCount > 0 {
                        proxy.scrollTo(newCount - 1, anchor: .bottom)
                    }
                }
            }
        }
    }

    // MARK: - Segment Row

    private func segmentRow(segment: CaptureSegment) -> some View {
        let isOut = segment.direction == .outbound
        let color: Color = isOut ? .orange : .cyan

        return VStack(alignment: .leading, spacing: 0) {
            // Header: timestamp + direction + size
            HStack(spacing: 8) {
                Text(Self.timeFormatter.string(from: segment.timestamp))
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.7))

                Text(isOut ? ">" : "<")
                    .font(.system(size: 10, weight: .bold, design: .monospaced))
                    .foregroundColor(color)

                Text(isOut ? "OUT" : "IN")
                    .font(.system(size: 9, weight: .bold, design: .monospaced))
                    .foregroundColor(color)

                Text("[\(Self.formatBytes(segment.byteCount))]")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.6))

                Spacer()
            }
            .padding(.horizontal, 12)
            .padding(.top, 6)
            .padding(.bottom, 2)

            // Data content
            dataContentView(data: segment.data, color: color)
                .padding(.horizontal, 12)
                .padding(.bottom, 4)
        }
        .background(isOut ? Color.orange.opacity(0.03) : Color.cyan.opacity(0.03))
    }

    @ViewBuilder
    private func dataContentView(data: Data, color: Color) -> some View {
        let text = String(data: data, encoding: .utf8)

        if let text, Self.isPrintable(text) {
            Text(text)
                .font(.system(size: 11, design: .monospaced))
                .foregroundColor(color.opacity(0.9))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        } else {
            hexDumpView(data: data, color: color)
        }
    }

    private func hexDumpView(data: Data, color: Color) -> some View {
        let lines = Self.buildHexLines(data.prefix(4096))
        return VStack(alignment: .leading, spacing: 0) {
            ForEach(Array(lines.enumerated()), id: \.offset) { _, line in
                Text(line)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(color.opacity(0.7))
            }
            if data.count > 4096 {
                Text("... +\(Self.formatBytes(data.count - 4096)) truncated")
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.gray.opacity(0.5))
                    .padding(.top, 2)
            }
        }
        .textSelection(.enabled)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    // MARK: - Actions

    private func loadConversation() async {
        isLoading = true
        segments = await store.fetchConversation(for: connection.id)
        isLoading = false
    }

    private func formatTotalBytes(_ direction: CaptureSegment.Direction) -> String {
        let total = segments.filter { $0.direction == direction }.reduce(0) { $0 + $1.byteCount }
        return NetworkConnection.formatBytes(UInt64(total))
    }

    private func copyConversationToClipboard() {
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

    private var stateColor: Color {
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
