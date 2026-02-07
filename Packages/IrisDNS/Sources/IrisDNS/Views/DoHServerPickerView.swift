import SwiftUI

// MARK: - DoH Server Picker

struct DoHServerPickerView: View {
    @ObservedObject var store: DNSStore
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Text("DNS-over-HTTPS Server")
                    .font(.headline)
                Spacer()
                Button("Done") { dismiss() }
            }
            .padding()

            Divider()

            List {
                ForEach(DoHServerConfig.allServers) { server in
                    HStack {
                        VStack(alignment: .leading, spacing: 4) {
                            Text(server.name)
                                .font(.system(size: 13, weight: .medium))
                            Text(server.url)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.secondary)
                            Text("IPs: \(server.bootstrapIPs.prefix(2).joined(separator: ", "))")
                                .font(.system(size: 10))
                                .foregroundColor(.secondary)
                        }

                        Spacer()

                        if store.serverName == server.name {
                            Image(systemName: "checkmark.circle.fill")
                                .foregroundColor(.blue)
                        }
                    }
                    .contentShape(Rectangle())
                    .onTapGesture {
                        Task {
                            await store.setServer(server.name)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .frame(width: 450, height: 350)
    }
}
