import SwiftUI

/// Shows TCC permission grants and flags suspicious entries.
/// SIP blocks system TCC.db — only user-level entries are readable.
public struct TCCMonitorView: View {
    @State private var entries: [TCCEntry] = []
    @State private var isLoading = true
    @State private var showSuspiciousOnly = false
    @State private var errorMessage: String?

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if isLoading {
                    loadingView
                } else if let error = errorMessage {
                    errorView(error)
                } else if filteredEntries.isEmpty {
                    emptyView
                } else {
                    entryList
                }
            }
        }
        .task { await loadEntries() }
    }

    private var filteredEntries: [TCCEntry] {
        showSuspiciousOnly ? entries.filter(\.isSuspicious) : entries
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("TCC Permissions")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                HStack(spacing: 12) {
                    Text("\(entries.count) entries").font(.caption).foregroundColor(.gray)
                    let suspicious = entries.filter(\.isSuspicious).count
                    if suspicious > 0 {
                        Text("\(suspicious) suspicious").font(.caption).foregroundColor(.red)
                    }
                }
            }
            Spacer()
            Toggle("Suspicious", isOn: $showSuspiciousOnly)
                .toggleStyle(.switch).foregroundColor(.white).font(.system(size: 11))
            Button(action: { Task { await loadEntries() } }) {
                Image(systemName: "arrow.clockwise").foregroundColor(.blue)
            }.buttonStyle(.plain)
        }.padding(20)
    }

    private var entryList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(filteredEntries) { entry in
                    TCCEntryRow(entry: entry)
                }
            }.padding(.vertical, 8)
        }
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text("Reading TCC database...").font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func errorView(_ message: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "lock.shield").font(.system(size: 48)).foregroundColor(.orange)
            Text("Limited Access").font(.headline).foregroundColor(.white)
            Text(message).font(.caption).foregroundColor(.gray).multilineTextAlignment(.center)
        }.frame(maxWidth: .infinity, maxHeight: .infinity).padding(40)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill").font(.system(size: 48)).foregroundColor(.green)
            Text("No suspicious permissions").font(.headline).foregroundColor(.white)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private func loadEntries() async {
        isLoading = true
        errorMessage = nil
        let result = await TCCMonitor.shared.scan()
        if result.isEmpty {
            errorMessage = "SIP blocks system TCC.db on modern macOS. User-level TCC.db may also require Full Disk Access."
        }
        entries = result
        isLoading = false
    }
}

struct TCCEntryRow: View {
    let entry: TCCEntry

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: entry.isAllowed ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundColor(entry.isAllowed ? (entry.isSuspicious ? .red : .green) : .gray)
                .frame(width: 20)
            VStack(alignment: .leading, spacing: 2) {
                Text(entry.serviceName)
                    .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                Text(entry.client)
                    .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    .lineLimit(1)
            }
            Spacer()
            Text(entry.reasonName)
                .font(.system(size: 10)).foregroundColor(.gray)
            if entry.isSuspicious {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.orange).font(.system(size: 12))
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(entry.isSuspicious ? Color.red.opacity(0.05) : Color.white.opacity(0.02))
    }
}
