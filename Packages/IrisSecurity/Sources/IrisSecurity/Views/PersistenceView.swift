import SwiftUI

/// Displays all persistence items found on the system (KnockKnock-style)
public struct PersistenceView: View {
    @State private var items: [PersistenceItem] = []
    @State private var isLoading = true
    @State private var searchText = ""
    @State private var showSuspiciousOnly = false
    @State private var selectedType: PersistenceType?
    @Environment(\.dismiss) private var dismiss

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                filterBar
                if isLoading {
                    loadingView
                } else {
                    itemList
                }
            }
        }
        .task { await loadItems() }
        .toolbar {
            ToolbarItem(placement: .navigation) { backButton }
        }
    }

    private var filteredItems: [PersistenceItem] {
        var result = items
        if showSuspiciousOnly { result = result.filter(\.isSuspicious) }
        if let type = selectedType { result = result.filter { $0.type == type } }
        if !searchText.isEmpty {
            result = result.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.path.localizedCaseInsensitiveContains(searchText)
            }
        }
        return result
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Persistence Scan")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(.white)
                HStack(spacing: 12) {
                    Text("\(items.count) items")
                        .font(.caption).foregroundColor(.gray)
                    let suspicious = items.filter(\.isSuspicious).count
                    if suspicious > 0 {
                        Text("\(suspicious) suspicious")
                            .font(.caption).foregroundColor(.red)
                    }
                }
            }
            Spacer()
            Button(action: { Task { await loadItems() } }) {
                Image(systemName: "arrow.clockwise")
                    .foregroundColor(.blue)
            }.buttonStyle(.plain)
        }
        .padding(20)
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            HStack {
                Image(systemName: "magnifyingglass").foregroundColor(.gray)
                TextField("Search...", text: $searchText)
                    .textFieldStyle(.plain).foregroundColor(.white)
            }
            .padding(8)
            .background(Color.white.opacity(0.1))
            .cornerRadius(8)
            .frame(maxWidth: 300)

            Toggle("Suspicious", isOn: $showSuspiciousOnly)
                .toggleStyle(.switch)
                .foregroundColor(.white)
                .font(.system(size: 11))

            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.2))
    }

    private var itemList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(filteredItems) { item in
                    PersistenceItemRow(item: item)
                }
            }.padding(.vertical, 8)
        }
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text("Scanning persistence locations...")
                .font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private var backButton: some View {
        Button(action: { dismiss() }) {
            HStack(spacing: 4) {
                Image(systemName: "chevron.left")
                Text("Back")
            }.foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
        }
    }

    private func loadItems() async {
        isLoading = true
        items = await PersistenceScanner.shared.scanAll()
        isLoading = false
    }
}

struct PersistenceItemRow: View {
    let item: PersistenceItem
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: item.type.icon)
                    .foregroundColor(item.isSuspicious ? .red : .gray)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(item.name)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.white)
                    Text(item.path)
                        .font(.system(size: 10, design: .monospaced))
                        .foregroundColor(.gray)
                        .lineLimit(1)
                }

                Spacer()

                Text(item.signingStatus.rawValue)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(signingColor)
                    .padding(.horizontal, 6)
                    .padding(.vertical, 2)
                    .background(signingColor.opacity(0.15))
                    .cornerRadius(4)

                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .foregroundColor(.gray)
                    .font(.system(size: 10))
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    if let binary = item.binaryPath {
                        detailRow("Binary", binary)
                    }
                    if let sigId = item.signingIdentifier {
                        detailRow("Signing ID", sigId)
                    }
                    ForEach(item.suspicionReasons, id: \.self) { reason in
                        HStack(spacing: 6) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.orange).font(.system(size: 10))
                            Text(reason)
                                .font(.system(size: 11)).foregroundColor(.orange)
                        }
                    }
                }
                .padding(.horizontal, 50)
                .padding(.bottom, 8)
            }
        }
        .background(item.isSuspicious ? Color.red.opacity(0.05) : Color.white.opacity(0.02))
    }

    private var signingColor: Color {
        switch item.signingStatus {
        case .apple, .appStore: return .green
        case .devID: return .blue
        case .adHoc: return .orange
        case .unsigned, .invalid: return .red
        case .unknown: return .gray
        }
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack(spacing: 8) {
            Text(label).font(.system(size: 10, weight: .bold)).foregroundColor(.gray)
            Text(value).font(.system(size: 10, design: .monospaced)).foregroundColor(.white)
        }
    }
}
