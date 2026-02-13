import SwiftUI

/// Searchable list of installed packages grouped by source
public struct PackageInventoryView: View {
    @State private var packages: [InstalledPackage] = []
    @State private var isLoading = true
    @State private var searchText = ""
    @State private var selectedSource: PackageSource?
    public init() {}

    public var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.03, blue: 0.05),
                    Color(red: 0.05, green: 0.07, blue: 0.1)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                header
                filterBar
                if isLoading {
                    loadingView
                } else {
                    packageList
                }
            }
        }
        .task { await loadPackages() }
    }

    private var filteredPackages: [InstalledPackage] {
        var result = packages
        if let source = selectedSource {
            result = result.filter { $0.source == source }
        }
        if !searchText.isEmpty {
            result = result.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                ($0.bundleId?.localizedCaseInsensitiveContains(searchText) ?? false)
            }
        }
        return result.sorted { $0.name.lowercased() < $1.name.lowercased() }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Package Inventory")
                    .font(.system(size: 20, weight: .bold))
                    .foregroundColor(.white)
                Text("\(packages.count) packages installed")
                    .font(.caption)
                    .foregroundColor(.gray)
            }
            Spacer()
            // Source counts
            HStack(spacing: 12) {
                ForEach(PackageSource.allCases, id: \.self) { source in
                    let count = packages.filter { $0.source == source }.count
                    if count > 0 {
                        VStack(spacing: 2) {
                            Text("\(count)")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundColor(.white)
                            Text(source.rawValue)
                                .font(.system(size: 9))
                                .foregroundColor(.gray)
                        }
                    }
                }
            }
        }
        .padding(20)
    }

    private var filterBar: some View {
        HStack(spacing: 12) {
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.gray)
                TextField("Search packages...", text: $searchText)
                    .textFieldStyle(.plain)
                    .foregroundColor(.white)
            }
            .padding(8)
            .background(Color.white.opacity(0.1))
            .cornerRadius(8)
            .frame(maxWidth: 300)

            ForEach(PackageSource.allCases, id: \.self) { source in
                Button(action: {
                    selectedSource = selectedSource == source ? nil : source
                }) {
                    Text(source.rawValue)
                        .font(.system(size: 11))
                        .padding(.horizontal, 10)
                        .padding(.vertical, 5)
                        .background(selectedSource == source ? Color.blue.opacity(0.3) : Color.white.opacity(0.1))
                        .foregroundColor(selectedSource == source ? .blue : .white)
                        .cornerRadius(5)
                }
                .buttonStyle(.plain)
            }

            Spacer()
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 8)
        .background(Color.black.opacity(0.2))
    }

    private var packageList: some View {
        ThemedScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(filteredPackages) { pkg in
                    HStack(spacing: 12) {
                        Text(pkg.source.rawValue)
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(sourceColor(pkg.source))
                            .frame(width: 80, alignment: .leading)

                        Text(pkg.name)
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.white)

                        Spacer()

                        if let version = pkg.version {
                            Text(version)
                                .font(.system(size: 11, design: .monospaced))
                                .foregroundColor(.gray)
                                .lineLimit(1)
                        }
                    }
                    .padding(.horizontal, 20)
                    .padding(.vertical, 6)
                    .background(Color.white.opacity(0.02))
                }
            }
            .padding(.vertical, 8)
        }
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text("Scanning installed packages...").font(.system(size: 14)).foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private func sourceColor(_ source: PackageSource) -> Color {
        switch source {
        case .homebrew: return .orange
        case .appStore: return .blue
        case .pkgutil: return .purple
        case .application: return .green
        }
    }

    private func loadPackages() async {
        isLoading = true
        packages = await PackageInventory.shared.scan()
        isLoading = false
    }
}
