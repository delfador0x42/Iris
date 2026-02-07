import SwiftUI

/// Displays dylib hijack scan results
public struct DylibHijackView: View {
    @State private var hijacks: [DylibHijack] = []
    @State private var isLoading = true
    @State private var scanTarget = ScanTarget.running
    @Environment(\.dismiss) private var dismiss

    enum ScanTarget: String, CaseIterable {
        case running = "Running Processes"
        case applications = "/Applications"
    }

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if isLoading { loadingView } else if hijacks.isEmpty { emptyView } else { resultList }
            }
        }
        .task { await scan() }
        .toolbar {
            ToolbarItem(placement: .navigation) { backButton }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Dylib Hijack Scanner")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                let active = hijacks.filter(\.isActiveHijack).count
                Text("\(hijacks.count) findings\(active > 0 ? " (\(active) active hijacks!)" : "")")
                    .font(.caption).foregroundColor(active > 0 ? .red : .gray)
            }
            Spacer()
            Picker("Target", selection: $scanTarget) {
                ForEach(ScanTarget.allCases, id: \.self) { Text($0.rawValue) }
            }
            .pickerStyle(.segmented)
            .frame(maxWidth: 250)
            .onChange(of: scanTarget) { _ in Task { await scan() } }
        }.padding(20)
    }

    private var resultList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(hijacks) { hijack in
                    HijackRow(hijack: hijack)
                }
            }.padding(.vertical, 8)
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48)).foregroundColor(.green)
            Text("No dylib hijacks detected").font(.headline).foregroundColor(.white)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text("Scanning binaries for dylib hijacks...")
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

    private func scan() async {
        isLoading = true
        let scanner = DylibHijackScanner.shared
        switch scanTarget {
        case .running:
            hijacks = await scanner.scanRunningProcesses()
        case .applications:
            hijacks = await scanner.scanDirectory("/Applications")
        }
        isLoading = false
    }
}

struct HijackRow: View {
    let hijack: DylibHijack
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: hijack.isActiveHijack ? "exclamationmark.triangle.fill" : "shield.lefthalf.filled")
                    .foregroundColor(hijack.isActiveHijack ? .red : .orange)
                    .frame(width: 20)

                VStack(alignment: .leading, spacing: 2) {
                    Text(hijack.binaryName)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(hijack.type.rawValue)
                        .font(.system(size: 10)).foregroundColor(.orange)
                }

                Spacer()

                Text(hijack.isActiveHijack ? "ACTIVE" : "Vulnerable")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(hijack.isActiveHijack ? .red : .yellow)
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background((hijack.isActiveHijack ? Color.red : Color.yellow).opacity(0.15))
                    .cornerRadius(4)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 4) {
                    detailRow("Binary", hijack.binaryPath)
                    detailRow("Dylib", hijack.dylibPath)
                    Text(hijack.details)
                        .font(.system(size: 11)).foregroundColor(.gray)
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(hijack.isActiveHijack ? Color.red.opacity(0.05) : Color.white.opacity(0.02))
    }

    private func detailRow(_ label: String, _ value: String) -> some View {
        HStack(spacing: 8) {
            Text(label).font(.system(size: 10, weight: .bold)).foregroundColor(.gray)
            Text(value).font(.system(size: 10, design: .monospaced)).foregroundColor(.white)
                .lineLimit(1)
        }
    }
}
