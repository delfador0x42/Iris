import SwiftUI

/// Forensic scan for encrypted/ransomware-encrypted files using entropy analysis.
/// Uses EntropyAnalyzer (Shannon entropy + chi-square + Monte Carlo PI).
public struct RansomwareCheckView: View {
    @State private var results: [(path: String, entropy: Double)] = []
    @State private var isScanning = false
    @State private var scanPhase = ""
    @State private var selectedDir: ScanDirectory = .desktop

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                dirPicker
                if isScanning {
                    scanningView
                } else if results.isEmpty {
                    emptyView
                } else {
                    resultList
                }
            }
        }
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Ransomware Check")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                Text("Entropy analysis for encrypted files")
                    .font(.caption).foregroundColor(.gray)
            }
            Spacer()
            if !isScanning {
                Button(action: { Task { await runScan() } }) {
                    Text("Scan").font(.system(size: 12, weight: .bold))
                        .padding(.horizontal, 16).padding(.vertical, 6)
                        .background(Color.red.opacity(0.3))
                        .foregroundColor(.white).cornerRadius(6)
                }.buttonStyle(.plain)
            }
        }.padding(20)
    }

    private var dirPicker: some View {
        HStack(spacing: 8) {
            ForEach(ScanDirectory.allCases, id: \.self) { dir in
                Button(action: { selectedDir = dir }) {
                    Text(dir.rawValue).font(.system(size: 11))
                        .padding(.horizontal, 10).padding(.vertical, 5)
                        .background(selectedDir == dir ? Color.red.opacity(0.3) : Color.white.opacity(0.1))
                        .foregroundColor(selectedDir == dir ? .red : .white)
                        .cornerRadius(5)
                }.buttonStyle(.plain)
            }
            Spacer()
            if !results.isEmpty {
                Text("\(results.count) high-entropy files")
                    .font(.system(size: 11)).foregroundColor(.orange)
            }
        }
        .padding(.horizontal, 20).padding(.vertical, 8)
        .background(Color.black.opacity(0.2))
    }

    private var resultList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 1) {
                ForEach(Array(results.enumerated()), id: \.offset) { _, item in
                    HStack(spacing: 10) {
                        Image(systemName: "lock.fill")
                            .foregroundColor(.red).frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(URL(fileURLWithPath: item.path).lastPathComponent)
                                .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                            Text(item.path)
                                .font(.system(size: 10, design: .monospaced))
                                .foregroundColor(.gray).lineLimit(1)
                        }
                        Spacer()
                        Text(String(format: "%.2f bits", item.entropy))
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.orange)
                    }
                    .padding(.horizontal, 20).padding(.vertical, 8)
                    .background(Color.red.opacity(0.05))
                }
            }.padding(.vertical, 8)
        }
    }

    private var scanningView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
            Text(scanPhase).font(.system(size: 14)).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 48)).foregroundColor(.green)
            Text("No encrypted files found").font(.headline).foregroundColor(.white)
            Text("Select a directory and tap Scan")
                .font(.caption).foregroundColor(.gray)
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    private var darkBackground: some View {
        LinearGradient(
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private func runScan() async {
        isScanning = true
        scanPhase = "Scanning \(selectedDir.rawValue)..."
        results = await RansomwareDetector.shared.scanDirectoryForEncryptedFiles(selectedDir.path)
        isScanning = false
    }
}

enum ScanDirectory: String, CaseIterable {
    case desktop = "Desktop"
    case documents = "Documents"
    case downloads = "Downloads"

    var path: String {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        switch self {
        case .desktop: return "\(home)/Desktop"
        case .documents: return "\(home)/Documents"
        case .downloads: return "\(home)/Downloads"
        }
    }
}
