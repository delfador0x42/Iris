import SwiftUI

/// Compact sidebar: search + module list + scanner status dots.
struct SecuritySidebar: View {
  @Binding var selectedModule: SecurityModule?
  @ObservedObject var session: ScanSession
  @State private var searchText = ""

  var body: some View {
    VStack(spacing: 0) {
      moduleList
      Divider().overlay(Color.cyan.opacity(0.15))
      scannerDots
    }
    .background(Color(red: 0.02, green: 0.03, blue: 0.06))
  }

  // MARK: - Module List

  private var moduleList: some View {
    List(selection: $selectedModule) {
      Section {
        ForEach(filteredModules) { module in
          moduleRow(module)
            .tag(module)
        }
      } header: {
        TextField("Filter", text: $searchText)
          .textFieldStyle(.plain)
          .font(.system(size: 11, design: .monospaced))
          .foregroundColor(.white)
          .padding(6)
          .background(Color.white.opacity(0.05))
          .cornerRadius(6)
          .padding(.bottom, 4)
      }
    }
    .listStyle(.sidebar)
    .scrollContentBackground(.hidden)
  }

  private func moduleRow(_ module: SecurityModule) -> some View {
    HStack(spacing: 8) {
      Image(systemName: module.icon)
        .font(.system(size: 12))
        .foregroundColor(module.accentColor)
        .frame(width: 18)
      Text(module.rawValue)
        .font(.system(size: 11, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.9))
      Spacer()
      findingsBadge(for: module)
    }
    .padding(.vertical, 1)
  }

  @ViewBuilder
  private func findingsBadge(for module: SecurityModule) -> some View {
    let count = findingsCount(for: module)
    if count > 0 {
      Text("\(count)")
        .font(.system(size: 9, weight: .bold, design: .monospaced))
        .foregroundColor(.white)
        .padding(.horizontal, 5).padding(.vertical, 1)
        .background(badgeColor(for: module).opacity(0.7))
        .cornerRadius(4)
    }
  }

  private var filteredModules: [SecurityModule] {
    guard !searchText.isEmpty else { return SecurityModule.allCases }
    let q = searchText.lowercased()
    return SecurityModule.allCases.filter {
      $0.rawValue.lowercased().contains(q) || $0.subtitle.lowercased().contains(q)
    }
  }

  // MARK: - Scanner Dots (compact)

  private var scannerDots: some View {
    VStack(spacing: 4) {
      ScannerStatusGrid(session: session)
    }
    .padding(12)
  }

  // MARK: - Badge helpers

  private func findingsCount(for module: SecurityModule) -> Int {
    guard let r = session.scanResult else { return 0 }
    switch module {
    case .threatScan: return r.anomalies.count
    case .supplyChain: return r.supplyChainFindings.count
    case .fileIntegrity: return r.fsChanges.count
    default: return 0
    }
  }

  private func badgeColor(for module: SecurityModule) -> Color {
    guard let r = session.scanResult else { return .gray }
    switch module {
    case .threatScan: return r.criticalCount > 0 ? .red : .orange
    case .supplyChain: return .green
    case .fileIntegrity: return .cyan
    default: return .gray
    }
  }
}
