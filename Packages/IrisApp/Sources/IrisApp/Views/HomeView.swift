import SwiftUI

enum MenuDestination: String, CaseIterable {
  case securityAssessment = "Security"
  case processList = "Processes"
  case networkMonitor = "Network"
  case proxyMonitor = "Proxy"
  case wifiMonitor = "WiFi"
  case statistics = "Disk"
  case settings = "Settings"
}

/// Unified live dashboard — immediate value, no launcher tiles.
/// NieR Automata × Tron: monospaced, geometric, data-dense, cyan on black.
public struct HomeView: View {
  @StateObject private var ext = ExtensionManager.shared
  @State private var path = NavigationPath()

  // Actor snapshots (polled every 3s)
  @State private var alertCounts: [AnomalySeverity: Int] = [:]
  @State private var recentAlerts: [SecurityAlert] = []
  @State private var probeResults: [ProbeResult] = []

  public init() {}

  public var body: some View {
    NavigationStack(path: $path) {
      ZStack {
        gridBG
        VStack(spacing: 0) {
          permissionBar
          statusBar
          panelGrid
        }
      }
      .navigationDestination(for: MenuDestination.self) { d in
        switch d {
        case .securityAssessment: SecurityHubView()
        case .processList: ProcessListView()
        case .networkMonitor: NetworkMonitorView()
        case .proxyMonitor: ProxyMonitorView()
        case .wifiMonitor: WiFiMonitorView()
        case .statistics: DiskUsageView()
        case .settings: SettingsView()
        }
      }
    }
    .task { await poll() }
  }

  private func nav(_ d: MenuDestination) { path.append(d) }

  private func poll() async {
    while !Task.isCancelled {
      alertCounts = await AlertStore.shared.countBySeverity()
      recentAlerts = await AlertStore.shared.recent(10)
      probeResults = await ContradictionEngine.shared.results()
      try? await Task.sleep(nanoseconds: 3_000_000_000)
    }
  }
}

// MARK: - Permission Bar

extension HomeView {
  @ViewBuilder
  private var permissionBar: some View {
    let issues = permissionIssues
    if !issues.isEmpty {
      HStack(spacing: 8) {
        Text(issues.joined(separator: "  \u{00B7}  "))
          .font(.system(size: 10, design: .monospaced))
        Spacer()
        Button("FIX") { openPrivacy() }
          .font(.system(size: 9, weight: .bold, design: .monospaced))
          .foregroundColor(.black)
          .padding(.horizontal, 10).padding(.vertical, 3)
          .background(Color.orange)
      }
      .foregroundColor(.orange)
      .padding(.horizontal, 20).padding(.vertical, 6)
      .background(Color.orange.opacity(0.06))
    }
  }

  private var permissionIssues: [String] {
    var out: [String] = []
    if !ext.hasFullDiskAccess { out.append("Full Disk Access required") }
    if !ext.isEndpointExtensionReady { out.append("Endpoint extension offline") }
    if !ext.isNetworkExtensionReady { out.append("Network extension offline") }
    return out
  }

  private func openPrivacy() {
    if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy") {
      NSWorkspace.shared.open(u)
    }
  }
}

// MARK: - Status Bar

extension HomeView {
  private var statusBar: some View {
    let crit = alertCounts[.critical] ?? 0
    let high = alertCounts[.high] ?? 0
    let total = alertCounts.values.reduce(0, +)

    return HStack(spacing: 16) {
      statusDot(ext.isEndpointExtensionReady, "ES")
      statusDot(ext.isNetworkExtensionReady, "NET")

      Spacer()

      Text("I R I S")
        .font(.system(size: 13, weight: .thin, design: .monospaced))
        .foregroundColor(.white.opacity(0.35))

      Spacer()

      if total > 0 {
        if crit > 0 {
          Text("\(crit)")
            .font(.system(size: 12, weight: .bold, design: .monospaced))
            .foregroundColor(.red) +
          Text(" CRIT")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.red.opacity(0.5))
        }
        if high > 0 {
          Text("  \(high)")
            .font(.system(size: 12, weight: .bold, design: .monospaced))
            .foregroundColor(.orange) +
          Text(" HIGH")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.orange.opacity(0.5))
        }
      }

      Button { nav(.settings) } label: {
        Image(systemName: "gearshape")
          .font(.system(size: 11))
          .foregroundColor(.white.opacity(0.2))
      }
      .buttonStyle(.plain)
    }
    .padding(.horizontal, 20).padding(.vertical, 10)
    .background(Color.white.opacity(0.015))
  }

  private func statusDot(_ on: Bool, _ label: String) -> some View {
    HStack(spacing: 4) {
      Circle().fill(on ? Color.cyan.opacity(0.7) : Color.red.opacity(0.5))
        .frame(width: 5, height: 5)
      Text(label)
        .font(.system(size: 9, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.25))
    }
  }
}

// MARK: - Panel Grid

extension HomeView {
  private var panelGrid: some View {
    VStack(spacing: 1) {
      HStack(spacing: 1) {
        threatsPanel
        processesPanel
      }
      HStack(spacing: 1) {
        networkPanel
        probesPanel
      }
      livePanel
    }
    .padding(1)
  }
}

// MARK: - Threats

extension HomeView {
  private var threatsPanel: some View {
    let crit = alertCounts[.critical] ?? 0
    let high = alertCounts[.high] ?? 0
    let med = alertCounts[.medium] ?? 0
    let low = alertCounts[.low] ?? 0
    let total = crit + high + med + low

    return panel("THREATS", dest: .securityAssessment) {
      if total == 0 {
        Text("No detections")
          .font(.system(size: 11, design: .monospaced))
          .foregroundColor(.white.opacity(0.15))
      } else {
        VStack(alignment: .leading, spacing: 5) {
          sevBar("CRITICAL", crit, Color(red: 1, green: 0.2, blue: 0.2))
          sevBar("HIGH", high, .orange)
          sevBar("MEDIUM", med, .yellow.opacity(0.7))
          sevBar("LOW", low, .cyan.opacity(0.4))
        }
        Spacer()
        Text("\(total)")
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.white.opacity(0.15))
      }
    }
  }

  private func sevBar(_ label: String, _ n: Int, _ color: Color) -> some View {
    HStack(spacing: 6) {
      RoundedRectangle(cornerRadius: 1)
        .fill(n > 0 ? color : color.opacity(0.08))
        .frame(width: max(4, CGFloat(min(n, 60)) * 1.5), height: 8)
      if n > 0 {
        Text("\(n)")
          .font(.system(size: 12, weight: .bold, design: .monospaced))
          .foregroundColor(color)
      }
      Text(label)
        .font(.system(size: 8, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(n > 0 ? 0.4 : 0.1))
      Spacer()
    }
  }
}

// MARK: - Processes

extension HomeView {
  private var processesPanel: some View {
    let ps = ProcessStore.shared
    let total = ps.processes.count
    let suspect = ps.suspiciousCount
    let top = ps.processes.filter(\.isSuspicious).prefix(5)

    return panel("PROCESSES", dest: .processList) {
      HStack(spacing: 20) {
        bigNum(total, "total", .cyan.opacity(0.5))
        if suspect > 0 { bigNum(suspect, "suspect", .orange) }
        Spacer()
      }

      if !top.isEmpty {
        VStack(alignment: .leading, spacing: 3) {
          ForEach(Array(top), id: \.pid) { p in
            VStack(alignment: .leading, spacing: 1) {
              HStack(spacing: 4) {
                Text(p.name)
                  .font(.system(size: 10, weight: .medium, design: .monospaced))
                  .foregroundColor(.white.opacity(0.6))
                Text("\(p.pid)")
                  .font(.system(size: 9, design: .monospaced))
                  .foregroundColor(.white.opacity(0.2))
                Spacer()
                if let r = p.suspicionReasons.first {
                  Text(r.rawValue)
                    .font(.system(size: 8, design: .monospaced))
                    .foregroundColor(.orange.opacity(0.6))
                }
              }
              if p.arguments.count > 1 {
                Text(p.arguments.dropFirst().joined(separator: " "))
                  .font(.system(size: 9, design: .monospaced))
                  .foregroundColor(.cyan.opacity(0.3))
                  .lineLimit(1).truncationMode(.tail)
              }
            }
          }
        }
      }
      Spacer()
    }
  }
}

// MARK: - Network

extension HomeView {
  private var networkPanel: some View {
    let net = SecurityStore.shared
    let conns = net.connections.count
    let countries = net.uniqueCountries.count

    return panel("NETWORK", dest: .networkMonitor) {
      HStack(spacing: 20) {
        bigNum(conns, "conn", .cyan.opacity(0.5))
        if countries > 0 { bigNum(countries, "countries", .white.opacity(0.4)) }
        Spacer()
      }
      HStack(spacing: 16) {
        stat("up", fmtBytes(net.totalBytesUp))
        stat("dn", fmtBytes(net.totalBytesDown))
        Spacer()
      }
      Spacer()
    }
  }

  private func fmtBytes(_ b: UInt64) -> String {
    if b < 1024 { return "\(b) B" }
    if b < 1_048_576 { return "\(b / 1024) KB" }
    if b < 1_073_741_824 { return String(format: "%.1f MB", Double(b) / 1_048_576) }
    return String(format: "%.1f GB", Double(b) / 1_073_741_824)
  }
}

// MARK: - Probes

extension HomeView {
  private var probesPanel: some View {
    let total = probeResults.count
    let clean = probeResults.filter { $0.verdict == .consistent }.count
    let contras = probeResults.filter { $0.verdict == .contradiction }

    return panel("PROBES", dest: .securityAssessment) {
      HStack(spacing: 20) {
        bigNum(total, "total", .cyan.opacity(0.5))
        bigNum(clean, "clean", .green.opacity(0.5))
        if !contras.isEmpty {
          bigNum(contras.count, "CONTRA", Color(red: 1, green: 0.2, blue: 0.2))
        }
        Spacer()
      }
      if !contras.isEmpty {
        VStack(alignment: .leading, spacing: 2) {
          ForEach(contras) { p in
            HStack(spacing: 4) {
              Circle().fill(Color(red: 1, green: 0.2, blue: 0.2))
                .frame(width: 4, height: 4)
              Text(p.probeName)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.5))
            }
          }
        }
      }
      Spacer()
    }
  }
}

// MARK: - Live Alerts

extension HomeView {
  private var livePanel: some View {
    panel("LIVE", dest: .securityAssessment) {
      if recentAlerts.isEmpty {
        Text("Monitoring...")
          .font(.system(size: 10, design: .monospaced))
          .foregroundColor(.white.opacity(0.12))
      } else {
        VStack(alignment: .leading, spacing: 2) {
          ForEach(recentAlerts.prefix(8), id: \.id) { a in
            HStack(spacing: 6) {
              Text(fmt(a.timestamp))
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.white.opacity(0.15))
              Circle().fill(sevColor(a.severity))
                .frame(width: 4, height: 4)
              Text(a.name)
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.white.opacity(0.5))
                .lineLimit(1)
              Spacer()
              Text(a.processName)
                .font(.system(size: 9, design: .monospaced))
                .foregroundColor(.white.opacity(0.2))
                .lineLimit(1)
              if !a.mitreId.isEmpty {
                Text(a.mitreId)
                  .font(.system(size: 8, weight: .medium, design: .monospaced))
                  .foregroundColor(.cyan.opacity(0.25))
              }
            }
          }
        }
      }
    }
  }

  private func fmt(_ d: Date) -> String {
    let f = DateFormatter()
    f.dateFormat = "HH:mm"
    return f.string(from: d)
  }

  private func sevColor(_ s: AnomalySeverity) -> Color {
    switch s {
    case .critical: return Color(red: 1, green: 0.2, blue: 0.2)
    case .high: return .orange
    case .medium: return .yellow.opacity(0.7)
    case .low: return .cyan.opacity(0.4)
    }
  }
}

// MARK: - Shared Components

extension HomeView {
  private func panel<C: View>(
    _ title: String, dest: MenuDestination, @ViewBuilder content: () -> C
  ) -> some View {
    VStack(alignment: .leading, spacing: 8) {
      Text(title)
        .font(.system(size: 9, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.2))
        .tracking(3)
      content()
    }
    .padding(14)
    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
    .background(Color.white.opacity(0.018))
    .overlay(Rectangle().strokeBorder(Color.white.opacity(0.04), lineWidth: 0.5))
    .contentShape(Rectangle())
    .onTapGesture { nav(dest) }
  }

  private func bigNum(_ n: Int, _ label: String, _ color: Color) -> some View {
    VStack(alignment: .leading, spacing: 0) {
      Text("\(n)")
        .font(.system(size: 24, weight: .ultraLight, design: .monospaced))
        .foregroundColor(color)
      Text(label)
        .font(.system(size: 8, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.2))
    }
  }

  private func stat(_ label: String, _ value: String) -> some View {
    HStack(spacing: 4) {
      Text(label)
        .font(.system(size: 9, design: .monospaced))
        .foregroundColor(.white.opacity(0.15))
      Text(value)
        .font(.system(size: 10, weight: .medium, design: .monospaced))
        .foregroundColor(.white.opacity(0.4))
    }
  }

  private var gridBG: some View {
    ZStack {
      Color(red: 0.01, green: 0.01, blue: 0.025)
      Canvas { ctx, size in
        let gs: CGFloat = 40
        var p = Path()
        stride(from: CGFloat(0), to: size.width, by: gs).forEach { x in
          p.move(to: .init(x: x, y: 0))
          p.addLine(to: .init(x: x, y: size.height))
        }
        stride(from: CGFloat(0), to: size.height, by: gs).forEach { y in
          p.move(to: .init(x: 0, y: y))
          p.addLine(to: .init(x: size.width, y: y))
        }
        ctx.stroke(p, with: .color(.cyan.opacity(0.018)), lineWidth: 0.5)
      }
    }.ignoresSafeArea()
  }
}
