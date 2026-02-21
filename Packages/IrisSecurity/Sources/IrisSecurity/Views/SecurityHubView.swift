import SwiftUI

/// Security command center — sidebar + streaming results.
/// Auto-runs full scan on appear. Findings are the main view.
public struct SecurityHubView: View {
  @State private var selectedModule: SecurityModule?
  @StateObject private var session = ScanSession()
  @State private var showTiming = false

  public init() {}

  public var body: some View {
    NavigationSplitView {
      SecuritySidebar(
        selectedModule: $selectedModule,
        session: session
      )
    } detail: {
      ZStack {
        gridBackground
        if let module = selectedModule {
          moduleView(for: module)
        } else {
          ScanResultsView(session: session)
        }
      }
    }
    .toolbar { toolbarContent }
    .task { await autoScan() }
  }

  // MARK: - Toolbar

  @ToolbarContentBuilder
  private var toolbarContent: some ToolbarContent {
    ToolbarItem(placement: .navigation) {
      HStack(spacing: 8) {
        Image(systemName: "shield.lefthalf.filled")
          .foregroundColor(.cyan)
        if session.isScanning {
          ProgressView().controlSize(.small).tint(.cyan)
          Text("\(session.completed)/\(session.total)")
            .font(.system(size: 11, weight: .bold, design: .monospaced))
            .foregroundColor(.cyan)
          if !session.latestScanner.isEmpty {
            Text(session.latestScanner)
              .font(.system(size: 10, design: .monospaced))
              .foregroundColor(.gray)
          }
        } else if let r = session.scanResult {
          statusIcon(r)
          Text(r.totalFindings == 0 ? "Clean" : "\(r.totalFindings) findings")
            .font(.system(size: 11, weight: .bold, design: .monospaced))
            .foregroundColor(r.totalFindings == 0 ? .green : .orange)
          Text("\(r.scannerCount) engines \u{00B7} \(String(format: "%.1fs", r.scanDuration))")
            .font(.system(size: 10, design: .monospaced))
            .foregroundColor(.gray)
        }
      }
    }
    ToolbarItemGroup(placement: .primaryAction) {
      Button(action: { withAnimation { showTiming.toggle() } }) {
        Image(systemName: "clock")
          .foregroundColor(showTiming ? .cyan : .gray.opacity(0.5))
      }
      .help("Scanner timing")
      .popover(isPresented: $showTiming) {
        if !session.scannerResults.isEmpty {
          ScannerTimingView(results: session.scannerResults)
            .padding(12).frame(width: 280)
        }
      }

      if session.allowlistSuppressedCount > 0 {
        Text("\(session.allowlistSuppressedCount) suppressed")
          .font(.system(size: 9, design: .monospaced))
          .foregroundColor(.gray.opacity(0.5))
      }

      exportMenu

      Button(action: { Task { await session.runScan() } }) {
        Image(systemName: "arrow.clockwise")
      }
      .help("Rescan")
      .disabled(session.isScanning)
    }
  }

  private var exportMenu: some View {
    Menu {
      Button("Export as JSON") { exportReport(session.currentResult, format: .json) }
      Button("Export as HTML") { exportReport(session.currentResult, format: .html) }
    } label: {
      Image(systemName: "square.and.arrow.up")
    }
    .help("Export report")
    .disabled(session.scannerResults.isEmpty)
  }

  @ViewBuilder
  private func statusIcon(_ r: ThreatScanResult) -> some View {
    Image(systemName: r.totalFindings == 0
      ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
      .foregroundColor(r.totalFindings == 0 ? .green : .orange)
  }

  // MARK: - Module Views

  @ViewBuilder
  private func moduleView(for module: SecurityModule) -> some View {
    switch module {
    case .liveDetection: DetectionView()
    case .threatScan: ThreatScanView()
    case .persistence: PersistenceView()
    case .eventTaps: EventTapView()
    case .dylibHijack: DylibHijackView()
    case .fileIntegrity: FileIntegrityView()
    case .supplyChain: SupplyChainView()
    case .securityPosture: SecurityDashboardView()
    case .packageInventory: PackageInventoryView()
    case .avMonitor: AVMonitorView()
    case .tccPermissions: TCCMonitorView()
    case .ransomware: RansomwareCheckView()
    case .allowlist: AllowlistView()
    case .contradictionProbes: ProbeEngineView()
    }
  }

  // MARK: - Scan Logic

  private func autoScan() async {
    await session.loadCached()
    if session.scanResult == nil { await session.runScan() }
  }

  private func exportReport(
    _ result: ThreatScanResult, format: ScanReportExporter.ExportFormat
  ) {
    if let url = ScanReportExporter.save(result, format: format) {
      NSWorkspace.shared.selectFile(url.path, inFileViewerRootedAtPath: "")
    }
  }

  // MARK: - Background

  private var gridBackground: some View {
    ZStack {
      Color(red: 0.01, green: 0.02, blue: 0.04)
      Canvas { context, size in
        let gs: CGFloat = 40
        var path = Path()
        stride(from: CGFloat(0), to: size.width, by: gs).forEach { x in
          path.move(to: CGPoint(x: x, y: 0))
          path.addLine(to: CGPoint(x: x, y: size.height))
        }
        stride(from: CGFloat(0), to: size.height, by: gs).forEach { y in
          path.move(to: CGPoint(x: 0, y: y))
          path.addLine(to: CGPoint(x: size.width, y: y))
        }
        context.stroke(path, with: .color(.cyan.opacity(0.03)), lineWidth: 0.5)
      }
    }.ignoresSafeArea()
  }
}
