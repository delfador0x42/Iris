import SwiftUI

/// Security command center — Tron-style brutalist interface.
/// Entry point to all security scanning, monitoring, and auditing capabilities.
/// Auto-runs full scan on appear with live streaming progress via ScanSession.
public struct SecurityHubView: View {
  @State private var selectedModule: SecurityModule?
  @StateObject private var session = ScanSession()
  @State private var showTiming = false

  public init() {}

  public var body: some View {
    ZStack {
      gridBackground
      if let module = selectedModule {
        VStack(spacing: 0) {
          backButton
          moduleView(for: module)
        }
      } else {
        VStack(spacing: 0) {
          hubHeader
          fullScanBanner
          moduleGrid
        }
      }
    }
    .task { await autoScan() }
  }

  // MARK: - Header

  private var hubHeader: some View {
    VStack(spacing: 8) {
      HStack(spacing: 12) {
        Image(systemName: "shield.lefthalf.filled")
          .font(.system(size: 28))
          .foregroundStyle(
            LinearGradient(
              colors: [Color.cyan, Color.cyan.opacity(0.5)],
              startPoint: .top, endPoint: .bottom))
        VStack(alignment: .leading, spacing: 2) {
          Text("SECURITY")
            .font(.system(size: 24, weight: .black, design: .monospaced))
            .foregroundColor(.white).tracking(6)
          Text("50 DETECTION ENGINES")
            .font(.system(size: 10, weight: .medium, design: .monospaced))
            .foregroundColor(.cyan.opacity(0.7)).tracking(2)
        }
        Spacer()
      }
      .padding(.horizontal, 24).padding(.top, 20)
      Rectangle()
        .fill(LinearGradient(
          colors: [.clear, .cyan.opacity(0.3), .cyan.opacity(0.3), .clear],
          startPoint: .leading, endPoint: .trailing))
        .frame(height: 1)
        .padding(.horizontal, 20).padding(.top, 4)
    }
  }

  // MARK: - Full Scan Banner

  private var fullScanBanner: some View {
    VStack(spacing: 8) {
      Button(action: { Task { await session.runScan() } }) {
        HStack(spacing: 12) {
          if session.isScanning {
            ProgressView().controlSize(.small).tint(.cyan)
            Text("Scanning \(session.completed)/\(session.total)...")
              .font(.system(size: 12, weight: .medium, design: .monospaced))
              .foregroundColor(.cyan)
          } else if let r = session.scanResult {
            Image(systemName: r.totalFindings == 0
              ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
              .foregroundColor(r.totalFindings == 0 ? .green : .orange)
            VStack(alignment: .leading, spacing: 2) {
              Text(r.totalFindings == 0 ? "System Clean" : "\(r.totalFindings) findings")
                .font(.system(size: 12, weight: .bold, design: .monospaced))
                .foregroundColor(r.totalFindings == 0 ? .green : .orange)
              HStack(spacing: 4) {
                Text("\(r.scannerCount) engines \u{00B7} \(String(format: "%.1f", r.scanDuration))s \u{00B7} \(timeAgo(r.timestamp))")
                  .font(.system(size: 9, design: .monospaced)).foregroundColor(.gray)
                if !r.correlations.isEmpty {
                  Text("\u{00B7} \(r.correlations.count) correlated")
                    .font(.system(size: 9, weight: .bold, design: .monospaced)).foregroundColor(.red)
                }
              }
            }
          } else {
            Image(systemName: "play.fill").foregroundColor(.cyan)
            Text("Run Full Scan")
              .font(.system(size: 12, weight: .medium, design: .monospaced))
              .foregroundColor(.cyan)
          }
          Spacer()
          if !session.isScanning {
            Image(systemName: "arrow.clockwise")
              .font(.system(size: 12)).foregroundColor(.gray.opacity(0.5))
          }
        }
        .padding(12)
        .background(
          RoundedRectangle(cornerRadius: 8).fill(Color.cyan.opacity(0.05))
            .overlay(RoundedRectangle(cornerRadius: 8)
              .strokeBorder(Color.cyan.opacity(0.2), lineWidth: 1)))
      }
      .buttonStyle(.plain).disabled(session.isScanning)

      // Scanner status grid
      if session.isScanning || session.scanResult != nil {
        ScannerStatusGrid(session: session).padding(.horizontal, 4)
      }

      // Export button
      if let r = session.scanResult, !session.isScanning {
        HStack(spacing: 8) {
          Button(action: { exportReport(r, format: .json) }) {
            Label("JSON", systemImage: "doc.text")
              .font(.system(size: 9, weight: .medium, design: .monospaced))
              .foregroundColor(.gray.opacity(0.6))
          }.buttonStyle(.plain)
          Button(action: { exportReport(r, format: .html) }) {
            Label("HTML", systemImage: "doc.richtext")
              .font(.system(size: 9, weight: .medium, design: .monospaced))
              .foregroundColor(.gray.opacity(0.6))
          }.buttonStyle(.plain)
          Spacer()
          if session.allowlistSuppressedCount > 0 {
            Text("\(session.allowlistSuppressedCount) suppressed")
              .font(.system(size: 9, design: .monospaced))
              .foregroundColor(.gray.opacity(0.4))
          }
        }
      }

      // Timing toggle
      if !session.scannerResults.isEmpty && !session.isScanning {
        Button(action: { withAnimation { showTiming.toggle() } }) {
          Text(showTiming ? "Hide timing" : "Show timing")
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.gray.opacity(0.5))
        }.buttonStyle(.plain)
        if showTiming {
          ScannerTimingView(results: session.scannerResults)
        }
      }
    }
    .padding(.horizontal, 20).padding(.top, 12)
  }

  // MARK: - Module Grid + Views

  private var moduleGrid: some View {
    ThemedScrollView {
      LazyVGrid(
        columns: [
          GridItem(.flexible(), spacing: 12),
          GridItem(.flexible(), spacing: 12),
          GridItem(.flexible(), spacing: 12),
        ], spacing: 12
      ) {
        ForEach(SecurityModule.allCases) { module in
          ModuleCard(module: module) { selectedModule = module }
        }
      }.padding(20)
    }
  }

  private var backButton: some View {
    HStack {
      Button(action: {
        withAnimation(.easeInOut(duration: 0.2)) { selectedModule = nil }
      }) {
        HStack(spacing: 4) {
          Image(systemName: "chevron.left")
          Text("Security")
        }
        .foregroundColor(.cyan).font(.system(size: 13, weight: .medium))
      }.buttonStyle(.plain)
      Spacer()
    }
    .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 4)
  }

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

  private func timeAgo(_ date: Date) -> String {
    let s = Int(Date().timeIntervalSince(date))
    if s < 60 { return "just now" }
    if s < 3600 { return "\(s / 60)m ago" }
    return "\(s / 3600)h ago"
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
