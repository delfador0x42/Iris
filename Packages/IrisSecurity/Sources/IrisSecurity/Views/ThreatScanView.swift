import SwiftUI

/// Comprehensive threat scanning view that runs all security scanners
/// and presents findings organized by severity.
public struct ThreatScanView: View {
  @State private var anomalies: [ProcessAnomaly] = []
  @State private var supplyChainFindings: [SupplyChainFinding] = []
  @State private var fsChanges: [FileSystemChange] = []
  @State private var isLoading = true
  @State private var scanPhase = ""
  @State private var scanProgress: Double = 0
  @State private var showCriticalOnly = false

  public init() {}

  public var body: some View {
    ZStack {
      darkBackground
      VStack(spacing: 0) {
        header
        if isLoading {
          scanningView
        } else if allFindingsEmpty {
          cleanView
        } else {
          findingsList
        }
      }
    }
    .task { await runFullScan() }
  }

  private var allFindingsEmpty: Bool {
    filteredAnomalies.isEmpty && filteredSupplyChain.isEmpty && filteredFSChanges.isEmpty
  }

  private var filteredAnomalies: [ProcessAnomaly] {
    showCriticalOnly ? anomalies.filter { $0.severity >= .high } : anomalies
  }

  private var filteredSupplyChain: [SupplyChainFinding] {
    showCriticalOnly ? supplyChainFindings.filter { $0.severity >= .high } : supplyChainFindings
  }

  private var filteredFSChanges: [FileSystemChange] {
    showCriticalOnly ? fsChanges.filter { $0.severity >= .high } : fsChanges
  }

  private var totalFindings: Int {
    anomalies.count + supplyChainFindings.count + fsChanges.count
  }

  private var header: some View {
    HStack {
      VStack(alignment: .leading, spacing: 4) {
        Text("Threat Scanner")
          .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
        if !isLoading {
          let critical =
            anomalies.filter { $0.severity == .critical }.count
            + fsChanges.filter { $0.severity == .critical }.count
          let high =
            anomalies.filter { $0.severity == .high }.count
            + supplyChainFindings.filter { $0.severity == .high }.count
            + fsChanges.filter { $0.severity == .high }.count
          HStack(spacing: 12) {
            Text("\(totalFindings) findings")
              .font(.caption).foregroundColor(.gray)
            if critical > 0 {
              Text("\(critical) critical").font(.caption).foregroundColor(.red)
            }
            if high > 0 {
              Text("\(high) high").font(.caption).foregroundColor(.orange)
            }
          }
        }
      }
      Spacer()
      if !isLoading {
        Toggle("Critical+", isOn: $showCriticalOnly)
          .toggleStyle(.switch)
          .foregroundColor(.white).font(.system(size: 11))
        Button(action: { Task { await runFullScan() } }) {
          Image(systemName: "arrow.clockwise").foregroundColor(.blue)
        }.buttonStyle(.plain)
      }
    }.padding(20)
  }

  private var findingsList: some View {
    ThemedScrollView {
      LazyVStack(alignment: .leading, spacing: 2) {
        if !filteredAnomalies.isEmpty {
          sectionHeader("Process & System Anomalies", count: filteredAnomalies.count)
          ForEach(filteredAnomalies) { anomaly in
            AnomalyRow(anomaly: anomaly)
          }
        }
        if !filteredFSChanges.isEmpty {
          sectionHeader("Filesystem Changes", count: filteredFSChanges.count)
          ForEach(filteredFSChanges) { change in
            FSChangeRow(change: change)
          }
        }
        if !filteredSupplyChain.isEmpty {
          sectionHeader("Supply Chain", count: filteredSupplyChain.count)
          ForEach(filteredSupplyChain) { finding in
            SupplyChainRow(finding: finding)
          }
        }
      }.padding(.vertical, 8)
    }
  }

  private func sectionHeader(_ title: String, count: Int) -> some View {
    HStack {
      Text(title).font(.system(size: 11, weight: .semibold)).foregroundColor(.cyan)
      Text("(\(count))").font(.system(size: 10)).foregroundColor(.gray)
      Spacer()
    }
    .padding(.horizontal, 20).padding(.top, 12).padding(.bottom, 4)
  }

  private var scanningView: some View {
    VStack(spacing: 16) {
      ProgressView(value: scanProgress)
        .tint(.cyan).frame(width: 200)
      Text(scanPhase)
        .font(.system(size: 14)).foregroundColor(.gray)
        .animation(.easeInOut, value: scanPhase)
    }.frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var cleanView: some View {
    VStack(spacing: 16) {
      Image(systemName: "checkmark.shield.fill")
        .font(.system(size: 48)).foregroundColor(.green)
      Text("No threats detected").font(.headline).foregroundColor(.white)
      Text("All 15 scans passed")
        .font(.caption).foregroundColor(.gray)
    }.frame(maxWidth: .infinity, maxHeight: .infinity)
  }

  private var darkBackground: some View {
    LinearGradient(
      colors: [
        Color(red: 0.02, green: 0.03, blue: 0.05),
        Color(red: 0.05, green: 0.07, blue: 0.1),
      ],
      startPoint: .top, endPoint: .bottom
    ).ignoresSafeArea()
  }

  private func runFullScan() async {
    isLoading = true
    let totalPhases: Double = 15

    // Single process snapshot shared across all PID-based scanners
    scanPhase = "Capturing process state"
    scanProgress = 0
    let snapshot = ProcessSnapshot.capture()

    // Fire ALL scanners concurrently
    scanPhase = "Running 15 scanners"
    scanProgress = 0.05

    async let r1 = LOLBinDetector.shared.scan(snapshot: snapshot)
    async let r2 = StealthScanner.shared.scanAll(snapshot: snapshot)
    async let r3a = XPCServiceAuditor.shared.scanXPCServices()
    async let r3b = XPCServiceAuditor.shared.scanMachServices()
    let connections = await MainActor.run { SecurityStore.shared.connections }
    async let r4 = NetworkAnomalyDetector.shared.scanConnections(connections)
    async let r5 = ProcessIntegrityChecker.shared.scan(snapshot: snapshot)
    async let r6 = CredentialAccessDetector.shared.scan(snapshot: snapshot)
    async let r7 = KextAnomalyDetector.shared.scan()
    async let r8 = AuthorizationDBMonitor.shared.scan()
    async let r9 = DyldEnvDetector.shared.scan(snapshot: snapshot)
    async let r10 = PersistenceScanner.shared.scanAll()
    async let r11 = EventTapScanner.shared.scan()
    async let r12 = DylibHijackScanner.shared.scanRunningProcesses(snapshot: snapshot)
    async let r13 = TCCMonitor.shared.scan()
    async let r14 = SupplyChainAuditor.shared.auditAll()
    async let r15 = FileSystemBaseline.shared.diff()

    // Collect results — each await resolves when that scanner finishes
    var all: [ProcessAnomaly] = []
    var phase: Double = 0
    func tick(_ label: String) {
      phase += 1
      scanPhase = label
      scanProgress = phase / totalPhases
    }

    tick("LOLBin activity")
    all.append(contentsOf: await r1)
    tick("Stealth persistence")
    all.append(contentsOf: await r2)
    tick("XPC services")
    all.append(contentsOf: await r3a)
    all.append(contentsOf: await r3b)
    tick("Network anomalies")
    all.append(
      contentsOf: (await r4).map { na in
        ProcessAnomaly(
          pid: 0, processName: na.processName, processPath: "",
          parentPID: 0, parentName: "",
          technique: na.type.rawValue,
          description: na.description, severity: na.severity
        )
      })
    tick("Process integrity")
    all.append(contentsOf: await r5)
    tick("Credential access")
    all.append(contentsOf: await r6)
    tick("Kernel extensions")
    all.append(contentsOf: await r7)
    tick("Authorization database")
    all.append(contentsOf: await r8)
    tick("DYLD injection")
    all.append(contentsOf: await r9)
    tick("Persistence locations")
    all.append(
      contentsOf: (await r10).filter(\.isSuspicious).map { item in
        ProcessAnomaly(
          pid: 0, processName: item.name, processPath: item.path,
          parentPID: 0, parentName: "",
          technique: "Suspicious \(item.type.rawValue)",
          description: item.suspicionReasons.joined(separator: "; "),
          severity: item.signingStatus == .unsigned ? .high : .medium,
          mitreID: "T1547"
        )
      })
    tick("Event taps")
    all.append(
      contentsOf: (await r11).filter(\.isSuspicious).map { tap in
        ProcessAnomaly(
          pid: tap.tappingPID, processName: tap.tappingProcessName,
          processPath: tap.tappingProcessPath,
          parentPID: 0, parentName: "",
          technique: "Suspicious Event Tap",
          description: tap.suspicionReasons.joined(separator: "; "),
          severity: tap.isKeyboardTap ? .high : .medium,
          mitreID: "T1056.001"
        )
      })
    tick("Dylib hijacking")
    all.append(
      contentsOf: (await r12).filter(\.isActiveHijack).map { h in
        ProcessAnomaly(
          pid: 0, processName: h.binaryName, processPath: h.binaryPath,
          parentPID: 0, parentName: "",
          technique: h.type.rawValue,
          description: h.details, severity: .high, mitreID: "T1574.004"
        )
      })
    tick("TCC permissions")
    all.append(
      contentsOf: (await r13).filter(\.isSuspicious).map { entry in
        ProcessAnomaly(
          pid: 0, processName: entry.client, processPath: "",
          parentPID: 0, parentName: "",
          technique: "Suspicious TCC Grant",
          description: entry.suspicionReason ?? "Suspicious permission: \(entry.serviceName)",
          severity: .high, mitreID: "T1005"
        )
      })
    tick("Supply chain")
    let scFindings = await r14
    tick("Filesystem integrity")
    let fsResult = await r15

    anomalies = all.sorted { $0.severity > $1.severity }
    supplyChainFindings = scFindings
    fsChanges = fsResult
    isLoading = false
  }
}
