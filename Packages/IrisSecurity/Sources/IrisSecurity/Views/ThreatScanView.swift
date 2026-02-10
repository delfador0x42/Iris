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
                    let critical = anomalies.filter { $0.severity == .critical }.count
                        + fsChanges.filter { $0.severity == .critical }.count
                    let high = anomalies.filter { $0.severity == .high }.count
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
        ScrollView {
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
            colors: [Color(red: 0.02, green: 0.03, blue: 0.05),
                     Color(red: 0.05, green: 0.07, blue: 0.1)],
            startPoint: .top, endPoint: .bottom
        ).ignoresSafeArea()
    }

    private func runFullScan() async {
        isLoading = true
        var all: [ProcessAnomaly] = []
        let totalPhases: Double = 15

        scanPhase = "LOLBin activity"
        scanProgress = 1 / totalPhases
        all.append(contentsOf: await LOLBinDetector.shared.scan())

        scanPhase = "Stealth persistence"
        scanProgress = 2 / totalPhases
        all.append(contentsOf: await StealthScanner.shared.scanAll())

        scanPhase = "XPC services"
        scanProgress = 3 / totalPhases
        all.append(contentsOf: await XPCServiceAuditor.shared.scanXPCServices())
        all.append(contentsOf: await XPCServiceAuditor.shared.scanMachServices())

        scanPhase = "Network anomalies"
        scanProgress = 4 / totalPhases
        let netAnomalies = await NetworkAnomalyDetector.shared.scanCurrentConnections()
        all.append(contentsOf: netAnomalies.map { na in
            ProcessAnomaly(
                pid: 0, processName: na.processName, processPath: "",
                parentPID: 0, parentName: "",
                technique: na.type.rawValue,
                description: na.description,
                severity: na.severity
            )
        })

        scanPhase = "Process integrity"
        scanProgress = 5 / totalPhases
        all.append(contentsOf: await ProcessIntegrityChecker.shared.scan())

        scanPhase = "Credential access"
        scanProgress = 6 / totalPhases
        all.append(contentsOf: await CredentialAccessDetector.shared.scan())

        scanPhase = "Kernel extensions"
        scanProgress = 7 / totalPhases
        all.append(contentsOf: await KextAnomalyDetector.shared.scan())

        scanPhase = "Authorization database"
        scanProgress = 8 / totalPhases
        all.append(contentsOf: await AuthorizationDBMonitor.shared.scan())

        scanPhase = "DYLD injection"
        scanProgress = 9 / totalPhases
        all.append(contentsOf: await DyldEnvDetector.shared.scan())

        scanPhase = "Persistence locations"
        scanProgress = 10 / totalPhases
        let persistenceItems = await PersistenceScanner.shared.scanAll()
        all.append(contentsOf: persistenceItems.filter(\.isSuspicious).map { item in
            ProcessAnomaly(
                pid: 0, processName: item.name, processPath: item.path,
                parentPID: 0, parentName: "",
                technique: "Suspicious \(item.type.rawValue)",
                description: item.suspicionReasons.joined(separator: "; "),
                severity: item.signingStatus == .unsigned ? .high : .medium,
                mitreID: "T1547"
            )
        })

        scanPhase = "Event taps"
        scanProgress = 11 / totalPhases
        let taps = await EventTapScanner.shared.scan()
        all.append(contentsOf: taps.filter(\.isSuspicious).map { tap in
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

        scanPhase = "Dylib hijacking"
        scanProgress = 12 / totalPhases
        let hijacks = await DylibHijackScanner.shared.scanRunningProcesses()
        all.append(contentsOf: hijacks.filter(\.isActiveHijack).map { h in
            ProcessAnomaly(
                pid: 0, processName: h.binaryName, processPath: h.binaryPath,
                parentPID: 0, parentName: "",
                technique: h.type.rawValue,
                description: h.details,
                severity: .high, mitreID: "T1574.004"
            )
        })

        scanPhase = "TCC permissions"
        scanProgress = 13 / totalPhases
        let tccEntries = await TCCMonitor.shared.scan()
        all.append(contentsOf: tccEntries.filter(\.isSuspicious).map { entry in
            ProcessAnomaly(
                pid: 0, processName: entry.client, processPath: "",
                parentPID: 0, parentName: "",
                technique: "Suspicious TCC Grant",
                description: entry.suspicionReason ?? "Suspicious permission: \(entry.serviceName)",
                severity: .high, mitreID: "T1005"
            )
        })

        scanPhase = "Supply chain"
        scanProgress = 14 / totalPhases
        let scFindings = await SupplyChainAuditor.shared.auditAll()

        scanPhase = "Filesystem integrity"
        scanProgress = 15 / totalPhases
        let fsResult = await FileSystemBaseline.shared.diff()

        anomalies = all.sorted { $0.severity > $1.severity }
        supplyChainFindings = scFindings
        fsChanges = fsResult
        isLoading = false
    }
}

// MARK: - Anomaly Row

struct AnomalyRow: View {
    let anomaly: ProcessAnomaly
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: anomaly.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(anomaly.technique)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(anomaly.processName)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                if let mitre = anomaly.mitreID {
                    MITREBadge(id: mitre)
                }
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(anomaly.description)
                        .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    if !anomaly.processPath.isEmpty {
                        Text("Path: \(anomaly.processPath)")
                            .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    }
                    if anomaly.pid > 0 {
                        Text("PID: \(anomaly.pid) | Parent: \(anomaly.parentName) (\(anomaly.parentPID))")
                            .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                    }
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(anomaly.severity))
    }
}

// MARK: - Filesystem Change Row

struct FSChangeRow: View {
    let change: FileSystemChange
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: change.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(change.changeType.rawValue)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(URL(fileURLWithPath: change.path).lastPathComponent)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                changeIcon
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                VStack(alignment: .leading, spacing: 6) {
                    Text(change.details)
                        .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    Text(change.path)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(change.severity))
    }

    private var changeIcon: some View {
        Image(systemName: iconForType)
            .font(.system(size: 10))
            .foregroundColor(colorForType)
    }

    private var iconForType: String {
        switch change.changeType {
        case .created: return "plus.circle"
        case .modified: return "pencil.circle"
        case .deleted: return "trash.circle"
        case .permissionsChanged: return "lock.circle"
        }
    }

    private var colorForType: Color {
        switch change.changeType {
        case .created: return .green
        case .modified: return .orange
        case .deleted: return .red
        case .permissionsChanged: return .yellow
        }
    }
}

// MARK: - Supply Chain Row

struct SupplyChainRow: View {
    let finding: SupplyChainFinding
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                SeverityBadge(severity: finding.severity)
                VStack(alignment: .leading, spacing: 2) {
                    Text(finding.finding)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text("\(finding.source.rawValue): \(finding.packageName)")
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                ExpandChevron(isExpanded: isExpanded)
            }
            .padding(.horizontal, 20).padding(.vertical, 8)
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { isExpanded.toggle() } }

            if isExpanded {
                Text(finding.details)
                    .font(.system(size: 11)).foregroundColor(.white.opacity(0.8))
                    .padding(.horizontal, 50).padding(.bottom, 8)
            }
        }
        .background(backgroundFor(finding.severity))
    }
}

// MARK: - Shared Components

struct SeverityBadge: View {
    let severity: AnomalySeverity

    var body: some View {
        Text(severity.label)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(color)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .background(color.opacity(0.15))
            .cornerRadius(4)
            .frame(width: 60)
    }

    private var color: Color {
        switch severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .gray
        }
    }
}

struct MITREBadge: View {
    let id: String
    var body: some View {
        Text(id)
            .font(.system(size: 9, design: .monospaced))
            .foregroundColor(.cyan)
            .padding(.horizontal, 6).padding(.vertical, 2)
            .background(Color.cyan.opacity(0.1))
            .cornerRadius(4)
    }
}

struct ExpandChevron: View {
    let isExpanded: Bool
    var body: some View {
        Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
            .foregroundColor(.gray).font(.system(size: 10))
    }
}

private func backgroundFor(_ severity: AnomalySeverity) -> Color {
    switch severity {
    case .critical: return Color.red.opacity(0.05)
    case .high: return Color.orange.opacity(0.03)
    default: return Color.white.opacity(0.02)
    }
}
