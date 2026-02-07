import SwiftUI

/// Comprehensive threat scanning view that runs all security scanners
/// and presents findings organized by severity.
public struct ThreatScanView: View {
    @State private var anomalies: [ProcessAnomaly] = []
    @State private var isLoading = true
    @State private var scanPhase = ""
    @State private var showCriticalOnly = false
    @Environment(\.dismiss) private var dismiss

    public init() {}

    public var body: some View {
        ZStack {
            darkBackground
            VStack(spacing: 0) {
                header
                if isLoading {
                    scanningView
                } else if filteredAnomalies.isEmpty {
                    cleanView
                } else {
                    anomalyList
                }
            }
        }
        .task { await runFullScan() }
        .toolbar {
            ToolbarItem(placement: .navigation) { backButton }
        }
    }

    private var filteredAnomalies: [ProcessAnomaly] {
        showCriticalOnly ? anomalies.filter { $0.severity >= .high } : anomalies
    }

    private var header: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text("Threat Scanner")
                    .font(.system(size: 20, weight: .bold)).foregroundColor(.white)
                if !isLoading {
                    let critical = anomalies.filter { $0.severity == .critical }.count
                    let high = anomalies.filter { $0.severity == .high }.count
                    HStack(spacing: 12) {
                        Text("\(anomalies.count) findings")
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

    private var anomalyList: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 2) {
                ForEach(filteredAnomalies) { anomaly in
                    AnomalyRow(anomaly: anomaly)
                }
            }.padding(.vertical, 8)
        }
    }

    private var scanningView: some View {
        VStack(spacing: 16) {
            ProgressView().scaleEffect(1.2).tint(.white)
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
            Text("All scans passed")
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

    private var backButton: some View {
        Button(action: { dismiss() }) {
            HStack(spacing: 4) {
                Image(systemName: "chevron.left")
                Text("Back")
            }.foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
        }
    }

    private func runFullScan() async {
        isLoading = true
        var all: [ProcessAnomaly] = []

        scanPhase = "Scanning LOLBin activity..."
        let lolbin = await LOLBinDetector.shared.scan()
        all.append(contentsOf: lolbin)

        scanPhase = "Scanning stealth persistence..."
        let stealth = await StealthScanner.shared.scanAll()
        all.append(contentsOf: stealth)

        scanPhase = "Auditing XPC services..."
        let xpcServices = await XPCServiceAuditor.shared.scanXPCServices()
        let machServices = await XPCServiceAuditor.shared.scanMachServices()
        all.append(contentsOf: xpcServices)
        all.append(contentsOf: machServices)

        scanPhase = "Checking network anomalies..."
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

        anomalies = all.sorted { $0.severity > $1.severity }
        isLoading = false
    }
}

struct AnomalyRow: View {
    let anomaly: ProcessAnomaly
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                severityBadge
                VStack(alignment: .leading, spacing: 2) {
                    Text(anomaly.technique)
                        .font(.system(size: 12, weight: .medium)).foregroundColor(.white)
                    Text(anomaly.processName)
                        .font(.system(size: 10, design: .monospaced)).foregroundColor(.gray)
                }
                Spacer()
                if let mitre = anomaly.mitreID {
                    Text(mitre)
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundColor(.cyan)
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(Color.cyan.opacity(0.1))
                        .cornerRadius(4)
                }
                Image(systemName: isExpanded ? "chevron.up" : "chevron.down")
                    .foregroundColor(.gray).font(.system(size: 10))
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
        .background(backgroundForSeverity)
    }

    private var severityBadge: some View {
        Text(anomaly.severity.label)
            .font(.system(size: 9, weight: .bold))
            .foregroundColor(colorForSeverity)
            .padding(.horizontal, 6).padding(.vertical, 3)
            .background(colorForSeverity.opacity(0.15))
            .cornerRadius(4)
            .frame(width: 60)
    }

    private var colorForSeverity: Color {
        switch anomaly.severity {
        case .critical: return .red
        case .high: return .orange
        case .medium: return .yellow
        case .low: return .gray
        }
    }

    private var backgroundForSeverity: Color {
        switch anomaly.severity {
        case .critical: return Color.red.opacity(0.05)
        case .high: return Color.orange.opacity(0.03)
        default: return Color.white.opacity(0.02)
        }
    }
}
