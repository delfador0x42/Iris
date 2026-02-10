import SwiftUI

/// Security command center — Tron-style brutalist interface.
/// Entry point to all security scanning, monitoring, and auditing capabilities.
public struct SecurityHubView: View {
    @State private var selectedModule: SecurityModule?

    public init() {}

    public var body: some View {
        ZStack {
            gridBackground
            if let module = selectedModule {
                VStack(spacing: 0) {
                    // Inline back-to-grid button
                    HStack {
                        Button(action: {
                            withAnimation(.easeInOut(duration: 0.2)) { selectedModule = nil }
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: "chevron.left")
                                Text("Security")
                            }
                            .foregroundColor(.cyan)
                            .font(.system(size: 13, weight: .medium))
                        }
                        .buttonStyle(.plain)
                        Spacer()
                    }
                    .padding(.horizontal, 20)
                    .padding(.top, 12)
                    .padding(.bottom, 4)

                    moduleView(for: module)
                }
            } else {
                VStack(spacing: 0) {
                    hubHeader
                    moduleGrid
                }
            }
        }
    }

    private var hubHeader: some View {
        VStack(spacing: 8) {
            HStack(spacing: 12) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 28))
                    .foregroundStyle(
                        LinearGradient(
                            colors: [Color.cyan, Color.cyan.opacity(0.5)],
                            startPoint: .top, endPoint: .bottom
                        )
                    )
                VStack(alignment: .leading, spacing: 2) {
                    Text("SECURITY")
                        .font(.system(size: 24, weight: .black, design: .monospaced))
                        .foregroundColor(.white)
                        .tracking(6)
                    Text("20 DETECTION ENGINES")
                        .font(.system(size: 10, weight: .medium, design: .monospaced))
                        .foregroundColor(.cyan.opacity(0.7))
                        .tracking(2)
                }
                Spacer()
            }
            .padding(.horizontal, 24).padding(.top, 20)

            // Divider line
            Rectangle()
                .fill(LinearGradient(
                    colors: [.clear, .cyan.opacity(0.3), .cyan.opacity(0.3), .clear],
                    startPoint: .leading, endPoint: .trailing
                ))
                .frame(height: 1)
                .padding(.horizontal, 20).padding(.top, 4)
        }
    }

    private var moduleGrid: some View {
        ScrollView {
            LazyVGrid(
                columns: [
                    GridItem(.flexible(), spacing: 12),
                    GridItem(.flexible(), spacing: 12),
                    GridItem(.flexible(), spacing: 12),
                ],
                spacing: 12
            ) {
                ForEach(SecurityModule.allCases) { module in
                    ModuleCard(module: module) {
                        selectedModule = module
                    }
                }
            }
            .padding(20)
        }
    }

    @ViewBuilder
    private func moduleView(for module: SecurityModule) -> some View {
        switch module {
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
        }
    }

    private var gridBackground: some View {
        ZStack {
            Color(red: 0.01, green: 0.02, blue: 0.04)
            // Subtle grid pattern
            Canvas { context, size in
                let gridSpacing: CGFloat = 40
                var path = Path()
                // Vertical lines
                var x: CGFloat = 0
                while x < size.width {
                    path.move(to: CGPoint(x: x, y: 0))
                    path.addLine(to: CGPoint(x: x, y: size.height))
                    x += gridSpacing
                }
                // Horizontal lines
                var y: CGFloat = 0
                while y < size.height {
                    path.move(to: CGPoint(x: 0, y: y))
                    path.addLine(to: CGPoint(x: size.width, y: y))
                    y += gridSpacing
                }
                context.stroke(path, with: .color(.cyan.opacity(0.03)), lineWidth: 0.5)
            }
        }.ignoresSafeArea()
    }

}

// MARK: - Module Definition

enum SecurityModule: String, CaseIterable, Identifiable {
    case threatScan = "Threat Scan"
    case securityPosture = "Security Posture"
    case persistence = "Persistence"
    case eventTaps = "Event Taps"
    case dylibHijack = "Dylib Hijack"
    case fileIntegrity = "File Integrity"
    case supplyChain = "Supply Chain"
    case avMonitor = "AV Monitor"
    case tccPermissions = "TCC Permissions"
    case ransomware = "Ransomware Check"
    case packageInventory = "Package Inventory"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .threatScan: return "exclamationmark.shield"
        case .securityPosture: return "gauge.with.dots.needle.33percent"
        case .persistence: return "arrow.clockwise.circle"
        case .eventTaps: return "keyboard"
        case .dylibHijack: return "link.badge.plus"
        case .fileIntegrity: return "externaldrive.badge.checkmark"
        case .supplyChain: return "shippingbox"
        case .avMonitor: return "video.badge.waveform.fill"
        case .tccPermissions: return "hand.raised.fill"
        case .ransomware: return "lock.trianglebadge.exclamationmark"
        case .packageInventory: return "archivebox"
        }
    }

    var subtitle: String {
        switch self {
        case .threatScan: return "15 engines \u{00B7} full sweep"
        case .securityPosture: return "SIP \u{00B7} FileVault \u{00B7} grade"
        case .persistence: return "13 locations \u{00B7} signing"
        case .eventTaps: return "keylogger detection"
        case .dylibHijack: return "Mach-O \u{00B7} rpath \u{00B7} weak"
        case .fileIntegrity: return "SHA-256 baseline \u{00B7} diff"
        case .supplyChain: return "brew \u{00B7} npm \u{00B7} pip \u{00B7} xcode"
        case .avMonitor: return "mic \u{00B7} camera \u{00B7} realtime"
        case .tccPermissions: return "FDA \u{00B7} screen \u{00B7} accessibility"
        case .ransomware: return "entropy \u{00B7} chi-square \u{00B7} pi"
        case .packageInventory: return "brew \u{00B7} app store \u{00B7} pkgutil"
        }
    }

    var accentColor: Color {
        switch self {
        case .threatScan: return .red
        case .securityPosture: return .blue
        case .persistence: return .orange
        case .eventTaps: return .purple
        case .dylibHijack: return .yellow
        case .fileIntegrity: return .cyan
        case .supplyChain: return .green
        case .avMonitor: return .pink
        case .tccPermissions: return .mint
        case .ransomware: return Color(red: 0.8, green: 0.2, blue: 0.2)
        case .packageInventory: return .indigo
        }
    }
}

// MARK: - Module Card

struct ModuleCard: View {
    let module: SecurityModule
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 12) {
                HStack {
                    Image(systemName: module.icon)
                        .font(.system(size: 20))
                        .foregroundColor(module.accentColor)
                    Spacer()
                    Image(systemName: "chevron.right")
                        .font(.system(size: 10))
                        .foregroundColor(.gray.opacity(0.5))
                }

                Text(module.rawValue)
                    .font(.system(size: 14, weight: .bold, design: .monospaced))
                    .foregroundColor(.white)

                Text(module.subtitle)
                    .font(.system(size: 10, design: .monospaced))
                    .foregroundColor(.gray)
                    .lineLimit(1)
            }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.white.opacity(0.03))
                    .overlay(
                        RoundedRectangle(cornerRadius: 8)
                            .strokeBorder(
                                module.accentColor.opacity(0.15),
                                lineWidth: 1
                            )
                    )
            )
        }
        .buttonStyle(.plain)
    }
}
