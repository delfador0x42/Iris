import SwiftUI

// MARK: - Module Definition

enum SecurityModule: String, CaseIterable, Identifiable {
  case liveDetection = "Live Detection"
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
  case allowlist = "Allowlist"

  var id: String { rawValue }

  var icon: String {
    switch self {
    case .liveDetection: return "bolt.shield.fill"
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
    case .allowlist: return "list.bullet.rectangle.portrait"
    }
  }

  var subtitle: String {
    switch self {
    case .liveDetection: return "40+ rules \u{00B7} realtime \u{00B7} MITRE"
    case .threatScan: return "50 engines \u{00B7} full sweep"
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
    case .allowlist: return "suppress false positives"
    }
  }

  var accentColor: Color {
    switch self {
    case .liveDetection: return Color(red: 0.0, green: 0.9, blue: 0.6)
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
    case .allowlist: return .gray
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
              .strokeBorder(module.accentColor.opacity(0.15), lineWidth: 1)))
    }
    .buttonStyle(.plain)
  }
}
