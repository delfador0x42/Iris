import SwiftUI

enum MenuDestination: String, CaseIterable {
  case securityAssessment = "Security"
  case processList = "Processes"
  case networkMonitor = "Network"
  case proxyMonitor = "Proxy"
  case wifiMonitor = "WiFi"
  case statistics = "Disk"
  case settings = "Settings"

  var icon: String {
    switch self {
    case .securityAssessment: return "shield.checkered"
    case .processList: return "list.bullet.rectangle.fill"
    case .networkMonitor: return "network.badge.shield.half.filled"
    case .proxyMonitor: return "lock.open.display"
    case .wifiMonitor: return "wifi"
    case .statistics: return "internaldrive.fill"
    case .settings: return "gearshape.fill"
    }
  }

  var description: String {
    switch self {
    case .securityAssessment: return "Threat scanning & integrity probes"
    case .processList: return "Live process monitoring"
    case .networkMonitor: return "Connection tracking & firewall"
    case .proxyMonitor: return "Decrypted HTTPS inspection"
    case .wifiMonitor: return "WiFi signal & networks"
    case .statistics: return "Disk usage analysis"
    case .settings: return "Extensions & permissions"
    }
  }
}

public struct HomeView: View {
  @StateObject private var extensionManager = ExtensionManager.shared
  @State private var navigationPath = NavigationPath()

  private let destinations: [MenuDestination] = MenuDestination.allCases

  public init() {}

  public var body: some View {
    NavigationStack(path: $navigationPath) {
      ZStack {
        BackgroundGradient()

        VStack(spacing: 32) {
          // Status header
          statusHeader

          // Navigation grid
          LazyVGrid(columns: [
            GridItem(.flexible(), spacing: 16),
            GridItem(.flexible(), spacing: 16),
            GridItem(.flexible(), spacing: 16),
          ], spacing: 16) {
            ForEach(destinations, id: \.self) { dest in
              Button {
                navigationPath.append(dest)
              } label: {
                navCard(dest)
              }
              .buttonStyle(.plain)
            }
          }
          .padding(.horizontal, 40)

          Spacer()
        }
        .padding(.top, 40)
      }
      .navigationDestination(for: MenuDestination.self) { destination in
        switch destination {
        case .securityAssessment:
          SecurityHubView()
        case .processList:
          ProcessListView()
        case .networkMonitor:
          NetworkMonitorView()
        case .proxyMonitor:
          ProxyMonitorView()
        case .wifiMonitor:
          WiFiMonitorView()
        case .statistics:
          DiskUsageView()
        case .settings:
          SettingsView()
        }
      }
    }
  }

  private var statusHeader: some View {
    HStack(spacing: 24) {
      // Extension status
      HStack(spacing: 8) {
        Circle()
          .fill(extensionManager.isEndpointExtensionReady ? .green : .red)
          .frame(width: 8, height: 8)
        Text("Endpoint")
          .font(.caption)
          .foregroundColor(.secondary)
      }

      HStack(spacing: 8) {
        Circle()
          .fill(extensionManager.isNetworkExtensionReady ? .green : .red)
          .frame(width: 8, height: 8)
        Text("Network")
          .font(.caption)
          .foregroundColor(.secondary)
      }

      Spacer()

      Text("Iris")
        .font(.system(size: 28, weight: .bold, design: .serif))
        .foregroundColor(.white)

      Spacer()

      // Placeholder for alert count — will be wired in Phase 2
      Text("Ready")
        .font(.caption)
        .foregroundColor(.secondary)
    }
    .padding(.horizontal, 40)
  }

  private func navCard(_ dest: MenuDestination) -> some View {
    VStack(spacing: 12) {
      Image(systemName: dest.icon)
        .font(.system(size: 28))
        .foregroundColor(.white)
      Text(dest.rawValue)
        .font(.headline)
        .foregroundColor(.white)
      Text(dest.description)
        .font(.caption)
        .foregroundColor(.gray)
        .multilineTextAlignment(.center)
    }
    .frame(maxWidth: .infinity)
    .frame(height: 140)
    .background(
      RoundedRectangle(cornerRadius: 12)
        .fill(Color.white.opacity(0.05))
        .overlay(
          RoundedRectangle(cornerRadius: 12)
            .strokeBorder(Color.white.opacity(0.1), lineWidth: 1)
        )
    )
  }
}

#Preview {
  HomeView()
    .frame(width: 1000, height: 800)
}
