import SwiftUI

enum MenuDestination: String, CaseIterable {
  case satelliteTracker = "Satellite Tracker"
  case statistics = "Statistics"
  case processList = "Process List"
  case firewall = "Firewall Rules"
  case securityAssessment = "Security Assessment"
  case settings = "Settings"
  case networkMonitor = "Network Monitor"
  case proxyMonitor = "Proxy Monitor"
  case wifiMonitor = "WiFi Monitor"

  var icon: String {
    switch self {
    case .satelliteTracker: return "satellite.fill"
    case .statistics: return "internaldrive.fill"
    case .processList: return "list.bullet.rectangle.fill"
    case .firewall: return "flame.fill"
    case .securityAssessment: return "shield.checkered"
    case .settings: return "gearshape.fill"
    case .networkMonitor: return "network.badge.shield.half.filled"
    case .proxyMonitor: return "lock.open.display"
    case .wifiMonitor: return "wifi"
    }
  }

  var description: String {
    switch self {
    case .satelliteTracker: return "Track satellites in real-time"
    case .statistics: return "View disk usage"
    case .processList: return "View running processes"
    case .firewall: return "Manage network rules"
    case .securityAssessment: return "System security posture"
    case .settings: return "Extension & permissions"
    case .networkMonitor: return "Monitor network & HTTP traffic"
    case .proxyMonitor: return "Decrypted HTTPS traffic"
    case .wifiMonitor: return "WiFi signal & networks"
    }
  }
}

public struct HomeView: View {
  @StateObject private var renderer = HomeRenderer()
  @State private var navigationPath = NavigationPath()

  // Button layout: 8 buttons arranged clockwise from top
  private let destinations: [MenuDestination] = [
    .satelliteTracker,  // Top (0)
    .statistics,  // Top-right (1)
    .processList,  // Right (2)
    .securityAssessment,  // Bottom-right (3)
    .settings,  // Bottom (4)
    .networkMonitor,  // Bottom-left (5)
    .proxyMonitor,  // Left (6)
    .wifiMonitor,  // Top-left (7)
  ]

  public init() {}

  public var body: some View {
    NavigationStack(path: $navigationPath) {
      ZStack {
        // Metal-rendered stone circle with flames
        HomeMetalView(renderer: renderer) { buttonIndex in
          if buttonIndex >= 0 && buttonIndex < destinations.count {
            navigationPath.append(destinations[buttonIndex])
          }
        }
        .ignoresSafeArea()

        // Overlay: Button labels on hover
        if let hoveredIndex = renderer.hoveredButton,
          hoveredIndex >= 0 && hoveredIndex < destinations.count
        {
          VStack {
            Spacer()

            HStack(spacing: 12) {
              Image(systemName: destinations[hoveredIndex].icon)
                .font(.title2)

              VStack(alignment: .leading, spacing: 2) {
                Text(destinations[hoveredIndex].rawValue)
                  .font(.headline)
                Text(destinations[hoveredIndex].description)
                  .font(.caption)
                  .foregroundColor(.gray)
              }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 12)
            .background(.ultraThinMaterial, in: RoundedRectangle(cornerRadius: 12))
            .padding(.bottom, 40)
          }
          .transition(.opacity.combined(with: .move(edge: .bottom)))
          .animation(.easeInOut(duration: 0.2), value: renderer.hoveredButton)
        }
      }
      .navigationDestination(for: MenuDestination.self) { destination in
        switch destination {
        case .satelliteTracker:
          SatelliteView()
        case .statistics:
          DiskUsageView()
        case .processList:
          ProcessListView()
        case .networkMonitor:
          NetworkMonitorView()
        case .wifiMonitor:
          WiFiMonitorView()
        case .proxyMonitor:
          ProxyMonitorView()
        case .securityAssessment:
          SecurityHubView()
        case .settings:
          SettingsView()
        default:
          PlaceholderView(title: destination.rawValue, description: destination.description)
        }
      }
    }
  }
}

struct PlaceholderView: View {
  let title: String
  let description: String

  var body: some View {
    ZStack {
      // Dark gradient background
      LinearGradient(
        colors: [
          Color(red: 0.02, green: 0.03, blue: 0.05),
          Color(red: 0.05, green: 0.07, blue: 0.1),
        ],
        startPoint: .top,
        endPoint: .bottom
      )
      .ignoresSafeArea()

      VStack(spacing: 24) {
        Text(title)
          .font(.system(size: 36, weight: .bold, design: .serif))
          .foregroundColor(.white)

        Text(description)
          .font(.title3)
          .foregroundColor(.gray)

        Text("Coming Soon")
          .font(.caption)
          .foregroundColor(Color(red: 0.4, green: 0.6, blue: 1.0))
          .padding(.top, 20)
      }
    }
  }
}

#Preview {
  HomeView()
    .frame(width: 1000, height: 800)
}
