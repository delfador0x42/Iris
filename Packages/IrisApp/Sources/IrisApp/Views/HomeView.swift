import SwiftUI
import IrisDisk
import IrisProcess
import IrisNetwork
import IrisSatellite

enum MenuDestination: String, CaseIterable {
    case satelliteTracker = "Satellite Tracker"
    case statistics = "Statistics"
    case processList = "Process List"
    case favorites = "Favorites"
    case settings = "Settings"
    case networkMonitor = "Network Monitor"
    case help = "Help"
    case about = "About"

    var icon: String {
        switch self {
        case .satelliteTracker: return "satellite.fill"
        case .statistics: return "internaldrive.fill"
        case .processList: return "list.bullet.rectangle.fill"
        case .favorites: return "star.fill"
        case .settings: return "gearshape.fill"
        case .networkMonitor: return "network.badge.shield.half.filled"
        case .help: return "questionmark.circle.fill"
        case .about: return "info.circle.fill"
        }
    }

    var description: String {
        switch self {
        case .satelliteTracker: return "Track satellites in real-time"
        case .statistics: return "View disk usage"
        case .processList: return "View running processes"
        case .favorites: return "Your saved satellites"
        case .settings: return "Extension & permissions"
        case .networkMonitor: return "Monitor network connections"
        case .help: return "Help & documentation"
        case .about: return "About this app"
        }
    }
}

public struct HomeView: View {
    @StateObject private var renderer = HomeRenderer()
    @State private var navigationPath = NavigationPath()

    // Button layout: 8 buttons arranged clockwise from top
    private let destinations: [MenuDestination] = [
        .satelliteTracker,  // Top (0)
        .statistics,        // Top-right (1)
        .processList,       // Right (2)
        .favorites,         // Bottom-right (3)
        .settings,          // Bottom (4)
        .networkMonitor,    // Bottom-left (5)
        .help,              // Left (6)
        .about              // Top-left (7)
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
                   hoveredIndex >= 0 && hoveredIndex < destinations.count {
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
                    ContentView()
                case .statistics:
                    DiskUsageView()
                case .processList:
                    ProcessListView()
                case .networkMonitor:
                    NetworkMonitorView()
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
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            // Dark gradient background
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.03, blue: 0.05),
                    Color(red: 0.05, green: 0.07, blue: 0.1)
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
        .toolbar {
            ToolbarItem(placement: .navigation) {
                Button(action: { dismiss() }) {
                    HStack(spacing: 4) {
                        Image(systemName: "chevron.left")
                        Text("Back")
                    }
                    .foregroundColor(Color(red: 0.4, green: 0.7, blue: 1.0))
                }
            }
        }
    }
}

#Preview {
    HomeView()
        .frame(width: 1000, height: 800)
}
