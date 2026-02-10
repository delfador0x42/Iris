import SwiftUI

@main
struct IrisMainApp: App {
    @StateObject private var extensionManager = ExtensionManager.shared

    var body: some Scene {
        WindowGroup {
            if extensionManager.areAllExtensionsReady {
                HomeView()
            } else {
                ExtensionSetupView()
            }
        }
        .windowToolbarStyle(.unified(showsTitle: false))
        .defaultSize(width: 1200, height: 800)
    }
}
