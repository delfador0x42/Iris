import SwiftUI

@main
struct IrisMainApp: App {
    var body: some Scene {
        WindowGroup {
            HomeView()
        }
        .windowStyle(.hiddenTitleBar)
        .defaultSize(width: 1200, height: 800)
    }
}




