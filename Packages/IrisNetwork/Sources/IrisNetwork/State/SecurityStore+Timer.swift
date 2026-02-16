import Foundation

// MARK: - Refresh Timer Lifecycle

@MainActor
extension SecurityStore {

    func startRefreshTimer() {
        stopRefreshTimer()

        refreshTimer = Timer.scheduledTimer(withTimeInterval: refreshInterval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                await self?.refreshData()
            }
        }
    }

    func stopRefreshTimer() {
        refreshTimer?.invalidate()
        refreshTimer = nil
    }
}
