import Foundation

// MARK: - Filter Enable/Disable

@MainActor
extension SecurityStore {

    /// Toggle network filtering on/off via XPC. When disabled, the extension
    /// stays loaded but returns .allow() for all flows — no tracking, rules, or capture.
    public func setFilteringEnabled(_ enabled: Bool) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? NetworkXPCProtocol else {
            errorMessage = "Not connected to extension"
            return false
        }

        return await withCheckedContinuation { continuation in
            proxy.setFilteringEnabled(enabled) { [weak self] success in
                Task { @MainActor in
                    if success {
                        self?.filteringEnabled = enabled
                    }
                    continuation.resume(returning: success)
                }
            }
        }
    }

    /// Sync filteringEnabled from extension status. Called during refresh.
    func fetchFilterStatus() async {
        guard let proxy = xpcConnection?.remoteObjectProxyWithErrorHandler({ _ in
        }) as? NetworkXPCProtocol else {
            return
        }

        await withCheckedContinuation { continuation in
            proxy.getStatus { [weak self] status in
                Task { @MainActor in
                    if let enabled = status["filterEnabled"] as? Bool {
                        self?.filteringEnabled = enabled
                    }
                    continuation.resume()
                }
            }
        }
    }
}
