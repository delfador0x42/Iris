import Foundation
import os.log

// MARK: - Filter Enable/Disable

@MainActor
extension SecurityStore {

    /// Toggle network filtering on/off via XPC. When disabled, the extension
    /// stays loaded but returns .allow() for all flows — no tracking, rules, or capture.
    public func setFilteringEnabled(_ enabled: Bool) async -> Bool {
        guard let proxy = xpcConnection?.remoteObjectProxy as? ProxyXPCProtocol else {
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
        }) as? ProxyXPCProtocol else {
            return
        }

        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            proxy.isFilteringEnabled { [weak self] enabled in
                Task { @MainActor in
                    self?.filteringEnabled = enabled
                    continuation.resume()
                }
            }
        }
    }
}
