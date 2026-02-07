import Foundation
import CoreWLAN
import os.log

// MARK: - Preferences

@MainActor
extension WiFiStore {

    /// Refresh preferences from system
    public func refreshPreferences() async {
        await Task.detached { [weak self] in
            guard let self = self else { return }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            process.arguments = ["prefs"]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                let output = String(data: data, encoding: .utf8) ?? ""

                let prefs = self.parsePreferencesOutput(output)

                await MainActor.run {
                    self.preferences = prefs
                    self.logger.debug("Refreshed WiFi preferences")
                }
            } catch {
                await MainActor.run {
                    self.logger.error("Failed to fetch preferences: \(error.localizedDescription)")
                }
            }
        }.value
    }

    /// Parse airport prefs output into WiFiPreferences
    nonisolated func parsePreferencesOutput(_ output: String) -> WiFiPreferences {
        var prefs = WiFiPreferences.default

        for line in output.components(separatedBy: "\n") {
            let parts = line.components(separatedBy: "=")
            guard parts.count == 2 else { continue }

            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)

            switch key {
            case "JoinMode":
                prefs.joinMode = WiFiJoinMode(rawValue: value) ?? .automatic
            case "JoinModeFallback":
                prefs.joinModeFallback = WiFiJoinMode(rawValue: value) ?? .strongest
            case "RememberRecentNetworks":
                prefs.rememberRecentNetworks = (value == "YES")
            case "DisconnectOnLogout":
                prefs.disconnectOnLogout = (value == "YES")
            case "RequireAdminIBSS":
                prefs.requireAdminIBSS = (value == "YES")
            case "RequireAdminNetworkChange":
                prefs.requireAdminNetworkChange = (value == "YES")
            case "RequireAdminPowerToggle":
                prefs.requireAdminPowerToggle = (value == "YES")
            default:
                break
            }
        }

        return prefs
    }

    /// Update a WiFi preference
    /// - Parameters:
    ///   - key: The preference key (e.g., "JoinMode", "DisconnectOnLogout")
    ///   - value: The value to set
    /// - Returns: Whether the operation succeeded
    public func setPreference(key: String, value: String) async -> Bool {
        guard let interface = wifiClient.interface() else {
            errorMessage = "No WiFi interface available"
            return false
        }

        let interfaceName = interface.interfaceName ?? "en0"

        return await Task.detached { [weak self] in
            guard let self = self else { return false }

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport")
            process.arguments = [interfaceName, "prefs", "\(key)=\(value)"]

            do {
                try process.run()
                process.waitUntilExit()

                if process.terminationStatus == 0 {
                    await self.refreshPreferences()
                    return true
                } else {
                    await MainActor.run {
                        self.errorMessage = "Failed to set preference (may require admin)"
                    }
                    return false
                }
            } catch {
                await MainActor.run {
                    self.logger.error("Failed to set preference: \(error.localizedDescription)")
                    self.errorMessage = "Failed to set preference: \(error.localizedDescription)"
                }
                return false
            }
        }.value
    }
}
