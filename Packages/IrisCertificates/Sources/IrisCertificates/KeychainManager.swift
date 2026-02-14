import Foundation
import Security
import os.log

/// Manages storage of certificates and keys in the macOS Keychain.
/// Provides secure storage for the CA private key and certificate.
public final class KeychainManager: Sendable {

    let logger = Logger(subsystem: "com.wudan.iris", category: "KeychainManager")

    /// Service name for Keychain items
    let serviceName = "com.wudan.iris.proxy"

    /// Label for the CA private key
    let caPrivateKeyLabel = "Iris Proxy CA Private Key"

    /// Label for the CA certificate
    let caCertificateLabel = "Iris Proxy CA Certificate"

    /// Account name for Keychain items
    let accountName = "IrisProxyCA"

    /// Shared keychain access group for cross-process access.
    /// The proxy extension runs as root; the app runs as user.
    /// Data protection keychain with shared access group bridges this gap.
    let keychainAccessGroup = "99HGW2AR62.com.wudan.iris"

    public init() {}

    // MARK: - Cleanup

    /// Removes all Iris proxy-related items from the Keychain.
    public func removeAllIrisItems() throws {
        try? deleteCAPrivateKey()
        try? deleteCACertificate()
        logger.info("All Iris Keychain items removed")
    }
}

// MARK: - Errors

/// Errors that can occur during Keychain operations.
public enum KeychainError: Error, LocalizedError {
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
    case invalidDataFormat
    case exportFailed(String)
    case keyCreationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .saveFailed(let status):
            return "Failed to save to Keychain: \(SecCopyErrorMessageString(status, nil) ?? "Error \(status)" as CFString)"
        case .loadFailed(let status):
            return "Failed to load from Keychain: \(SecCopyErrorMessageString(status, nil) ?? "Error \(status)" as CFString)"
        case .deleteFailed(let status):
            return "Failed to delete from Keychain: \(SecCopyErrorMessageString(status, nil) ?? "Error \(status)" as CFString)"
        case .invalidDataFormat:
            return "Invalid data format in Keychain"
        case .exportFailed(let msg):
            return "Failed to export: \(msg)"
        case .keyCreationFailed(let msg):
            return "Failed to create key: \(msg)"
        }
    }
}
