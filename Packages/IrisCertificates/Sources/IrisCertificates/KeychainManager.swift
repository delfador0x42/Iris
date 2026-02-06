import Foundation
import Security
import AppKit
import os.log

/// Manages storage of certificates and keys in the macOS Keychain.
/// Provides secure storage for the CA private key and certificate.
public final class KeychainManager: Sendable {

    private let logger = Logger(subsystem: "com.wudan.iris", category: "KeychainManager")

    /// Service name for Keychain items
    private let serviceName = "com.wudan.iris.proxy"

    /// Label for the CA private key
    private let caPrivateKeyLabel = "Iris Proxy CA Private Key"

    /// Label for the CA certificate
    private let caCertificateLabel = "Iris Proxy CA Certificate"

    /// Account name for Keychain items
    private let accountName = "IrisProxyCA"

    public init() {}

    // MARK: - CA Private Key Storage

    /// Saves the CA private key to the Keychain.
    /// - Parameter privateKey: The SecKey to store
    /// - Throws: KeychainError if storage fails
    public func saveCAPrivateKey(_ privateKey: SecKey) throws {
        logger.info("Saving CA private key to Keychain")

        // First, try to delete any existing key
        try? deleteCAPrivateKey()

        // Export the key to data
        var error: Unmanaged<CFError>?
        guard let keyData = SecKeyCopyExternalRepresentation(privateKey, &error) as Data? else {
            let errorMsg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            logger.error("Failed to export private key: \(errorMsg)")
            throw KeychainError.exportFailed(errorMsg)
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: caPrivateKeyLabel.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrLabel as String: caPrivateKeyLabel,
            kSecAttrService as String: serviceName,
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        if status != errSecSuccess {
            logger.error("Failed to save CA private key: \(status)")
            throw KeychainError.saveFailed(status)
        }

        logger.info("CA private key saved successfully")
    }

    /// Loads the CA private key from the Keychain.
    /// - Returns: The SecKey if found, nil otherwise
    /// - Throws: KeychainError if loading fails (except for not found)
    public func loadCAPrivateKey() throws -> SecKey? {
        logger.debug("Loading CA private key from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: caPrivateKeyLabel.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnData as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            logger.debug("CA private key not found in Keychain")
            return nil
        }

        if status != errSecSuccess {
            logger.error("Failed to load CA private key: \(status)")
            throw KeychainError.loadFailed(status)
        }

        guard let keyData = result as? Data else {
            logger.error("Invalid key data format")
            throw KeychainError.invalidDataFormat
        }

        // Create SecKey from data
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, &error) else {
            let errorMsg = error?.takeRetainedValue().localizedDescription ?? "Unknown error"
            logger.error("Failed to create SecKey from data: \(errorMsg)")
            throw KeychainError.keyCreationFailed(errorMsg)
        }

        logger.debug("CA private key loaded successfully")
        return privateKey
    }

    /// Deletes the CA private key from the Keychain.
    /// - Throws: KeychainError if deletion fails
    public func deleteCAPrivateKey() throws {
        logger.info("Deleting CA private key from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: caPrivateKeyLabel.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            logger.error("Failed to delete CA private key: \(status)")
            throw KeychainError.deleteFailed(status)
        }

        logger.info("CA private key deleted")
    }

    // MARK: - CA Certificate Storage

    /// Saves the CA certificate to the Keychain.
    /// - Parameter certificate: The SecCertificate to store
    /// - Throws: KeychainError if storage fails
    public func saveCACertificate(_ certificate: SecCertificate) throws {
        logger.info("Saving CA certificate to Keychain")

        // First, try to delete any existing certificate
        try? deleteCACertificate()

        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: caCertificateLabel,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        if status != errSecSuccess {
            logger.error("Failed to save CA certificate: \(status)")
            throw KeychainError.saveFailed(status)
        }

        logger.info("CA certificate saved successfully")
    }

    /// Loads the CA certificate from the Keychain.
    /// - Returns: The SecCertificate if found, nil otherwise
    /// - Throws: KeychainError if loading fails (except for not found)
    public func loadCACertificate() throws -> SecCertificate? {
        logger.debug("Loading CA certificate from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: caCertificateLabel,
            kSecReturnRef as String: true
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        if status == errSecItemNotFound {
            logger.debug("CA certificate not found in Keychain")
            return nil
        }

        if status != errSecSuccess {
            logger.error("Failed to load CA certificate: \(status)")
            throw KeychainError.loadFailed(status)
        }

        guard let certificate = result as! SecCertificate? else {
            logger.error("Invalid certificate data format")
            throw KeychainError.invalidDataFormat
        }

        logger.debug("CA certificate loaded successfully")
        return certificate
    }

    /// Deletes the CA certificate from the Keychain.
    /// - Throws: KeychainError if deletion fails
    public func deleteCACertificate() throws {
        logger.info("Deleting CA certificate from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: caCertificateLabel
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            logger.error("Failed to delete CA certificate: \(status)")
            throw KeychainError.deleteFailed(status)
        }

        logger.info("CA certificate deleted")
    }

    // MARK: - System Trust

    /// Checks if the CA certificate is trusted in the System Keychain.
    /// - Parameter certificate: The certificate to check
    /// - Returns: True if the certificate is trusted
    public func isCACertificateTrusted(_ certificate: SecCertificate) -> Bool {
        var trust: SecTrust?
        let policy = SecPolicyCreateBasicX509()

        let status = SecTrustCreateWithCertificates([certificate] as CFArray, policy, &trust)
        guard status == errSecSuccess, let trust = trust else {
            logger.warning("Failed to create trust object: \(status)")
            return false
        }

        var error: CFError?
        let trusted = SecTrustEvaluateWithError(trust, &error)

        if let error = error {
            logger.debug("Trust evaluation: \(error.localizedDescription)")
        }

        return trusted
    }

    /// Exports the CA certificate as DER data for user installation.
    /// - Parameter certificate: The certificate to export
    /// - Returns: DER-encoded certificate data
    public func exportCertificateForInstallation(_ certificate: SecCertificate) -> Data? {
        return SecCertificateCopyData(certificate) as Data?
    }

    /// Gets the file path where the CA certificate should be exported.
    /// - Returns: URL to the export location
    public func getCertificateExportURL() -> URL {
        let downloadsURL = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask).first!
        return downloadsURL.appendingPathComponent("IrisProxyCA.cer")
    }

    /// Exports the CA certificate to a file for user installation.
    /// - Parameter certificate: The certificate to export
    /// - Returns: URL to the exported file
    /// - Throws: Error if export fails
    public func exportCertificateToFile(_ certificate: SecCertificate) throws -> URL {
        guard let data = exportCertificateForInstallation(certificate) else {
            throw KeychainError.exportFailed("Failed to get certificate data")
        }

        let url = getCertificateExportURL()
        try data.write(to: url)

        logger.info("CA certificate exported to: \(url.path)")
        return url
    }

    /// Opens the certificate in Keychain Access for user installation.
    /// - Parameter certificateURL: URL to the certificate file
    public func openCertificateInKeychainAccess(_ certificateURL: URL) {
        NSWorkspace.shared.open(certificateURL)
    }

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
