import Foundation
import Security
import os.log

// MARK: - CA Private Key Storage

extension KeychainManager {

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
}
