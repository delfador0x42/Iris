import Foundation
import Security
import os.log

// MARK: - CA Private Key Storage

extension KeychainManager {

    /// Saves the CA private key to the Keychain.
    /// Uses data protection keychain with shared access group so the proxy
    /// extension (running as root) can read items stored by the app (running as user).
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
            kSecValueData as String: keyData,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlock,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: keychainAccessGroup
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        if status != errSecSuccess {
            logger.error("Failed to save CA private key: \(status)")
            throw KeychainError.saveFailed(status)
        }

        logger.info("CA private key saved successfully")
    }

    /// Loads the CA private key from the Keychain.
    public func loadCAPrivateKey() throws -> SecKey? {
        logger.debug("Loading CA private key from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: caPrivateKeyLabel.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: keychainAccessGroup
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
    public func deleteCAPrivateKey() throws {
        logger.info("Deleting CA private key from Keychain")

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: caPrivateKeyLabel.data(using: .utf8)!,
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessGroup as String: keychainAccessGroup
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status != errSecSuccess && status != errSecItemNotFound {
            logger.error("Failed to delete CA private key: \(status)")
            throw KeychainError.deleteFailed(status)
        }

        logger.info("CA private key deleted")
    }
}
