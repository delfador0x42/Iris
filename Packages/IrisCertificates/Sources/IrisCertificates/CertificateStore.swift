import Foundation
import Security
import os.log
import Combine

/// Main interface for managing the Iris Proxy CA certificate.
/// This store handles CA creation, storage, and trust status.
@MainActor
public final class CertificateStore: ObservableObject {

    // MARK: - Published State

    /// Whether the CA certificate has been generated and stored.
    @Published public private(set) var isCAInstalled: Bool = false

    /// Whether the CA certificate is trusted by the system.
    @Published public private(set) var isCATrusted: Bool = false

    /// The CA certificate (if loaded).
    @Published public private(set) var caCertificate: SecCertificate?

    /// The CA private key (if loaded).
    @Published public private(set) var caPrivateKey: SecKey?

    /// Loading state.
    @Published public private(set) var isLoading: Bool = false

    /// Error message if any operation failed.
    @Published public private(set) var errorMessage: String?

    /// CA certificate common name.
    @Published public private(set) var caCommonName: String?

    /// CA certificate expiration date.
    @Published public private(set) var caExpirationDate: Date?

    // MARK: - Private Properties

    private let logger = Logger(subsystem: "com.wudan.iris", category: "CertificateStore")
    private let generator: CertificateGenerator
    private let keychainManager: KeychainManager
    private let certificateCache: CertificateCache

    // MARK: - Singleton

    /// Shared instance for app-wide use.
    public static let shared = CertificateStore()

    // MARK: - Initialization

    /// Creates a new CertificateStore.
    /// - Parameters:
    ///   - generator: Certificate generator (defaults to new instance)
    ///   - keychainManager: Keychain manager (defaults to new instance)
    ///   - certificateCache: Certificate cache (defaults to new instance with 1000 capacity)
    public init(
        generator: CertificateGenerator = CertificateGenerator(),
        keychainManager: KeychainManager = KeychainManager(),
        certificateCache: CertificateCache = CertificateCache(maxCapacity: 1000)
    ) {
        self.generator = generator
        self.keychainManager = keychainManager
        self.certificateCache = certificateCache
    }

    // MARK: - Public Methods

    /// Loads the CA certificate and key from Keychain, or creates new ones if not found.
    public func loadOrCreateCA() async {
        logger.info("Loading or creating CA certificate")
        isLoading = true
        errorMessage = nil

        do {
            // Try to load existing CA
            if let privateKey = try keychainManager.loadCAPrivateKey(),
               let certificate = try keychainManager.loadCACertificate() {
                logger.info("Loaded existing CA from Keychain")
                self.caPrivateKey = privateKey
                self.caCertificate = certificate
                self.isCAInstalled = true
                updateCertificateInfo(certificate)
                updateTrustStatus()
            } else {
                // Create new CA
                logger.info("No existing CA found, creating new one")
                try await createAndStoreCA()
            }
        } catch {
            logger.error("Failed to load or create CA: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
        }

        isLoading = false
    }

    /// Creates a new CA certificate and stores it in the Keychain.
    /// This will replace any existing CA.
    public func createNewCA() async throws {
        logger.info("Creating new CA certificate")
        isLoading = true
        errorMessage = nil

        do {
            try await createAndStoreCA()
        } catch {
            logger.error("Failed to create new CA: \(error.localizedDescription)")
            errorMessage = error.localizedDescription
            throw error
        }

        isLoading = false
    }

    /// Exports the CA certificate to a file for user installation.
    /// - Returns: URL to the exported certificate file
    public func exportCACertificate() async throws -> URL {
        guard let certificate = caCertificate else {
            throw CertificateStoreError.caNotInstalled
        }

        let url = try keychainManager.exportCertificateToFile(certificate)
        logger.info("Exported CA certificate to: \(url.path)")
        return url
    }

    /// Opens the exported certificate in Keychain Access for user trust.
    public func promptUserToInstallCA() async throws {
        let url = try await exportCACertificate()
        keychainManager.openCertificateInKeychainAccess(url)
    }

    /// Refreshes the trust status of the CA certificate.
    public func refreshTrustStatus() {
        updateTrustStatus()
    }

    /// Generates a leaf certificate for a hostname, signed by the CA.
    /// Uses the certificate cache for performance.
    /// - Parameter hostname: The hostname for the certificate
    /// - Returns: Tuple of (privateKey, certificate) for TLS handshake
    public func getLeafCertificate(for hostname: String) async throws -> (privateKey: SecKey, certificate: SecCertificate) {
        // Check cache first
        if let cached = certificateCache.get(hostname: hostname) {
            logger.debug("Using cached certificate for: \(hostname)")
            return cached
        }

        // Generate new certificate
        guard let caPrivateKey = caPrivateKey,
              let caCertificate = caCertificate else {
            throw CertificateStoreError.caNotInstalled
        }

        logger.debug("Generating new certificate for: \(hostname)")
        let leaf = try generator.createLeafCertificate(
            hostname: hostname,
            caPrivateKey: caPrivateKey,
            caCertificate: caCertificate
        )

        // Cache the certificate
        certificateCache.set(hostname: hostname, certificate: leaf)

        return leaf
    }

    /// Gets the CA certificate as PEM-encoded string.
    public func getCACertificatePEM() -> String? {
        guard let certificate = caCertificate else { return nil }
        return generator.exportCertificateAsPEM(certificate)
    }

    /// Removes all CA data from Keychain.
    public func removeCA() async throws {
        logger.info("Removing CA certificate and private key")

        try keychainManager.removeAllIrisItems()

        caCertificate = nil
        caPrivateKey = nil
        isCAInstalled = false
        isCATrusted = false
        caCommonName = nil
        caExpirationDate = nil
        certificateCache.clear()

        logger.info("CA removed successfully")
    }

    /// Clears the leaf certificate cache.
    public func clearCertificateCache() {
        certificateCache.clear()
        logger.info("Certificate cache cleared")
    }

    /// Gets cache statistics.
    public func getCacheStats() -> (count: Int, capacity: Int) {
        return (certificateCache.count, certificateCache.maxCapacity)
    }

    // MARK: - Private Methods

    /// Creates a new CA and stores it in the Keychain.
    private func createAndStoreCA() async throws {
        let (privateKey, certificate) = try generator.createCA()

        // Store in Keychain
        try keychainManager.saveCAPrivateKey(privateKey)
        try keychainManager.saveCACertificate(certificate)

        // Update state
        self.caPrivateKey = privateKey
        self.caCertificate = certificate
        self.isCAInstalled = true

        updateCertificateInfo(certificate)
        updateTrustStatus()

        logger.info("New CA created and stored successfully")
    }

    /// Updates the trust status based on the current certificate.
    private func updateTrustStatus() {
        guard let certificate = caCertificate else {
            isCATrusted = false
            return
        }

        isCATrusted = keychainManager.isCACertificateTrusted(certificate)
        logger.debug("CA trust status: \(self.isCATrusted)")
    }

    /// Updates certificate info from the certificate.
    private func updateCertificateInfo(_ certificate: SecCertificate) {
        // Get common name
        var commonName: CFString?
        SecCertificateCopyCommonName(certificate, &commonName)
        self.caCommonName = commonName as String?

        // Get expiration date (simplified - would need full ASN.1 parsing for exact date)
        // For now, we'll estimate based on creation
        self.caExpirationDate = Date().addingTimeInterval(CertificateGenerator.caValidityDays * 24 * 60 * 60)
    }
}

// MARK: - Errors

/// Errors specific to the CertificateStore.
public enum CertificateStoreError: Error, LocalizedError {
    case caNotInstalled
    case caGenerationFailed(String)
    case storageFailed(String)

    public var errorDescription: String? {
        switch self {
        case .caNotInstalled:
            return "CA certificate is not installed. Please install it first."
        case .caGenerationFailed(let msg):
            return "Failed to generate CA: \(msg)"
        case .storageFailed(let msg):
            return "Failed to store certificate: \(msg)"
        }
    }
}
