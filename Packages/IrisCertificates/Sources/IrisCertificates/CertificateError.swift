import Foundation

/// Errors that can occur during certificate operations.
public enum CertificateError: Error, LocalizedError {
    case keyGenerationFailed(String)
    case publicKeyExtractionFailed
    case certificateCreationFailed(String)
    case certificateParsingFailed(String)
    case signingFailed(String)
    case keychainError(OSStatus)

    public var errorDescription: String? {
        switch self {
        case .keyGenerationFailed(let msg): return "Key generation failed: \(msg)"
        case .publicKeyExtractionFailed: return "Failed to extract public key"
        case .certificateCreationFailed(let msg): return "Certificate creation failed: \(msg)"
        case .certificateParsingFailed(let msg): return "Certificate parsing failed: \(msg)"
        case .signingFailed(let msg): return "Signing failed: \(msg)"
        case .keychainError(let status): return "Keychain error: \(status)"
        }
    }
}
