import Foundation

// MARK: - Root Error Type

/// Root error type for the Iris application.
public enum IrisError: Error, LocalizedError, Sendable {
    case network(NetworkError)
    case rendering(RenderingError)
    case data(DataError)
    case configuration(ConfigurationError)
    case disk(DiskScanError)

    public var errorDescription: String? {
        switch self {
        case .network(let error): return error.errorDescription
        case .rendering(let error): return error.errorDescription
        case .data(let error): return error.errorDescription
        case .configuration(let error): return error.errorDescription
        case .disk(let error): return error.errorDescription
        }
    }
}

// MARK: - Network Errors

public enum NetworkError: Error, LocalizedError, Sendable {
    case invalidURL(String)
    case requestFailed(underlying: String)
    case invalidResponse(statusCode: Int)
    case decodingFailed(underlying: String)
    case timeout
    case noConnection

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url): return "Invalid URL: \(url)"
        case .requestFailed(let msg): return "Request failed: \(msg)"
        case .invalidResponse(let code): return "Server error (status: \(code))"
        case .decodingFailed(let msg): return "Decode failed: \(msg)"
        case .timeout: return "Request timed out"
        case .noConnection: return "No network connection"
        }
    }

    public var isRetryable: Bool {
        switch self {
        case .timeout, .noConnection, .requestFailed: return true
        case .invalidURL, .invalidResponse, .decodingFailed: return false
        }
    }
}

// MARK: - Rendering Errors

public enum RenderingError: Error, LocalizedError, Sendable {
    case metalNotSupported
    case deviceCreationFailed
    case commandQueueCreationFailed
    case shaderCompilationFailed(String)
    case pipelineCreationFailed(String)
    case bufferCreationFailed(String)
    case textureLoadFailed(String)
    case encoderCreationFailed

    public var errorDescription: String? {
        switch self {
        case .metalNotSupported: return "Metal is not supported on this device"
        case .deviceCreationFailed: return "Failed to create Metal device"
        case .commandQueueCreationFailed: return "Failed to create command queue"
        case .shaderCompilationFailed(let msg): return "Shader compilation failed: \(msg)"
        case .pipelineCreationFailed(let msg): return "Pipeline creation failed: \(msg)"
        case .bufferCreationFailed(let msg): return "Buffer creation failed: \(msg)"
        case .textureLoadFailed(let msg): return "Texture loading failed: \(msg)"
        case .encoderCreationFailed: return "Failed to create command encoder"
        }
    }
}

// MARK: - Data Errors

public enum DataError: Error, LocalizedError, Sendable {
    case noData
    case invalidFormat
    case cacheMiss
    case parseError(String)
    case validationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noData: return "No data available"
        case .invalidFormat: return "Invalid data format"
        case .cacheMiss: return "Data not in cache"
        case .parseError(let msg): return "Parse error: \(msg)"
        case .validationFailed(let msg): return "Validation failed: \(msg)"
        }
    }
}

// MARK: - Configuration Errors

public enum ConfigurationError: Error, LocalizedError, Sendable {
    case missingValue(String)
    case invalidValue(key: String, value: String)
    case fileNotFound(String)

    public var errorDescription: String? {
        switch self {
        case .missingValue(let key): return "Missing config: \(key)"
        case .invalidValue(let key, let value): return "Invalid '\(value)' for \(key)"
        case .fileNotFound(let path): return "Config not found: \(path)"
        }
    }
}

// MARK: - Disk Scan Errors

public enum DiskScanError: Error, LocalizedError, Sendable, Equatable {
    case permissionDenied(path: String)
    case pathNotFound(path: String)
    case cancelled
    case scanFailed(underlying: String)

    public var errorDescription: String? {
        switch self {
        case .permissionDenied(let path): return "Permission denied: \(path)"
        case .pathNotFound(let path): return "Path not found: \(path)"
        case .cancelled: return "Scan was cancelled"
        case .scanFailed(let msg): return "Scan failed: \(msg)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .permissionDenied:
            return "Grant Full Disk Access in System Settings > Privacy & Security"
        case .pathNotFound: return "Check that the path exists"
        case .cancelled: return "Start a new scan"
        case .scanFailed: return "Try scanning again"
        }
    }
}
