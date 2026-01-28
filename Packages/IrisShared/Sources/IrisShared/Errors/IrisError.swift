import Foundation

// MARK: - Root Error Type

/// Root error type for the Iris application.
/// Provides a unified error hierarchy for all subsystems.
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

    public var recoverySuggestion: String? {
        switch self {
        case .network(let error): return error.recoverySuggestion
        case .rendering(let error): return error.recoverySuggestion
        case .data(let error): return error.recoverySuggestion
        case .configuration(let error): return error.recoverySuggestion
        case .disk(let error): return error.recoverySuggestion
        }
    }
}

// MARK: - Network Errors

/// Errors related to network operations and API calls.
public enum NetworkError: Error, LocalizedError, Sendable {
    case invalidURL(String)
    case requestFailed(underlying: String)
    case invalidResponse(statusCode: Int)
    case decodingFailed(underlying: String)
    case timeout
    case noConnection

    public var errorDescription: String? {
        switch self {
        case .invalidURL(let url):
            return "Invalid URL: \(url)"
        case .requestFailed(let message):
            return "Network request failed: \(message)"
        case .invalidResponse(let code):
            return "Server returned error (status: \(code))"
        case .decodingFailed(let message):
            return "Failed to decode response: \(message)"
        case .timeout:
            return "Request timed out"
        case .noConnection:
            return "No network connection"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .invalidURL:
            return "Check the URL format"
        case .requestFailed, .timeout, .noConnection:
            return "Check your internet connection and try again"
        case .invalidResponse:
            return "The server may be temporarily unavailable. Try again later"
        case .decodingFailed:
            return "The data format may have changed. Check for app updates"
        }
    }

    /// Whether this error is potentially recoverable by retrying.
    public var isRetryable: Bool {
        switch self {
        case .timeout, .noConnection, .requestFailed:
            return true
        case .invalidURL, .invalidResponse, .decodingFailed:
            return false
        }
    }
}

// MARK: - Rendering Errors

/// Errors related to Metal rendering and GPU operations.
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
        case .metalNotSupported:
            return "Metal is not supported on this device"
        case .deviceCreationFailed:
            return "Failed to create Metal device"
        case .commandQueueCreationFailed:
            return "Failed to create Metal command queue"
        case .shaderCompilationFailed(let message):
            return "Shader compilation failed: \(message)"
        case .pipelineCreationFailed(let message):
            return "Pipeline creation failed: \(message)"
        case .bufferCreationFailed(let message):
            return "Buffer creation failed: \(message)"
        case .textureLoadFailed(let message):
            return "Texture loading failed: \(message)"
        case .encoderCreationFailed:
            return "Failed to create command encoder"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .metalNotSupported:
            return "This application requires a Metal-capable GPU"
        case .deviceCreationFailed, .commandQueueCreationFailed:
            return "Restart the application or check GPU drivers"
        case .shaderCompilationFailed, .pipelineCreationFailed:
            return "This is an internal error. Please report this issue"
        case .bufferCreationFailed, .textureLoadFailed:
            return "The system may be low on GPU memory. Close other applications"
        case .encoderCreationFailed:
            return "GPU may be overloaded. Try again"
        }
    }
}

// MARK: - Data Errors

/// Errors related to data parsing and validation.
public enum DataError: Error, LocalizedError, Sendable {
    case noData
    case invalidFormat
    case cacheMiss
    case parseError(String)
    case validationFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noData:
            return "No data available"
        case .invalidFormat:
            return "Invalid data format"
        case .cacheMiss:
            return "Data not in cache"
        case .parseError(let message):
            return "Parse error: \(message)"
        case .validationFailed(let message):
            return "Validation failed: \(message)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .noData, .cacheMiss:
            return "Try refreshing the data"
        case .invalidFormat, .parseError:
            return "The data format may have changed. Check for app updates"
        case .validationFailed:
            return "Some data may be invalid. Try refreshing"
        }
    }
}

// MARK: - Configuration Errors

/// Errors related to application configuration.
public enum ConfigurationError: Error, LocalizedError, Sendable {
    case missingValue(String)
    case invalidValue(key: String, value: String)
    case fileNotFound(String)

    public var errorDescription: String? {
        switch self {
        case .missingValue(let key):
            return "Missing configuration value: \(key)"
        case .invalidValue(let key, let value):
            return "Invalid value '\(value)' for \(key)"
        case .fileNotFound(let path):
            return "Configuration file not found: \(path)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .missingValue, .invalidValue:
            return "Check the application configuration"
        case .fileNotFound:
            return "Reinstall the application"
        }
    }
}

// MARK: - Disk Scan Errors

/// Errors related to disk scanning operations.
public enum DiskScanError: Error, LocalizedError, Sendable, Equatable {
    case permissionDenied(path: String)
    case pathNotFound(path: String)
    case cancelled
    case scanFailed(underlying: String)

    public var errorDescription: String? {
        switch self {
        case .permissionDenied(let path):
            return "Permission denied: \(path)"
        case .pathNotFound(let path):
            return "Path not found: \(path)"
        case .cancelled:
            return "Scan was cancelled"
        case .scanFailed(let message):
            return "Scan failed: \(message)"
        }
    }

    public var recoverySuggestion: String? {
        switch self {
        case .permissionDenied:
            return "Grant Full Disk Access in System Settings > Privacy & Security"
        case .pathNotFound:
            return "Check that the path exists"
        case .cancelled:
            return "Start a new scan"
        case .scanFailed:
            return "Try scanning again"
        }
    }
}

// MARK: - Result Extensions

extension Result where Failure == IrisError {
    /// Execute an async throwing operation with proper error wrapping.
    public static func catching<T>(
        _ operation: () async throws -> T,
        transform: (Error) -> IrisError
    ) async -> Result<T, IrisError> {
        do {
            return .success(try await operation())
        } catch let error as IrisError {
            return .failure(error)
        } catch {
            return .failure(transform(error))
        }
    }
}
