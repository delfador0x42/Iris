//
//  StatusBadge.swift
//  IrisProxy
//
//  Badge displaying HTTP status code with color coding.
//

import SwiftUI

/// Badge displaying an HTTP status code with appropriate color coding.
public struct StatusBadge: View {
    let statusCode: Int

    public init(statusCode: Int) {
        self.statusCode = statusCode
    }

    public var body: some View {
        Text("\(statusCode)")
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .cornerRadius(4)
    }

    private var backgroundColor: Color {
        switch statusCode {
        case 100..<200:
            return .gray // Informational
        case 200..<300:
            return .green // Success
        case 300..<400:
            return .blue // Redirect
        case 400..<500:
            return .orange // Client Error
        case 500..<600:
            return .red // Server Error
        default:
            return .secondary
        }
    }
}

/// Badge indicating a pending request (no response yet).
public struct PendingBadge: View {
    public init() {}

    public var body: some View {
        HStack(spacing: 4) {
            ProgressView()
                .scaleEffect(0.6)
            Text("Pending")
                .font(.system(size: 10, weight: .medium))
        }
        .foregroundColor(.secondary)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Color.secondary.opacity(0.2))
        .cornerRadius(4)
    }
}

/// Badge indicating an error.
public struct ErrorBadge: View {
    let message: String?

    public init(message: String? = nil) {
        self.message = message
    }

    public var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 8))
            Text("Error")
                .font(.system(size: 10, weight: .medium))
        }
        .foregroundColor(.white)
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Color.red)
        .cornerRadius(4)
        .help(message ?? "Request failed")
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 8) {
        HStack(spacing: 8) {
            StatusBadge(statusCode: 200)
            StatusBadge(statusCode: 201)
            StatusBadge(statusCode: 204)
        }
        HStack(spacing: 8) {
            StatusBadge(statusCode: 301)
            StatusBadge(statusCode: 302)
            StatusBadge(statusCode: 304)
        }
        HStack(spacing: 8) {
            StatusBadge(statusCode: 400)
            StatusBadge(statusCode: 401)
            StatusBadge(statusCode: 404)
        }
        HStack(spacing: 8) {
            StatusBadge(statusCode: 500)
            StatusBadge(statusCode: 502)
            StatusBadge(statusCode: 503)
        }
        HStack(spacing: 8) {
            PendingBadge()
            ErrorBadge(message: "Connection refused")
        }
    }
    .padding()
}
