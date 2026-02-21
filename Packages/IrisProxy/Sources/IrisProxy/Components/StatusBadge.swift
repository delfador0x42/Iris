//
//  StatusBadge.swift
//  IrisProxy
//
//  Outline-style status badges — NieR aesthetic.
//

import SwiftUI

/// Outline badge displaying an HTTP status code.
public struct StatusBadge: View {
    let statusCode: Int

    public init(statusCode: Int) {
        self.statusCode = statusCode
    }

    public var body: some View {
        Text("\(statusCode)")
            .font(.system(size: 10, weight: .bold, design: .monospaced))
            .foregroundColor(accentColor)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(accentColor.opacity(0.08))
            .overlay(
                RoundedRectangle(cornerRadius: 3)
                    .stroke(accentColor.opacity(0.3), lineWidth: 0.5)
            )
            .cornerRadius(3)
    }

    private var accentColor: Color {
        switch statusCode {
        case 100..<200: return Color.white.opacity(0.5)
        case 200..<300: return Color(red: 0.3, green: 0.9, blue: 0.5)
        case 300..<400: return .cyan
        case 400..<500: return Color(red: 1.0, green: 0.6, blue: 0.2)
        case 500..<600: return Color(red: 1.0, green: 0.35, blue: 0.35)
        default:        return Color.white.opacity(0.4)
        }
    }
}

/// Minimalist pending indicator.
public struct PendingBadge: View {
    public init() {}

    public var body: some View {
        HStack(spacing: 4) {
            ProgressView()
                .scaleEffect(0.5)
            Text("---")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
        }
        .foregroundColor(Color.white.opacity(0.3))
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Color.white.opacity(0.03))
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(Color.white.opacity(0.1), lineWidth: 0.5)
        )
        .cornerRadius(3)
    }
}

/// Outline error badge.
public struct ErrorBadge: View {
    let message: String?

    public init(message: String? = nil) {
        self.message = message
    }

    public var body: some View {
        HStack(spacing: 4) {
            Text("ERR")
                .font(.system(size: 10, weight: .bold, design: .monospaced))
        }
        .foregroundColor(Color(red: 1.0, green: 0.35, blue: 0.35))
        .padding(.horizontal, 6)
        .padding(.vertical, 2)
        .background(Color.red.opacity(0.08))
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(Color.red.opacity(0.3), lineWidth: 0.5)
        )
        .cornerRadius(3)
        .help(message ?? "Request failed")
    }
}

// MARK: - Preview

#Preview {
    VStack(spacing: 8) {
        HStack(spacing: 8) {
            StatusBadge(statusCode: 200)
            StatusBadge(statusCode: 301)
            StatusBadge(statusCode: 404)
            StatusBadge(statusCode: 500)
        }
        HStack(spacing: 8) {
            MethodBadge(method: "GET")
            MethodBadge(method: "POST")
            PendingBadge()
            ErrorBadge(message: "Connection refused")
        }
    }
    .padding()
    .background(Color(red: 0.01, green: 0.02, blue: 0.04))
}
