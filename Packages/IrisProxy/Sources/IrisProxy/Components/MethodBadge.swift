//
//  MethodBadge.swift
//  IrisProxy
//
//  Outline-style HTTP method badge — NieR aesthetic.
//

import SwiftUI

/// Outline badge displaying an HTTP method with muted color coding.
public struct MethodBadge: View {
    let method: String

    public init(method: String) {
        self.method = method
    }

    public var body: some View {
        Text(method)
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
        switch method.uppercased() {
        case "GET":    return .cyan
        case "POST":   return Color(red: 1.0, green: 0.6, blue: 0.2)
        case "PUT":    return Color(red: 0.7, green: 0.5, blue: 1.0)
        case "PATCH":  return Color(red: 0.5, green: 0.5, blue: 1.0)
        case "DELETE": return Color(red: 1.0, green: 0.35, blue: 0.35)
        case "HEAD":   return Color.white.opacity(0.5)
        case "OPTIONS": return Color(red: 0.4, green: 0.8, blue: 0.8)
        case "CONNECT": return Color(red: 0.8, green: 0.5, blue: 0.7)
        default:       return Color.white.opacity(0.4)
        }
    }
}

// MARK: - Preview

#Preview {
    HStack(spacing: 8) {
        MethodBadge(method: "GET")
        MethodBadge(method: "POST")
        MethodBadge(method: "PUT")
        MethodBadge(method: "DELETE")
        MethodBadge(method: "PATCH")
    }
    .padding()
    .background(Color(red: 0.01, green: 0.02, blue: 0.04))
}
