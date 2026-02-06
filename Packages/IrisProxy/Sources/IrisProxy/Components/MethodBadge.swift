//
//  MethodBadge.swift
//  IrisProxy
//
//  Badge displaying HTTP method with color coding.
//

import SwiftUI

/// Badge displaying an HTTP method with appropriate color coding.
public struct MethodBadge: View {
    let method: String

    public init(method: String) {
        self.method = method
    }

    public var body: some View {
        Text(method)
            .font(.system(size: 10, weight: .semibold, design: .monospaced))
            .foregroundColor(.white)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(backgroundColor)
            .cornerRadius(4)
    }

    private var backgroundColor: Color {
        switch method.uppercased() {
        case "GET":
            return .blue
        case "POST":
            return .orange
        case "PUT":
            return .purple
        case "PATCH":
            return .indigo
        case "DELETE":
            return .red
        case "HEAD":
            return .gray
        case "OPTIONS":
            return .teal
        case "CONNECT":
            return .pink
        default:
            return .secondary
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
}
