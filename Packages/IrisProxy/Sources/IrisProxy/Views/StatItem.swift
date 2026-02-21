//
//  StatItem.swift
//  IrisProxy
//
//  Compact stat display — outline style, NieR aesthetic.
//

import SwiftUI

struct StatItem: View {
    let title: String
    let value: String
    let color: Color

    var body: some View {
        VStack(spacing: 1) {
            Text(value)
                .font(.system(size: 13, weight: .bold, design: .monospaced))
                .foregroundColor(color)
            Text(title.uppercased())
                .font(.system(size: 8, weight: .medium, design: .monospaced))
                .foregroundColor(Color.white.opacity(0.35))
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 4)
        .background(color.opacity(0.05))
        .overlay(
            RoundedRectangle(cornerRadius: 3)
                .stroke(color.opacity(0.15), lineWidth: 0.5)
        )
        .cornerRadius(3)
    }
}
