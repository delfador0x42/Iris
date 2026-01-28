import SwiftUI

/// Dust-style size bar visualization
struct DiskSizeBar: View {
    let percentage: Double  // 0.0 to 1.0
    let depth: Int

    // Colors matching dust's depth-based shading
    private var barColor: Color {
        switch depth {
        case 0: return Color(red: 0.8, green: 0.2, blue: 0.2)  // Red for root-level
        case 1: return Color(red: 0.9, green: 0.5, blue: 0.2)  // Orange
        case 2: return Color(red: 0.9, green: 0.8, blue: 0.2)  // Yellow
        case 3: return Color(red: 0.4, green: 0.8, blue: 0.4)  // Green
        default: return Color(red: 0.4, green: 0.6, blue: 0.8) // Blue for deep
        }
    }

    var body: some View {
        GeometryReader { geometry in
            ZStack(alignment: .leading) {
                // Background
                Rectangle()
                    .fill(Color.white.opacity(0.1))
                    .cornerRadius(2)

                // Filled portion
                Rectangle()
                    .fill(barColor)
                    .frame(width: geometry.size.width * CGFloat(min(percentage, 1.0)))
                    .cornerRadius(2)
            }
        }
    }
}

#Preview {
    VStack(spacing: 8) {
        DiskSizeBar(percentage: 1.0, depth: 0)
            .frame(height: 12)
        DiskSizeBar(percentage: 0.75, depth: 1)
            .frame(height: 12)
        DiskSizeBar(percentage: 0.5, depth: 2)
            .frame(height: 12)
        DiskSizeBar(percentage: 0.25, depth: 3)
            .frame(height: 12)
        DiskSizeBar(percentage: 0.1, depth: 4)
            .frame(height: 12)
    }
    .padding()
    .background(Color.black)
}
