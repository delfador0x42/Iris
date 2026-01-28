import SwiftUI

/// Legend showing satellite color coding by inclination
struct LegendView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Inclination")
                .font(.headline)
                .foregroundColor(.white)

            ForEach(OrbitalClassification.allCases) { classification in
                HStack(spacing: 8) {
                    // Color swatch
                    RoundedRectangle(cornerRadius: 3)
                        .fill(Color(
                            red: classification.uiColor.red,
                            green: classification.uiColor.green,
                            blue: classification.uiColor.blue
                        ))
                        .frame(width: 16, height: 16)

                    VStack(alignment: .leading, spacing: 1) {
                        Text(classification.rawValue)
                            .font(.system(size: 12, weight: .medium))
                            .foregroundColor(.white)

                        Text(classification.rangeDescription)
                            .font(.system(size: 10))
                            .foregroundColor(.gray)
                    }
                }
            }
        }
        .padding(12)
        .background(.ultraThinMaterial)
        .cornerRadius(10)
    }
}
