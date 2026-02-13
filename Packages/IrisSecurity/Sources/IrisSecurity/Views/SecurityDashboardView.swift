import SwiftUI

/// Security posture dashboard with letter grade and categorized check results
public struct SecurityDashboardView: View {
    @StateObject private var store = SecurityAssessmentStore()
    public init() {}

    public var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.02, green: 0.03, blue: 0.05),
                    Color(red: 0.05, green: 0.07, blue: 0.1)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .ignoresSafeArea()

            if store.isLoading && store.checks.isEmpty {
                loadingView
            } else if let grade = store.grade {
                ThemedScrollView {
                    VStack(spacing: 24) {
                        gradeHeader(grade)
                        statsBar
                        categoryBreakdown(grade)
                        checksList
                    }
                    .padding(24)
                }
            } else {
                emptyView
            }
        }
        .task { await store.runAssessment() }
        .toolbar {
            ToolbarItem(placement: .automatic) {
                Button(action: { Task { await store.runAssessment() } }) {
                    Image(systemName: "arrow.clockwise")
                        .foregroundColor(.white)
                }
                .disabled(store.isLoading)
            }
        }
    }

    // MARK: - Grade Header

    private func gradeHeader(_ grade: SecurityGrade) -> some View {
        VStack(spacing: 8) {
            Text("Security Posture")
                .font(.system(size: 14, weight: .medium))
                .foregroundColor(.gray)

            Text(grade.letter)
                .font(.system(size: 96, weight: .bold, design: .rounded))
                .foregroundColor(gradeColor(grade.letter))

            Text("\(grade.score)/100")
                .font(.system(size: 18, weight: .medium, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))

            if let lastAssessment = store.lastAssessment {
                Text("Last scan: \(lastAssessment.formatted(.relative(presentation: .named)))")
                    .font(.caption)
                    .foregroundColor(.gray)
            }
        }
        .padding(.vertical, 16)
    }

    // MARK: - Stats Bar

    private var statsBar: some View {
        HStack(spacing: 20) {
            statBox(count: store.passCount, label: "Pass", color: .green)
            statBox(count: store.warningCount, label: "Warning", color: .orange)
            statBox(count: store.failCount, label: "Fail", color: .red)
        }
    }

    private func statBox(count: Int, label: String, color: Color) -> some View {
        VStack(spacing: 4) {
            Text("\(count)")
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .foregroundColor(color)
            Text(label)
                .font(.caption)
                .foregroundColor(.gray)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 12)
        .background(color.opacity(0.1))
        .cornerRadius(8)
    }

    // MARK: - Category Breakdown

    private func categoryBreakdown(_ grade: SecurityGrade) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Categories")
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))

            ForEach(SecurityCategory.allCases, id: \.self) { category in
                if let score = grade.categoryScores[category] {
                    categoryBar(category: category, score: score)
                }
            }
        }
    }

    private func categoryBar(category: SecurityCategory, score: Int) -> some View {
        HStack(spacing: 12) {
            Image(systemName: category.icon)
                .frame(width: 20)
                .foregroundColor(.white)

            Text(category.rawValue)
                .font(.system(size: 13))
                .foregroundColor(.white)
                .frame(width: 140, alignment: .leading)

            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 4)
                        .fill(Color.white.opacity(0.1))
                    RoundedRectangle(cornerRadius: 4)
                        .fill(scoreColor(score))
                        .frame(width: geo.size.width * CGFloat(score) / 100)
                }
            }
            .frame(height: 8)

            Text("\(score)%")
                .font(.system(size: 12, design: .monospaced))
                .foregroundColor(.white.opacity(0.7))
                .frame(width: 40, alignment: .trailing)
        }
    }

    // MARK: - Checks List

    private var checksList: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("All Checks")
                .font(.system(size: 14, weight: .semibold))
                .foregroundColor(Color(red: 0.0, green: 0.8, blue: 0.8))

            ForEach(store.checksByCategory, id: \.category) { group in
                VStack(alignment: .leading, spacing: 8) {
                    Text(group.category.rawValue)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.gray)
                        .padding(.top, 4)

                    ForEach(group.checks) { check in
                        SecurityCheckRow(check: check)
                    }
                }
            }
        }
    }

    // MARK: - State Views

    private var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.2)
                .tint(.white)
            Text("Running security assessment...")
                .font(.system(size: 14))
                .foregroundColor(.gray)
        }
    }

    private var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "shield.slash")
                .font(.system(size: 48))
                .foregroundColor(.gray)
            Text("No assessment results")
                .font(.headline)
                .foregroundColor(.white)
        }
    }

    // MARK: - Colors

    private func gradeColor(_ letter: String) -> Color {
        switch letter {
        case "A": return .green
        case "B": return Color(red: 0.5, green: 0.8, blue: 0.2)
        case "C": return .yellow
        case "D": return .orange
        default: return .red
        }
    }

    private func scoreColor(_ score: Int) -> Color {
        switch score {
        case 90...100: return .green
        case 70..<90: return .yellow
        case 50..<70: return .orange
        default: return .red
        }
    }
}
