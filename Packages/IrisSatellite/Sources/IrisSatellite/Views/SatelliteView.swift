import SwiftUI

/// Main content view composing Metal renderer with UI overlay.
/// Uses IrisViewModel for unified state management.
public struct SatelliteView: View {
  @StateObject private var viewModel = IrisViewModel()

  public init() {}

  public var body: some View {
    ZStack {
      // Metal rendering view
      MetalView(
        renderer: viewModel.renderer,
        camera: viewModel.camera,
        onSetupError: { error in
          viewModel.handleSetupError(error)
        }
      )
      .ignoresSafeArea()

      // UI Overlay
      VStack {
        // Top bar - Statistics
        HStack {
          Spacer()

          StatisticsView(statistics: viewModel.statistics)
            .frame(width: 280)
        }
        .padding()

        Spacer()

        // Bottom bar - Legend and Controls
        HStack(alignment: .bottom) {
          LegendView()

          Spacer()

          if viewModel.showControls {
            ControlsView(
              store: viewModel.store,
              timeScales: viewModel.timeScales
            )
          }
        }
        .padding()
      }

      // Loading overlay
      if viewModel.isLoading {
        VStack(spacing: 12) {
          ProgressView()
            .scaleEffect(1.5)
            .tint(.white)

          Text("Loading satellites...")
            .font(.system(size: 14))
            .foregroundColor(.white)
        }
        .padding(24)
        .background(.ultraThinMaterial)
        .cornerRadius(12)
      }

      // Error overlay
      if let error = viewModel.errorMessage {
        VStack(spacing: 12) {
          Image(systemName: "exclamationmark.triangle")
            .font(.system(size: 32))
            .foregroundColor(.yellow)

          Text("Error loading data")
            .font(.headline)
            .foregroundColor(.white)

          Text(error)
            .font(.system(size: 12))
            .foregroundColor(.gray)
            .multilineTextAlignment(.center)

          Button("Retry") {
            Task {
              await viewModel.loadData()
            }
          }
          .buttonStyle(.borderedProminent)
        }
        .padding(24)
        .background(.ultraThinMaterial)
        .cornerRadius(12)
      }

      // Render error overlay
      if let renderError = viewModel.renderError {
        VStack(spacing: 12) {
          Image(systemName: "gpu")
            .font(.system(size: 32))
            .foregroundColor(.red)

          Text("Rendering Error")
            .font(.headline)
            .foregroundColor(.white)

          Text(renderError.localizedDescription)
            .font(.system(size: 12))
            .foregroundColor(.gray)
            .multilineTextAlignment(.center)
        }
        .padding(24)
        .background(.ultraThinMaterial)
        .cornerRadius(12)
      }
    }
    .background(Color.black)
    .onAppear {
      Task {
        await viewModel.loadData()
      }
    }
    .focusable()
    .onKeyPress { press in
      viewModel.handleKeyPress(press)
    }
  }
}
