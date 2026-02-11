# IrisSatellite — 3D Satellite Tracker

## What This Does
Fetches real satellite TLE data from CelesTrak, computes orbital positions
using SGP4 propagation, and renders a 3D Earth with satellites, orbital
paths, and atmosphere effects using Metal 4 at 60 FPS.

## Why This Design
SGP4 is the standard orbital propagation model — it takes a Two-Line Element
set and produces position/velocity at any time. Computing positions in Swift
(not a shader) keeps the math debuggable and lets us classify orbits. Metal
handles rendering only: Earth sphere, satellite meshes, orbital arcs, glow.

## Data Flow
```
SatelliteStore.loadSatellites()
  → CelesTrakDataSource: HTTP fetch TLE data
  → parse TLE → [SatelliteData]
  → SGP4 propagation: TLE + time → position (ECI coordinates)
  → classify orbit: LEO/MEO/GEO/HEO by altitude
  → simulation timer: advance time at timeScale
  → every frame: recompute positions → Renderer.draw()
    → projection matrix from Camera
    → render Earth, satellites, paths, atmosphere
    → present to MetalView
```

## Decisions Made
- **SGP4 in Swift** — MathLibrary.swift implements SGP4 from first
  principles. No C dependency. Accurate enough for visualization (not
  collision avoidance).
- **CelesTrak data source** — free, reliable, updated daily. Protocol-based
  for dependency injection in tests (MockSatelliteDataSource).
- **Metal 4 rendering** — GPU-accelerated for thousands of satellites.
  Custom shaders for Earth texture, atmosphere scattering, satellite glow.
- **Camera controller** — mouse drag for rotation, scroll for zoom.
  Separate protocol (CameraControllerProtocol) for testability.
- **Time simulation** — real-time by default, adjustable timeScale for
  fast-forward. Pause/resume supported.

## Key Files
- `State/SatelliteStore.swift` — Main store, simulation timer, time control
- `Data/CelesTrakDataSource.swift` — TLE data fetcher
- `Math/MathLibrary.swift` — SGP4 propagation, linear algebra
- `Rendering/Renderer.swift` + `+Draw` + `+Satellites` — Metal renderer pipeline
- `Rendering/Camera.swift` — 3D camera with mouse/scroll control
- `Views/MetalView.swift` — Metal rendering surface (NSViewRepresentable)
