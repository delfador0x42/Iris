# IrisApp — Main Application UI & Navigation

## What This Does
The app's entry point and navigation hub. Renders a Metal-powered home screen
with 8 navigation buttons arranged in a stone circle, routes to all feature
modules, and provides the settings UI for extension management and API
configuration.

## Why This Design
Each feature module (IrisNetwork, IrisProcess, etc.) is self-contained with
its own store and views. IrisApp is the shell that wires them together via
NavigationStack routing. The Metal home screen is deliberately unusual — it's
a statement piece, not a standard sidebar layout.

## Data Flow
```
IrisApp (entry point)
  → HomeView (NavigationStack)
    → HomeMetalView (Metal: stone circle + flames)
      → HomeRenderer: GPU rendering, hover detection on 8 buttons
    → route selection → push destination view:
      → SatelliteTracker (IrisSatellite)
      → DiskUsage (IrisDisk)
      → ProcessList (IrisProcess)
      → Firewall (IrisNetwork rules)
      → Settings (ExtensionManager + API keys)
      → NetworkMonitor (IrisNetwork connections)
      → DNSMonitor (IrisDNS)
      → WiFiMonitor (IrisWiFi)
```

## Decisions Made
- **Metal home screen** — GPU-rendered stone circle with fire effects. Each
  button is a 3D-positioned hit target. Intentionally over-the-top.
- **NavigationStack, not sidebar** — full-screen feature views rather than
  split layout. Each module gets maximum screen real estate.
- **Settings centralized here** — extension install/status UI lives in
  IrisApp because it depends on ExtensionManager (IrisShared) and touches
  all extensions. Feature modules don't know about installation.
- **No global state** — each feature module has its own store singleton.
  IrisApp doesn't hold a god-object.

## Key Files
- `Views/HomeView.swift` — Navigation hub with 8 route buttons
- `Views/HomeMetalView.swift` — Metal rendering surface for home screen
- `Views/SettingsView.swift` — Main settings container
- `Views/SettingsView+NetworkExtension.swift` — Network ext install/status
- `Views/SettingsView+EndpointExtension.swift` — Endpoint ext install/status
- `Views/SettingsView+Permissions.swift` — FDA, system extension approval
- `Views/SettingsView+ThreatIntelligence.swift` — API key configuration
- `Rendering/HomeRenderer.swift` — Metal renderer for stone circle + flames
