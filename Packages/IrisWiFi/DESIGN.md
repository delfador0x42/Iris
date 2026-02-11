# IrisWiFi — WiFi Network Monitoring

## What This Does
Monitors the current WiFi connection in real-time (signal strength, MCS/NSS,
channel, security), scans for nearby networks, and provides a signal history
graph. Uses CoreWLAN for interface data and system_profiler for MCS/NSS.

## Why This Design
CoreWLAN is the only supported API for WiFi on macOS. It provides interface
state, scan results, and connection management. MCS/NSS (modulation and
spatial stream info) isn't available through CoreWLAN, so we shell out to
`system_profiler SPAirPortDataType -json` every 5 seconds for that data.

## Data Flow
```
WiFiStore (1s monitoring timer):
  → CWWiFiClient.shared().interface()
  → read: SSID, BSSID, signal (RSSI), noise, channel, security, TX power
  → append to signalHistory (max 60 samples = 1 minute)
  → every 5s: system_profiler → parse MCS index, NSS, country code
  → @Published interfaceInfo → WiFiMonitorView

WiFiStore (scan on demand):
  → interface.scanForNetworks()
  → map [CWNetwork] → [WiFiNetwork]
  → sort by signal strength descending
  → @Published scannedNetworks → network list
```

## Decisions Made
- **CoreWLAN direct, not Airport utility** — CWWiFiClient is the supported
  API. Airport utility (airport -s) is deprecated and may disappear.
- **system_profiler for MCS/NSS** — CoreWLAN doesn't expose modulation info.
  SPAirPortDataType JSON output has it. Polled every 5s (not 1s) because
  the subprocess is heavyweight.
- **Signal history graph** — 60 samples at 1s intervals. Simple line graph
  showing RSSI over time. Useful for diagnosing intermittent signal issues.
- **WiFiEventDelegate** — CWWiFiClient delegate for SSID/BSSID/power change
  notifications. Supplements the polling timer.

## Key Files
- `State/WiFiStore.swift` + `+Monitoring` + `+Scanning` + `+Association` — CoreWLAN integration
- `State/WiFiEventDelegate.swift` — CWWiFiClient event delegate
- `Models/WiFiNetwork.swift` — Scanned network model
- `Models/WiFiInterfaceInfo.swift` — Current connection info
- `Views/WiFiMonitorView.swift` + `+SignalGraph` + `+NetworkScan` — WiFi monitoring UI
