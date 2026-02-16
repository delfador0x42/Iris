#!/usr/bin/env swift
//
//  iris-ctl.swift — CLI controller for the Iris app
//
//  Sends commands to the running Iris app via DistributedNotificationCenter
//  and reads the response (status written to /tmp/iris-status.json).
//
//  Usage:
//    swift scripts/iris-ctl.swift status          # Dump app status to /tmp/iris-status.json
//    swift scripts/iris-ctl.swift reinstall        # Trigger clean reinstall of all extensions
//    swift scripts/iris-ctl.swift startProxy       # Enable the transparent proxy
//    swift scripts/iris-ctl.swift stopProxy        # Disable the transparent proxy
//    swift scripts/iris-ctl.swift sendCA           # Resend CA cert to proxy extension
//    swift scripts/iris-ctl.swift checkExtensions  # Check extension statuses + write status
//

import Foundation

let statusPath = "/tmp/iris-status.json"
let commandName = Notification.Name("com.wudan.iris.command")
let responseName = Notification.Name("com.wudan.iris.response")

let args = CommandLine.arguments
let action = args.count > 1 ? args[1] : "status"

let validCommands = [
  "status", "reinstall", "startProxy", "stopProxy", "sendCA", "checkExtensions",
  "installProxy", "installDNS", "cleanProxy", "scan",
]
guard validCommands.contains(action) else {
  print("Unknown command: \(action)")
  print("Valid commands: \(validCommands.joined(separator: ", "))")
  exit(1)
}

// Delete stale status file before requesting fresh one
if action == "status" || action == "checkExtensions" {
  try? FileManager.default.removeItem(atPath: statusPath)
}

// Listen for response
var gotResponse = false
let center = DistributedNotificationCenter.default()
let observer = center.addObserver(forName: responseName, object: nil, queue: .main) {
  notification in
  if let status = notification.userInfo?["status"] as? String,
    let respAction = notification.userInfo?["action"] as? String
  {
    if respAction == action {
      if status == "ok" {
        print("[\(action)] OK")
      } else {
        print("[\(action)] \(status)")
      }
      gotResponse = true
    }
  }
}

// Send command
print("Sending: \(action)")
center.postNotificationName(
  commandName,
  object: nil,
  userInfo: ["action": action],
  deliverImmediately: true
)

// Wait for response (scan takes longer — up to 60s)
let timeout: TimeInterval = action == "scan" ? 60 : 10
let deadline = Date().addingTimeInterval(timeout)
while !gotResponse && Date() < deadline {
  RunLoop.main.run(until: Date().addingTimeInterval(0.1))
}

center.removeObserver(observer)

if !gotResponse {
  print("No response from Iris app (is it running?)")
  exit(1)
}

// Print result file if available
let resultFile: String? = {
  switch action {
  case "status", "checkExtensions": return statusPath
  case "scan": return "/tmp/iris-scan-timing.json"
  default: return nil
  }
}()
if let path = resultFile {
  Thread.sleep(forTimeInterval: 0.5)
  if let data = FileManager.default.contents(atPath: path),
    let json = String(data: data, encoding: .utf8)
  {
    print("\n\(json)")
  }
}
