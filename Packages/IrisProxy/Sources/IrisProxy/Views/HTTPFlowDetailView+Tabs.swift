//
//  HTTPFlowDetailView+Tabs.swift
//  IrisProxy
//
//  Tab content views for HTTPFlowDetailView: overview, request, response, headers.
//

import SwiftUI

extension HTTPFlowDetailView {

    // MARK: - Overview Tab

    var overviewTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Request summary
            GroupBox("Request") {
                VStack(alignment: .leading, spacing: 8) {
                    DetailRow(label: "Method", value: flow.request.method)
                    DetailRow(label: "URL", value: flow.request.url)
                    DetailRow(label: "HTTP Version", value: flow.request.httpVersion)
                    DetailRow(label: "Body Size", value: formatBytes(flow.request.bodySize))
                    if let host = flow.request.host {
                        DetailRow(label: "Host", value: host)
                    }
                }
                .padding(.vertical, 4)
            }

            // Response summary
            if let response = flow.response {
                GroupBox("Response") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Status")
                                .foregroundColor(.secondary)
                                .frame(width: 100, alignment: .leading)
                            StatusBadge(statusCode: response.statusCode)
                            Text(response.reason)
                                .foregroundColor(.secondary)
                        }
                        DetailRow(label: "HTTP Version", value: response.httpVersion)
                        DetailRow(label: "Body Size", value: formatBytes(response.bodySize))
                        if let contentType = response.contentType {
                            DetailRow(label: "Content-Type", value: contentType)
                        }
                        DetailRow(label: "Duration", value: formatDuration(response.duration))
                    }
                    .padding(.vertical, 4)
                }
            } else if let error = flow.error {
                GroupBox("Error") {
                    HStack {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.red)
                        Text(error)
                            .foregroundColor(.red)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                GroupBox("Response") {
                    HStack {
                        ProgressView()
                            .scaleEffect(0.8)
                        Text("Waiting for response...")
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }

            // Process info
            if flow.processName != nil || flow.processId != nil {
                GroupBox("Process") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let name = flow.processName {
                            DetailRow(label: "Name", value: name)
                        }
                        if let pid = flow.processId {
                            DetailRow(label: "PID", value: "\(pid)")
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
    }

    // MARK: - Request Tab

    var requestTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            // Request line
            GroupBox("Request Line") {
                Text("\(flow.request.method) \(flow.request.path) \(flow.request.httpVersion)")
                    .font(.system(size: 12, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(.vertical, 4)
            }

            // Headers
            GroupBox("Headers") {
                headersView(flow.request.headers)
            }

            // Body preview
            if let preview = flow.request.bodyPreview {
                GroupBox("Body Preview (\(formatBytes(flow.request.bodySize)))") {
                    bodyPreviewView(preview)
                }
            } else if flow.request.bodySize > 0 {
                GroupBox("Body") {
                    Text("\(formatBytes(flow.request.bodySize)) (no preview available)")
                        .foregroundColor(.secondary)
                        .padding(.vertical, 4)
                }
            }
        }
    }

    // MARK: - Response Tab

    var responseTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            if let response = flow.response {
                // Status line
                GroupBox("Status Line") {
                    HStack {
                        Text("\(response.httpVersion) \(response.statusCode) \(response.reason)")
                            .font(.system(size: 12, design: .monospaced))
                            .textSelection(.enabled)
                        Spacer()
                        StatusBadge(statusCode: response.statusCode)
                    }
                    .padding(.vertical, 4)
                }

                // Headers
                GroupBox("Headers") {
                    headersView(response.headers)
                }

                // Body preview
                if let preview = response.bodyPreview {
                    GroupBox("Body Preview (\(formatBytes(response.bodySize)))") {
                        bodyPreviewView(preview)
                    }
                } else if response.bodySize > 0 {
                    GroupBox("Body") {
                        Text("\(formatBytes(response.bodySize)) (no preview available)")
                            .foregroundColor(.secondary)
                            .padding(.vertical, 4)
                    }
                }
            } else if let error = flow.error {
                GroupBox("Error") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.red)
                            Text("Request Failed")
                                .font(.headline)
                                .foregroundColor(.red)
                        }
                        Text(error)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                    }
                    .padding(.vertical, 4)
                }
            } else {
                VStack(spacing: 16) {
                    ProgressView()
                    Text("Waiting for response...")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
    }

    // MARK: - Headers Tab

    var headersTab: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Request Headers (\(flow.request.headers.count))") {
                headersView(flow.request.headers)
            }

            if let response = flow.response {
                GroupBox("Response Headers (\(response.headers.count))") {
                    headersView(response.headers)
                }
            }
        }
    }
}
